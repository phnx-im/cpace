//! The CPace protocol state machine for both the initiator-responder and
//! the symmetric (parallel) execution modes.

use alloc::vec::Vec;
use core::fmt;

use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::encoding::{lexicographically_larger, update_lv};
use crate::error::Error;
use crate::group::{DSI_ISK, calculate_generator, sample_scalar, scalar_mult, scalar_mult_vfy};
use crate::msg::Msg;
use crate::output::{Isk, Output};

/// Common protocol inputs both parties must agree on.
///
/// `prs` is the secret, typically low-entropy password-related string;
/// the caller keeps ownership and should zeroize its copy after use. `ci`
/// (channel identifier) and `sid` (session id) are public context values
/// and may be empty; see draft sections 10.1 and 10.6 for guidance.
pub struct Context<'a> {
    /// Password-related string, the shared secret.
    pub prs: &'a [u8],
    /// Channel identifier, agreed out of band and never transmitted.
    pub ci: &'a [u8],
    /// Session id; SHOULD be unique per protocol run when available.
    pub sid: &'a [u8],
}

/// How the two messages enter the ISK transcript.
enum TranscriptKind {
    /// `transcript_ir`: our message strictly before or after the peer's,
    /// fixed by role.
    Ir { own_is_first: bool },
    /// `transcript_oc`: ordered concatenation, independent of arrival order.
    Oc,
}

/// Per-session secrets and public values kept between the two steps.
struct Pending {
    y: Scalar,
    sid: Vec<u8>,
    own_msg: Msg,
    kind: TranscriptKind,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

impl Pending {
    fn start<R: CryptoRng + ?Sized>(
        ctx: &Context<'_>,
        ad: &[u8],
        kind: TranscriptKind,
        rng: &mut R,
    ) -> Self {
        let mut generator = calculate_generator(ctx.prs, ctx.ci, ctx.sid);
        let y = sample_scalar(rng);
        let element = scalar_mult(&y, &generator);
        // The generator is derived from the password, so we treat it as a
        // secret even though a single group element does not allow
        // recovering the PRS without a dictionary attack.
        generator.zeroize();
        let own_msg = Msg::new(&element, ad);
        Self {
            y,
            sid: ctx.sid.to_vec(),
            own_msg,
            kind,
        }
    }

    fn finish(self, peer_msg: &Msg) -> Result<Output, Error> {
        let k = scalar_mult_vfy(&self.y, &peer_msg.element())?;

        let mut isk_hash = Sha512::new();
        update_lv(&mut isk_hash, DSI_ISK);
        update_lv(&mut isk_hash, &self.sid);
        update_lv(&mut isk_hash, k.as_ref());

        let mut sid_hash = Sha512::new();
        sid_hash.update(b"CPaceSidOutput");

        let own = self.own_msg.as_bytes();
        let peer = peer_msg.as_bytes();
        let (first, second) = match self.kind {
            TranscriptKind::Ir { own_is_first: true } => (own, peer),
            TranscriptKind::Ir {
                own_is_first: false,
            } => (peer, own),
            TranscriptKind::Oc => {
                isk_hash.update(b"oc");
                sid_hash.update(b"oc");
                if lexicographically_larger(own, peer) {
                    (own, peer)
                } else {
                    (peer, own)
                }
            }
        };
        isk_hash.update(first);
        isk_hash.update(second);
        sid_hash.update(first);
        sid_hash.update(second);

        let mut isk = [0u8; 64];
        isk.copy_from_slice(&isk_hash.finalize());
        let mut sid_output = [0u8; 64];
        sid_output.copy_from_slice(&sid_hash.finalize());
        Ok(Output {
            isk: Isk::new(isk),
            sid_output,
        })
    }
}

/// Party A's state between [`initiate`] and [`InitiatorState::finish`].
///
/// Holds the session's secret scalar; it is zeroized on drop and consumed
/// by `finish`, so one state cannot complete two exchanges.
pub struct InitiatorState(Pending);

impl InitiatorState {
    /// Completes the exchange with the responder's message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPeerElement`] if the peer's element does not
    /// decode to a valid group element or the shared point would be the
    /// neutral element. The exchange MUST be considered failed.
    pub fn finish(self, msg_b: &Msg) -> Result<Output, Error> {
        self.0.finish(msg_b)
    }
}

impl fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitiatorState(<redacted>)")
    }
}

/// Starts an exchange in initiator-responder mode as party A.
///
/// Returns the state needed to process the response and the message to
/// send to the responder (as [`Msg::as_bytes`]).
pub fn initiate<R: CryptoRng + ?Sized>(
    ctx: &Context<'_>,
    ad_a: &[u8],
    rng: &mut R,
) -> (InitiatorState, Msg) {
    let pending = Pending::start(ctx, ad_a, TranscriptKind::Ir { own_is_first: true }, rng);
    let msg = pending.own_msg.clone();
    (InitiatorState(pending), msg)
}

/// Completes an exchange in initiator-responder mode as party B.
///
/// The responder already holds the initiator's message when it acts, so
/// this single call produces both the reply to send back and the output.
///
/// # Errors
///
/// Returns [`Error::InvalidPeerElement`] if the initiator's element does
/// not decode to a valid group element or the shared point would be the
/// neutral element. The exchange MUST be considered failed.
pub fn respond<R: CryptoRng + ?Sized>(
    ctx: &Context<'_>,
    ad_b: &[u8],
    msg_a: &Msg,
    rng: &mut R,
) -> Result<(Msg, Output), Error> {
    let pending = Pending::start(
        ctx,
        ad_b,
        TranscriptKind::Ir {
            own_is_first: false,
        },
        rng,
    );
    let msg = pending.own_msg.clone();
    let output = pending.finish(msg_a)?;
    Ok((msg, output))
}

/// A party's state between [`start_symmetric`] and
/// [`SymmetricState::finish`].
///
/// Holds the session's secret scalar; it is zeroized on drop and consumed
/// by `finish`, so one state cannot complete two exchanges.
pub struct SymmetricState(Pending);

impl SymmetricState {
    /// Completes the exchange with the peer's message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPeerElement`] if the peer's element does not
    /// decode to a valid group element or the shared point would be the
    /// neutral element. The exchange MUST be considered failed.
    pub fn finish(self, peer_msg: &Msg) -> Result<Output, Error> {
        self.0.finish(peer_msg)
    }
}

impl fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricState(<redacted>)")
    }
}

/// Starts an exchange in symmetric (parallel) mode, where both parties act
/// identically and messages may cross on the wire.
///
/// Use this mode only when the associated data of both parties is
/// guaranteed distinct or unique per draft section 5.2; otherwise prefer
/// [`initiate`]/[`respond`].
pub fn start_symmetric<R: CryptoRng + ?Sized>(
    ctx: &Context<'_>,
    ad: &[u8],
    rng: &mut R,
) -> (SymmetricState, Msg) {
    let pending = Pending::start(ctx, ad, TranscriptKind::Oc, rng);
    let msg = pending.own_msg.clone();
    (SymmetricState(pending), msg)
}
