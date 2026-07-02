//! CPace, a balanced composable password-authenticated key exchange
//! ([draft-irtf-cfrg-cpace-21]), instantiated with the CPaceRistretto255
//! cipher suite (ristretto255 + SHA-512).
//!
//! Two parties who share a low-entropy secret (`prs`, typically a
//! password) each send one message and derive a shared high-entropy
//! intermediate session key ([`Isk`]). An attacker who intercepts or
//! manipulates the exchange gets one password guess per active attack and
//! learns nothing from passive observation.
//!
//! The crate is sans-io and `no_std` (with `alloc`): the caller moves the
//! messages and supplies the RNG.
//!
//! # Initiator-responder mode
//!
//! Use this mode whenever the protocol has a defined message order.
//!
//! ```
//! use cpace::{Context, Msg};
//!
//! let mut rng = rand::rng();
//! let ctx = Context { prs: b"our password", ci: b"A_and_B", sid: b"unique-session-id-123" };
//!
//! // Party A starts and sends msg_a.as_bytes() to B.
//! let (state_a, msg_a) = cpace::initiate(&ctx, b"ADa", &mut rng);
//!
//! // Party B parses the received bytes, replies and is done.
//! let received_a = Msg::from_bytes(msg_a.as_bytes())?;
//! let (msg_b, output_b) = cpace::respond(&ctx, b"ADb", &received_a, &mut rng)?;
//!
//! // Party A processes B's reply.
//! let received_b = Msg::from_bytes(msg_b.as_bytes())?;
//! let output_a = state_a.finish(&received_b)?;
//!
//! assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
//! # Ok::<(), cpace::Error>(())
//! ```
//!
//! # Symmetric mode
//!
//! Use this mode when both parties may send simultaneously and no roles
//! exist. The associated data of the two parties must be distinct or
//! unique per run (draft section 5.2); otherwise use initiator-responder
//! mode.
//!
//! ```
//! use cpace::{Context, Msg};
//!
//! let mut rng = rand::rng();
//! let ctx = Context { prs: b"our password", ci: b"", sid: b"" };
//!
//! let (state_a, msg_a) = cpace::start_symmetric(&ctx, b"party-A-nonce-1", &mut rng);
//! let (state_b, msg_b) = cpace::start_symmetric(&ctx, b"party-B-nonce-1", &mut rng);
//!
//! let output_a = state_a.finish(&Msg::from_bytes(msg_b.as_bytes())?)?;
//! let output_b = state_b.finish(&Msg::from_bytes(msg_a.as_bytes())?)?;
//!
//! assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
//! // With an empty sid, use sid_output as session id for follow-up runs.
//! assert_eq!(output_a.sid_output, output_b.sid_output);
//! # Ok::<(), cpace::Error>(())
//! ```
//!
//! # Security notes
//!
//! * A failed exchange ([`Error::InvalidPeerElement`]) or a wrong password
//!   (mismatching ISKs) MUST abort the session. CPace itself has no key
//!   confirmation; if the application needs explicit confirmation, derive
//!   confirmation tags from the ISK (draft section 10.4).
//! * Post-process the ISK with a KDF such as HKDF before use as a
//!   symmetric key (draft section 6.4).
//! * The caller owns the `prs` buffer and should zeroize it after the
//!   exchange; this crate never copies it to the heap and zeroizes all
//!   internal secrets (scalar, generator, shared point K) on drop.
//! * Party identities belong in `ci` (if confidential) or in the
//!   associated data (if public); see draft section 10.1.
//!
//! [draft-irtf-cfrg-cpace-21]: https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.html

#![no_std]

extern crate alloc;

mod encoding;
mod error;
mod group;
mod msg;
mod output;
mod protocol;

pub use error::{Error, MsgError};
pub use msg::Msg;
pub use output::{Isk, Output};
pub use protocol::{Context, InitiatorState, SymmetricState, initiate, respond, start_symmetric};
