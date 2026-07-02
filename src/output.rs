//! Protocol outputs: the intermediate session key and the optional
//! session-id output.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The intermediate session key (ISK).
///
/// Per draft section 6.4 this value SHOULD be post-processed by a KDF
/// (e.g. HKDF) before being used as a symmetric key in a higher-level
/// protocol. It is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Isk([u8; 64]);

impl Isk {
    pub(crate) fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for Isk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Isk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Isk(<redacted>)")
    }
}

/// Result of a completed CPace exchange.
#[derive(Debug)]
pub struct Output {
    /// The intermediate session key shared by both parties.
    pub isk: Isk,
    /// `H(b"CPaceSidOutput" || transcript)`, a value both parties agree on.
    ///
    /// Only meaningful when the exchange started with an empty `sid`: draft
    /// section 10.6 recommends it as the session id for follow-up protocol
    /// runs. It is derived from public values only.
    pub sid_output: [u8; 64],
}
