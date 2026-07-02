//! CPace wire message: exactly `lv_cat(Y, AD)` as defined in the draft.
//!
//! Keeping the wire bytes identical to the transcript component means
//! received bytes are hashed verbatim, with no re-encoding step that could
//! diverge from what the peer sent.

use alloc::vec::Vec;
use core::fmt;

use crate::encoding::{Leb128, prepend_len_into, read_lv};
use crate::error::MsgError;

/// Length of an encoded ristretto255 group element.
pub(crate) const ELEMENT_LEN: usize = 32;

/// A CPace protocol message: one group element plus associated data,
/// framed as `lv_cat(Y, AD)`.
#[derive(Clone, PartialEq, Eq)]
pub struct Msg {
    bytes: Vec<u8>,
    ad_offset: usize,
}

impl Msg {
    /// Builds the message for our own public element and associated data.
    pub(crate) fn new(element: &[u8; ELEMENT_LEN], ad: &[u8]) -> Self {
        let mut bytes = Vec::new();
        prepend_len_into(&mut bytes, element);
        let ad_offset = bytes
            .len()
            .saturating_add(Leb128::encode(ad.len()).as_bytes().len());
        prepend_len_into(&mut bytes, ad);
        Self { bytes, ad_offset }
    }

    /// Parses a received message.
    ///
    /// Parsing is strict: length prefixes must be minimal LEB128, the
    /// element must be exactly 32 bytes and no trailing bytes may follow.
    ///
    /// # Errors
    ///
    /// Returns a [`MsgError`] describing the first violation encountered.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MsgError> {
        let (element, rest) = read_lv(bytes)?;
        if element.len() != ELEMENT_LEN {
            return Err(MsgError::BadElementLength);
        }
        let (ad, rest) = read_lv(rest)?;
        if !rest.is_empty() {
            return Err(MsgError::TrailingBytes);
        }
        let ad_offset = bytes.len().saturating_sub(ad.len());
        Ok(Self {
            bytes: bytes.to_vec(),
            ad_offset,
        })
    }

    /// The wire representation, ready to transmit.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The encoded group element Y carried by this message.
    #[must_use]
    pub fn element(&self) -> [u8; ELEMENT_LEN] {
        let mut out = [0u8; ELEMENT_LEN];
        // The element always sits at bytes 1..33: its length prefix is the
        // single byte 0x20 because 32 < 128. Construction and parsing both
        // guarantee this.
        if let Some(src) = self.bytes.get(1..ELEMENT_LEN.saturating_add(1)) {
            out.copy_from_slice(src);
        }
        out
    }

    /// The associated data carried by this message.
    #[must_use]
    pub fn associated_data(&self) -> &[u8] {
        self.bytes.get(self.ad_offset..).unwrap_or_default()
    }
}

impl fmt::Debug for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Msg(")?;
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "unwrap on fixed vectors is fine in tests"
    )]

    use alloc::vec::Vec;

    use super::Msg;
    use crate::error::MsgError;

    #[test]
    fn round_trip() {
        let element = [0x42u8; 32];
        let msg = Msg::new(&element, b"ADa");
        let parsed = Msg::from_bytes(msg.as_bytes()).unwrap();
        assert_eq!(parsed, msg);
        assert_eq!(parsed.element(), element);
        assert_eq!(parsed.associated_data(), b"ADa");
    }

    #[test]
    fn empty_ad() {
        let msg = Msg::new(&[7u8; 32], b"");
        assert_eq!(msg.as_bytes().len(), 34);
        let parsed = Msg::from_bytes(msg.as_bytes()).unwrap();
        assert_eq!(parsed.associated_data(), b"");
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Msg::from_bytes(b"").unwrap_err(), MsgError::Truncated);

        // Element of 31 bytes.
        let mut short = Vec::from([0x1fu8]);
        short.extend_from_slice(&[0u8; 31]);
        short.push(0x00);
        assert_eq!(
            Msg::from_bytes(&short).unwrap_err(),
            MsgError::BadElementLength
        );

        let good = Msg::new(&[0x42u8; 32], b"AD");

        // Truncated associated data.
        let truncated = good.as_bytes().get(..good.as_bytes().len() - 1).unwrap();
        assert_eq!(Msg::from_bytes(truncated).unwrap_err(), MsgError::Truncated);

        // Trailing garbage.
        let mut trailing = good.as_bytes().to_vec();
        trailing.push(0x00);
        assert_eq!(
            Msg::from_bytes(&trailing).unwrap_err(),
            MsgError::TrailingBytes
        );

        // Non-minimal length prefix for the element (0x20 as two bytes).
        let mut non_minimal = Vec::from([0xa0u8, 0x00]);
        non_minimal.extend_from_slice(&[0u8; 32]);
        non_minimal.push(0x00);
        assert_eq!(
            Msg::from_bytes(&non_minimal).unwrap_err(),
            MsgError::NonMinimalLength
        );
    }
}
