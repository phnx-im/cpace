//! Byte-string utilities from Appendix A of the draft: LEB128 length
//! prefixes (`prepend_len`), length-value concatenation (`lv_cat`) and
//! ordered concatenation (`o_cat`).

use alloc::vec::Vec;

use crate::error::MsgError;

/// One LEB128-encoded length. A 64-bit `usize` needs at most 10 bytes.
pub(crate) struct Leb128 {
    buf: [u8; 10],
    len: usize,
}

impl Leb128 {
    pub(crate) fn encode(mut value: usize) -> Self {
        let mut buf = [0u8; 10];
        let mut len = 0usize;
        for (i, slot) in buf.iter_mut().enumerate() {
            let low = u8::try_from(value & 0x7f).unwrap_or(0);
            value >>= 7;
            if value == 0 {
                *slot = low;
                len = i.saturating_add(1);
                break;
            }
            *slot = low | 0x80;
        }
        Self { buf, len }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

/// Appends `prepend_len(data)` to `out`.
pub(crate) fn prepend_len_into(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(Leb128::encode(data.len()).as_bytes());
    out.extend_from_slice(data);
}

/// Feeds one length-prefixed field into a hash.
pub(crate) fn update_lv(hash: &mut sha2::Sha512, field: &[u8]) {
    use sha2::Digest as _;
    hash.update(Leb128::encode(field.len()).as_bytes());
    hash.update(field);
}

/// `lv_cat`: concatenation of all fields, each with its length prepended.
/// Production code streams fields into the hash instead; this materialized
/// form exists for the Appendix A and B test vectors.
#[cfg(test)]
pub(crate) fn lv_cat(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        prepend_len_into(&mut out, field);
    }
    out
}

/// Lexicographic "larger" relation from Appendix A.3.1. Rust's slice
/// ordering is byte-wise lexicographic with shorter-prefix-first, which
/// matches the draft's definition exactly (verified by the A.3.3 vectors).
/// Transcript components are public, so variable time is acceptable here.
pub(crate) fn lexicographically_larger(a: &[u8], b: &[u8]) -> bool {
    a > b
}

/// Parses one length-prefixed field, returning `(field, rest)`.
///
/// The length must use minimal LEB128 encoding and the field must fit in
/// the remaining input.
pub(crate) fn read_lv(input: &[u8]) -> Result<(&[u8], &[u8]), MsgError> {
    let mut len = 0usize;
    let mut shift = 0u32;
    let mut header = 0usize;
    let mut iter = input.iter();
    loop {
        let Some(&byte) = iter.next() else {
            return Err(MsgError::Truncated);
        };
        header = header.saturating_add(1);
        let payload = usize::from(byte & 0x7f);
        let shifted = payload.checked_shl(shift).ok_or(MsgError::LengthOverflow)?;
        if shifted.checked_shr(shift) != Some(payload) {
            return Err(MsgError::LengthOverflow);
        }
        len |= shifted;
        if byte & 0x80 == 0 {
            // A trailing zero byte would be a redundant continuation of a
            // shorter encoding of the same value.
            if header > 1 && byte == 0 {
                return Err(MsgError::NonMinimalLength);
            }
            break;
        }
        shift = shift.saturating_add(7);
    }
    let body = input.get(header..).unwrap_or_default();
    if body.len() < len {
        return Err(MsgError::Truncated);
    }
    let field = body.get(..len).unwrap_or_default();
    let rest = body.get(len..).unwrap_or_default();
    Ok((field, rest))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "unwrap on fixed vectors is fine in tests"
    )]

    use alloc::vec::Vec;

    use super::{Leb128, lexicographically_larger, lv_cat, prepend_len_into, read_lv};
    use crate::error::MsgError;

    fn prepend_len(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        prepend_len_into(&mut out, data);
        out
    }

    // Appendix A.1.2
    #[test]
    fn prepend_len_vectors() {
        assert_eq!(prepend_len(b""), [0x00]);
        assert_eq!(prepend_len(b"1234"), *b"\x041234");

        let bytes_127: Vec<u8> = (0u8..127).collect();
        let encoded = prepend_len(&bytes_127);
        assert_eq!(encoded.len(), 128);
        assert_eq!(encoded.first(), Some(&0x7f));

        let bytes_128: Vec<u8> = (0u8..128).collect();
        let encoded = prepend_len(&bytes_128);
        assert_eq!(encoded.len(), 130);
        assert_eq!(encoded.get(..2), Some(&[0x80, 0x01][..]));
    }

    #[test]
    fn leb128_multi_byte() {
        assert_eq!(Leb128::encode(0).as_bytes(), [0x00]);
        assert_eq!(Leb128::encode(127).as_bytes(), [0x7f]);
        assert_eq!(Leb128::encode(128).as_bytes(), [0x80, 0x01]);
        assert_eq!(Leb128::encode(16384).as_bytes(), [0x80, 0x80, 0x01]);
    }

    // Appendix A.1.4
    #[test]
    fn lv_cat_vector() {
        let out = lv_cat(&[b"1234", b"5", b"", b"678"]);
        assert_eq!(out, *b"\x041234\x015\x00\x03678");
    }

    // Appendix A.3.3
    #[test]
    fn lexicographic_ordering_vectors() {
        assert!(!lexicographically_larger(b"\0", b"\0\0"));
        assert!(lexicographically_larger(b"\x01", b"\0\0"));
        assert!(lexicographically_larger(b"\0\0", b"\0"));
        assert!(!lexicographically_larger(b"\0\0", b"\x01"));
        assert!(!lexicographically_larger(b"\0\x01", b"\x01"));
        assert!(!lexicographically_larger(b"ABCD", b"BCD"));
    }

    #[test]
    fn read_lv_round_trip() {
        let encoded = lv_cat(&[b"1234", b"5", b"", b"678"]);
        let (field, rest) = read_lv(&encoded).unwrap();
        assert_eq!(field, b"1234");
        let (field, rest) = read_lv(rest).unwrap();
        assert_eq!(field, b"5");
        let (field, rest) = read_lv(rest).unwrap();
        assert_eq!(field, b"");
        let (field, rest) = read_lv(rest).unwrap();
        assert_eq!(field, b"678");
        assert!(rest.is_empty());
    }

    #[test]
    fn read_lv_rejects_bad_input() {
        assert_eq!(read_lv(b"").unwrap_err(), MsgError::Truncated);
        assert_eq!(read_lv(b"\x05abc").unwrap_err(), MsgError::Truncated);
        assert_eq!(
            read_lv(b"\x80\x00abc").unwrap_err(),
            MsgError::NonMinimalLength
        );
        assert_eq!(
            read_lv(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f").unwrap_err(),
            MsgError::LengthOverflow
        );
    }
}
