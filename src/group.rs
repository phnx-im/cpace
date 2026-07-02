//! Group operations for the CPaceRistretto255 cipher suite (draft
//! section 7.2): scalar sampling, password-derived generator computation
//! and Diffie-Hellman operations with mandatory validity checks.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{Leb128, update_lv};
use crate::error::Error;
use crate::msg::ELEMENT_LEN;

pub(crate) const DSI: &[u8] = b"CPaceRistretto255";
pub(crate) const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";

/// SHA-512 input block size, the `s_in_bytes` suite parameter.
const S_IN_BYTES: usize = 128;

/// Samples a uniform scalar per the draft's recommended method: 32 random
/// bytes with the top four bits cleared, interpreted little-endian. The
/// result is below 2^252 and therefore already canonical mod the group
/// order, so the final reduction never changes the value.
pub(crate) fn sample_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(bytes.as_mut());
    if let Some(top) = bytes.last_mut() {
        *top &= 0x0f;
    }
    Scalar::from_bytes_mod_order(*bytes)
}

/// Derives the password-dependent generator
/// `g = one_way_map(H(generator_string(DSI, PRS, CI, sid)))`.
///
/// The generator string is streamed straight into SHA-512 so no heap copy
/// of the password-related string is ever made.
pub(crate) fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    // Zero padding aligns the first hash block so that its output does not
    // depend on the (short, secret) password length position.
    let prs_lv_len = Leb128::encode(prs.len())
        .as_bytes()
        .len()
        .saturating_add(prs.len());
    let dsi_lv_len = Leb128::encode(DSI.len())
        .as_bytes()
        .len()
        .saturating_add(DSI.len());
    let len_zpad = S_IN_BYTES
        .saturating_sub(1)
        .saturating_sub(prs_lv_len)
        .saturating_sub(dsi_lv_len);

    let mut hash = Sha512::new();
    update_lv(&mut hash, DSI);
    update_lv(&mut hash, prs);
    hash.update(Leb128::encode(len_zpad).as_bytes());
    let zeros = [0u8; S_IN_BYTES];
    hash.update(zeros.get(..len_zpad).unwrap_or_default());
    update_lv(&mut hash, ci);
    update_lv(&mut hash, sid);

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash.finalize());
    let generator = RistrettoPoint::from_uniform_bytes(&wide);
    wide.zeroize();
    generator
}

/// Computes the encoded public share `Y = y * g`.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "group scalar multiplication is modular and cannot overflow"
)]
pub(crate) fn scalar_mult(y: &Scalar, generator: &RistrettoPoint) -> [u8; ELEMENT_LEN] {
    (y * generator).compress().to_bytes()
}

/// Computes the encoded shared point `K = y * decode(peer)`.
///
/// Per draft section 9, the protocol MUST abort when the peer element does
/// not decode or when K is the neutral element. Both cases collapse into
/// the single [`Error::InvalidPeerElement`] so callers cannot accidentally
/// treat them differently.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "group scalar multiplication is modular and cannot overflow"
)]
pub(crate) fn scalar_mult_vfy(
    y: &Scalar,
    peer: &[u8; ELEMENT_LEN],
) -> Result<Zeroizing<[u8; ELEMENT_LEN]>, Error> {
    let Some(point) = CompressedRistretto(*peer).decompress() else {
        return Err(Error::InvalidPeerElement);
    };
    let k = Zeroizing::new((y * point).compress().to_bytes());
    let is_identity: bool = k.ct_eq(&[0u8; ELEMENT_LEN]).into();
    if is_identity {
        return Err(Error::InvalidPeerElement);
    }
    Ok(k)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "unwrap on fixed vectors is fine in tests"
    )]

    use alloc::vec::Vec;

    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    use super::{DSI, calculate_generator, scalar_mult, scalar_mult_vfy};
    use crate::encoding::{lv_cat, prepend_len_into};
    use crate::error::Error;

    fn hex(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for pair in s.as_bytes().chunks_exact(2) {
            let digits = core::str::from_utf8(pair).unwrap();
            out.push(u8::from_str_radix(digits, 16).unwrap());
        }
        out
    }

    fn scalar(bytes: &[u8]) -> Scalar {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        Scalar::from_bytes_mod_order(buf)
    }

    const PRS: &[u8] = b"Password";
    const CI_HEX: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
    const SID_HEX: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";

    // Appendix B.3.1: generator string, hash and encoded generator.
    #[test]
    fn generator_vector() {
        let ci = hex(CI_HEX);
        let sid = hex(SID_HEX);

        let expected_string = hex("11435061636552697374726574746f3235350850617373776f726464\
             00000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000180b415f696e69746961746f\
             720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f\
             2c57");
        let zeros = [0u8; 100];
        let gen_string = lv_cat(&[DSI, PRS, &zeros, &ci, &sid]);
        assert_eq!(gen_string, expected_string);

        let expected_hash = hex("da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288\
             b6663af06bf645c93cd1c51512307199c80e84908916d983b34af772\
             05f90851a657ee27");
        assert_eq!(Sha512::digest(&gen_string).as_slice(), expected_hash);

        let expected_g = hex("222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5\
             698c7e56");
        let g = calculate_generator(PRS, &ci, &sid);
        assert_eq!(g.compress().to_bytes().as_slice(), expected_g);
    }

    // Appendix B.3.2 / B.3.3: public shares from fixed scalars.
    #[test]
    fn public_share_vectors() {
        let ci = hex(CI_HEX);
        let sid = hex(SID_HEX);
        let g = calculate_generator(PRS, &ci, &sid);

        let ya = scalar(&hex(
            "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4f\
             f0976d08",
        ));
        let expected_ya = hex("d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec\
             482b9157");
        assert_eq!(scalar_mult(&ya, &g).as_slice(), expected_ya);

        let yb = scalar(&hex(
            "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762\
             d900b80d",
        ));
        let expected_yb = hex("3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7\
             433f7258");
        assert_eq!(scalar_mult(&yb, &g).as_slice(), expected_yb);
    }

    // Appendix B.3.10: valid scalar_mult_vfy input.
    #[test]
    fn scalar_mult_vfy_valid_vector() {
        let s = scalar(&hex(
            "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88\
             cf538a05",
        ));
        let mut x = [0u8; 32];
        x.copy_from_slice(&hex(
            "2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d6\
             54b4a51c",
        ));
        let expected = hex("7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e\
             7f6b600e");
        let k = scalar_mult_vfy(&s, &x).unwrap();
        assert_eq!(k.as_slice(), expected);
    }

    // Appendix B.3.11: invalid inputs MUST be rejected.
    #[test]
    fn scalar_mult_vfy_invalid_vectors() {
        let s = scalar(&hex(
            "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88\
             cf538a05",
        ));

        let mut y_i1 = [0u8; 32];
        y_i1.copy_from_slice(&hex(
            "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d6\
             54b4a51c",
        ));
        assert_eq!(
            scalar_mult_vfy(&s, &y_i1).unwrap_err(),
            Error::InvalidPeerElement
        );

        let y_i2 = [0u8; 32];
        assert_eq!(
            scalar_mult_vfy(&s, &y_i2).unwrap_err(),
            Error::InvalidPeerElement
        );
    }

    #[test]
    fn zero_padding_boundary() {
        // A PRS of 109 bytes fills the first block exactly (18 + 110 = 128,
        // len_zpad = 0); longer PRS values must also work with no padding.
        for prs_len in [0usize, 108, 109, 110, 200] {
            let prs = alloc::vec![0x50u8; prs_len];
            let mut expected = Vec::new();
            prepend_len_into(&mut expected, DSI);
            prepend_len_into(&mut expected, &prs);
            let len_zpad = 128usize.saturating_sub(1).saturating_sub(expected.len());
            let zeros = alloc::vec![0u8; len_zpad];
            prepend_len_into(&mut expected, &zeros);
            prepend_len_into(&mut expected, b"ci");
            prepend_len_into(&mut expected, b"sid");

            let mut wide = [0u8; 64];
            wide.copy_from_slice(&Sha512::digest(&expected));
            let want = curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&wide);
            assert_eq!(calculate_generator(&prs, b"ci", b"sid"), want);
        }
    }
}
