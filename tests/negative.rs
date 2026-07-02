//! Abort conditions: invalid peer elements from Appendix B.3.11, malformed
//! wire messages, and mismatched protocol inputs.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "fixed test vectors either match or the test must fail loudly"
)]

mod util;

use cpace::{Context, Error, Msg, MsgError};
use util::rng::FixedRng;
use util::{hex, json_from_b64};

const PRS: &[u8] = b"Password";

fn ctx() -> Context<'static> {
    Context {
        prs: PRS,
        ci: b"",
        sid: b"",
    }
}

fn scalar_bytes() -> Vec<u8> {
    let json = json_from_b64(include_str!("data/b3_11_invalid.b64"));
    hex(json
        .get("Valid")
        .unwrap()
        .get("s")
        .unwrap()
        .as_str()
        .unwrap())
}

/// The two invalid elements from B.3.11: a non-decodable encoding and the
/// neutral element.
fn invalid_elements() -> Vec<Vec<u8>> {
    let json = json_from_b64(include_str!("data/b3_11_invalid.b64"));
    vec![
        hex(json.get("Invalid Y1").unwrap().as_str().unwrap()),
        hex(json.get("Invalid Y2").unwrap().as_str().unwrap()),
    ]
}

fn msg_with_element(element: &[u8], ad: &[u8]) -> Msg {
    let mut bytes = vec![u8::try_from(element.len()).unwrap()];
    bytes.extend_from_slice(element);
    bytes.push(u8::try_from(ad.len()).unwrap());
    bytes.extend_from_slice(ad);
    Msg::from_bytes(&bytes).unwrap()
}

#[test]
fn invalid_peer_element_aborts_every_finish_path() {
    for element in invalid_elements() {
        let bad_msg = msg_with_element(&element, b"ADb");

        let (state, _) = cpace::initiate(&ctx(), b"ADa", &mut FixedRng(scalar_bytes()));
        assert_eq!(
            state.finish(&bad_msg).unwrap_err(),
            Error::InvalidPeerElement
        );

        let result = cpace::respond(&ctx(), b"ADb", &bad_msg, &mut FixedRng(scalar_bytes()));
        assert_eq!(result.unwrap_err(), Error::InvalidPeerElement);

        let (state, _) = cpace::start_symmetric(&ctx(), b"ADa", &mut FixedRng(scalar_bytes()));
        assert_eq!(
            state.finish(&bad_msg).unwrap_err(),
            Error::InvalidPeerElement
        );
    }
}

#[test]
fn malformed_wire_messages_are_rejected() {
    let mut rng = rand::rng();
    let (_, good) = cpace::initiate(&ctx(), b"AD", &mut rng);
    let good = good.as_bytes();

    assert_eq!(Msg::from_bytes(&[]).unwrap_err(), MsgError::Truncated);
    assert_eq!(
        Msg::from_bytes(&good[..20]).unwrap_err(),
        MsgError::Truncated
    );
    assert_eq!(
        Msg::from_bytes(&good[..good.len() - 1]).unwrap_err(),
        MsgError::Truncated
    );

    let mut trailing = good.to_vec();
    trailing.push(0);
    assert_eq!(
        Msg::from_bytes(&trailing).unwrap_err(),
        MsgError::TrailingBytes
    );

    // 31-byte element.
    let mut short_element = vec![0x1f];
    short_element.extend_from_slice(&[0u8; 31]);
    short_element.push(0);
    assert_eq!(
        Msg::from_bytes(&short_element).unwrap_err(),
        MsgError::BadElementLength
    );

    // Non-minimal LEB128 encoding of the element length (0x20 in 2 bytes).
    let mut non_minimal = vec![0xa0, 0x00];
    non_minimal.extend_from_slice(&good[1..]);
    assert_eq!(
        Msg::from_bytes(&non_minimal).unwrap_err(),
        MsgError::NonMinimalLength
    );

    // A length prefix that overflows usize.
    let huge = [
        0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    assert_eq!(
        Msg::from_bytes(&huge).unwrap_err(),
        MsgError::LengthOverflow
    );
}

#[test]
fn mismatched_inputs_yield_different_keys() {
    let mut rng = rand::rng();
    let base = Context {
        prs: b"Password",
        ci: b"context",
        sid: b"sid-0001",
    };
    let variants = [
        Context {
            prs: b"Passwore",
            ci: b"context",
            sid: b"sid-0001",
        },
        Context {
            prs: b"Password",
            ci: b"asymmetric-view",
            sid: b"sid-0001",
        },
        Context {
            prs: b"Password",
            ci: b"context",
            sid: b"sid-0002",
        },
    ];

    for wrong in variants {
        let (state_a, msg_a) = cpace::initiate(&base, b"", &mut rng);
        let (msg_b, output_b) = cpace::respond(&wrong, b"", &msg_a, &mut rng).unwrap();
        let output_a = state_a.finish(&msg_b).unwrap();
        // Both sides complete without error; only the derived keys reveal
        // the mismatch. Applications must confirm the key before use.
        assert_ne!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
    }
}
