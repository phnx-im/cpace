//! Property-based tests: wire-format round-trips, protocol agreement for
//! arbitrary inputs, and tamper detection.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "proptest closures assert on generated data"
)]

#[path = "util/rng.rs"]
mod rng;

use cpace::{Context, Msg};
use proptest::prelude::*;
use rng::FixedRng;

/// Minimal LEB128 encoding, the reference for wire-format round-trips.
fn leb128(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value == 0 {
            out.push(low);
            return out;
        }
        out.push(low | 0x80);
    }
}

proptest! {
    #[test]
    fn msg_round_trip(element in prop::array::uniform32(any::<u8>()),
                      ad in prop::collection::vec(any::<u8>(), 0..300)) {
        let mut bytes = vec![0x20u8];
        bytes.extend_from_slice(&element);
        bytes.extend_from_slice(&leb128(ad.len()));
        bytes.extend_from_slice(&ad);

        let msg = Msg::from_bytes(&bytes).unwrap();
        prop_assert_eq!(msg.as_bytes(), &bytes);
        prop_assert_eq!(msg.element(), element);
        prop_assert_eq!(msg.associated_data(), &ad);
    }

    #[test]
    fn parsing_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = Msg::from_bytes(&bytes);
    }

    #[test]
    fn agreement_for_arbitrary_inputs(
        prs in prop::collection::vec(any::<u8>(), 0..200),
        ci in prop::collection::vec(any::<u8>(), 0..64),
        sid in prop::collection::vec(any::<u8>(), 0..64),
        ad_a in prop::collection::vec(any::<u8>(), 0..64),
        ad_b in prop::collection::vec(any::<u8>(), 0..64),
        ya in prop::array::uniform32(any::<u8>()),
        yb in prop::array::uniform32(any::<u8>()),
    ) {
        let ctx = Context { prs: &prs, ci: &ci, sid: &sid };
        let (state_a, msg_a) = cpace::initiate(&ctx, &ad_a, &mut FixedRng(ya.to_vec()));
        let (msg_b, output_b) =
            cpace::respond(&ctx, &ad_b, &msg_a, &mut FixedRng(yb.to_vec())).unwrap();
        let output_a = state_a.finish(&msg_b).unwrap();
        prop_assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
        prop_assert_eq!(output_a.sid_output, output_b.sid_output);
    }

    #[test]
    fn tampering_with_message_changes_key_or_aborts(
        flip_bit in 0usize..8,
        position_seed in any::<u16>(),
        ya in prop::array::uniform32(any::<u8>()),
        yb in prop::array::uniform32(any::<u8>()),
    ) {
        let ctx = Context { prs: b"password", ci: b"", sid: b"sid" };
        let (state_a, msg_a) = cpace::initiate(&ctx, b"ADa", &mut FixedRng(ya.to_vec()));
        let (msg_b, output_b) =
            cpace::respond(&ctx, b"ADb", &msg_a, &mut FixedRng(yb.to_vec())).unwrap();

        let mut tampered = msg_b.as_bytes().to_vec();
        // Skip byte 0: flipping the length prefix is already covered by the
        // malformed-message tests.
        let position = 1 + usize::from(position_seed) % (tampered.len() - 1);
        tampered[position] ^= 1 << flip_bit;

        match Msg::from_bytes(&tampered) {
            Err(_) => {}
            Ok(msg) => match state_a.finish(&msg) {
                Err(_) => {}
                Ok(output_a) => {
                    prop_assert_ne!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
                }
            },
        }
    }
}
