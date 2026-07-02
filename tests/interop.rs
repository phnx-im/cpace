//! Self-interop with a real RNG: agreement in both modes, symmetric-mode
//! order independence, and domain separation between the two modes.

#![expect(
    clippy::unwrap_used,
    reason = "test exchanges with valid inputs must succeed"
)]

#[path = "util/rng.rs"]
mod rng;

use cpace::{Context, Msg};
use rng::FixedRng;

const CTX: Context<'static> = Context {
    prs: b"correct horse battery staple",
    ci: b"A_and_B",
    sid: b"sid-1234",
};

#[test]
fn initiator_responder_agreement() {
    let mut rng = rand::rng();
    let (state_a, msg_a) = cpace::initiate(&CTX, b"ADa", &mut rng);
    let wire_a = Msg::from_bytes(msg_a.as_bytes()).unwrap();
    let (msg_b, output_b) = cpace::respond(&CTX, b"ADb", &wire_a, &mut rng).unwrap();
    let wire_b = Msg::from_bytes(msg_b.as_bytes()).unwrap();
    let output_a = state_a.finish(&wire_b).unwrap();

    assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
    assert_eq!(output_a.sid_output, output_b.sid_output);
}

#[test]
fn symmetric_agreement_is_order_independent() {
    let mut rng = rand::rng();
    let (state_a, msg_a) = cpace::start_symmetric(&CTX, b"nonce-a", &mut rng);
    let (state_b, msg_b) = cpace::start_symmetric(&CTX, b"nonce-b", &mut rng);

    let output_a = state_a.finish(&msg_b).unwrap();
    let output_b = state_b.finish(&msg_a).unwrap();

    assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
    assert_eq!(output_a.sid_output, output_b.sid_output);
}

#[test]
fn modes_are_domain_separated() {
    // Same scalars, same inputs: the IR and OC transcripts must still
    // produce different keys.
    let ya = vec![0x11u8; 32];
    let yb = vec![0x0du8; 32];

    let (state_a, msg_a) = cpace::initiate(&CTX, b"ADa", &mut FixedRng(ya.clone()));
    let (msg_b, _) = cpace::respond(&CTX, b"ADb", &msg_a, &mut FixedRng(yb.clone())).unwrap();
    let ir = state_a.finish(&msg_b).unwrap();

    let (state_a, _) = cpace::start_symmetric(&CTX, b"ADa", &mut FixedRng(ya));
    let (_, msg_b) = cpace::start_symmetric(&CTX, b"ADb", &mut FixedRng(yb));
    let oc = state_a.finish(&msg_b).unwrap();

    assert_ne!(ir.isk.as_bytes(), oc.isk.as_bytes());
}

#[test]
fn fresh_scalars_per_session() {
    let mut rng = rand::rng();
    let (_, first) = cpace::initiate(&CTX, b"", &mut rng);
    let (_, second) = cpace::initiate(&CTX, b"", &mut rng);
    assert_ne!(first.as_bytes(), second.as_bytes());
}
