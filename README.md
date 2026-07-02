# cpace

Rust implementation of [CPace](https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.html)
(draft-irtf-cfrg-cpace-21), a balanced composable password-authenticated key exchange,
instantiated with the **CPaceRistretto255** cipher suite (ristretto255 + SHA-512).

Two parties who share a low-entropy secret (a password) each send one message and derive a
shared high-entropy intermediate session key (ISK). A passive attacker learns nothing; an
active attacker gets exactly one password guess per protocol run.

## Properties

- **Spec-tested**: all Appendix A and B.3 test vectors of the draft are enforced in unit and
  integration tests, including the invalid-point abort cases (B.3.11).
- **`no_std` + `alloc`**: the caller supplies the RNG (`rand_core::CryptoRng`); verified
  against `thumbv7em-none-eabihf`.
- **Constant-time group operations** via `curve25519-dalek`; secrets (scalar, generator,
  shared point, ISK) are zeroized on drop.
- **Misuse-resistant API**: session states are consumed on completion, hold no password copy
  and print no secrets via `Debug`.
- Both execution modes: initiator-responder and symmetric (parallel), with the draft's
  `transcript_ir` / `transcript_oc` domain separation.

## Usage

```rust
use cpace::{Context, Msg};

let mut rng = rand::rng();
let ctx = Context { prs: b"our password", ci: b"A_and_B", sid: b"unique-session-id-123" };

// Party A -> B: msg_a
let (state_a, msg_a) = cpace::initiate(&ctx, b"ADa", &mut rng);

// Party B: parse, reply (B -> A: msg_b), done.
let received_a = Msg::from_bytes(msg_a.as_bytes())?;
let (msg_b, output_b) = cpace::respond(&ctx, b"ADb", &received_a, &mut rng)?;

// Party A: finish.
let received_b = Msg::from_bytes(msg_b.as_bytes())?;
let output_a = state_a.finish(&received_b)?;

assert_eq!(output_a.isk.as_bytes(), output_b.isk.as_bytes());
# Ok::<(), cpace::Error>(())
```

See the crate docs (`cargo doc --open`) for the symmetric mode, associated data, and the
security notes on session ids, key confirmation, and KDF post-processing of the ISK.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --target thumbv7em-none-eabihf   # no_std proof
cargo deny check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
