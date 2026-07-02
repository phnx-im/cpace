//! Shared helpers for the integration tests that use the spec vectors.

pub mod rng;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

pub fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in test vector")
}

pub fn json_from_b64(blob: &str) -> serde_json::Value {
    let clean: String = blob.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = BASE64.decode(clean).expect("valid base64 test vector");
    serde_json::from_slice(&raw).expect("valid JSON test vector")
}
