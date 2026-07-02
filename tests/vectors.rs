//! Full-protocol test vectors from draft-irtf-cfrg-cpace-21 Appendix B.3.9,
//! driven through the public API with a deterministic RNG.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "fixed test vectors either match or the test must fail loudly"
)]

mod util;

use cpace::{Context, Msg};
use util::rng::FixedRng;
use util::{hex, json_from_b64};

struct Vectors {
    prs: Vec<u8>,
    ci: Vec<u8>,
    sid: Vec<u8>,
    ya: Vec<u8>,
    ad_a: Vec<u8>,
    big_ya: Vec<u8>,
    yb: Vec<u8>,
    ad_b: Vec<u8>,
    big_yb: Vec<u8>,
    isk_ir: Vec<u8>,
    isk_sy: Vec<u8>,
    sid_output_ir: Vec<u8>,
    sid_output_oc: Vec<u8>,
}

fn load() -> Vectors {
    let json = json_from_b64(include_str!("data/b3_9_vectors.b64"));
    let field = |name: &str| hex(json.get(name).unwrap().as_str().unwrap());
    Vectors {
        prs: field("PRS"),
        ci: field("CI"),
        sid: field("sid"),
        ya: field("ya"),
        ad_a: field("ADa"),
        big_ya: field("Ya"),
        yb: field("yb"),
        ad_b: field("ADb"),
        big_yb: field("Yb"),
        isk_ir: field("ISK_IR"),
        isk_sy: field("ISK_SY"),
        sid_output_ir: field("sid_output_ir"),
        sid_output_oc: field("sid_output_oc"),
    }
}

fn expected_msg(element: &[u8], ad: &[u8]) -> Vec<u8> {
    // lv_cat(Y, AD) with single-byte length prefixes; both fields in the
    // B.3 vectors are short enough for that.
    let mut out = vec![u8::try_from(element.len()).unwrap()];
    out.extend_from_slice(element);
    out.push(u8::try_from(ad.len()).unwrap());
    out.extend_from_slice(ad);
    out
}

#[test]
fn initiator_responder_exchange_matches_vectors() {
    let v = load();
    let ctx = Context {
        prs: &v.prs,
        ci: &v.ci,
        sid: &v.sid,
    };

    let (state_a, msg_a) = cpace::initiate(&ctx, &v.ad_a, &mut FixedRng(v.ya.clone()));
    assert_eq!(msg_a.as_bytes(), expected_msg(&v.big_ya, &v.ad_a));
    assert_eq!(msg_a.element().as_slice(), v.big_ya);
    assert_eq!(msg_a.associated_data(), v.ad_a);

    let received_a = Msg::from_bytes(msg_a.as_bytes()).unwrap();
    let (msg_b, output_b) =
        cpace::respond(&ctx, &v.ad_b, &received_a, &mut FixedRng(v.yb.clone())).unwrap();
    assert_eq!(msg_b.as_bytes(), expected_msg(&v.big_yb, &v.ad_b));
    assert_eq!(output_b.isk.as_bytes().as_slice(), v.isk_ir);
    assert_eq!(output_b.sid_output.as_slice(), v.sid_output_ir);

    let received_b = Msg::from_bytes(msg_b.as_bytes()).unwrap();
    let output_a = state_a.finish(&received_b).unwrap();
    assert_eq!(output_a.isk.as_bytes().as_slice(), v.isk_ir);
    assert_eq!(output_a.sid_output.as_slice(), v.sid_output_ir);
}

#[test]
fn symmetric_exchange_matches_vectors_in_both_orders() {
    let v = load();
    let ctx = Context {
        prs: &v.prs,
        ci: &v.ci,
        sid: &v.sid,
    };

    let (state_a, msg_a) = cpace::start_symmetric(&ctx, &v.ad_a, &mut FixedRng(v.ya.clone()));
    let (state_b, msg_b) = cpace::start_symmetric(&ctx, &v.ad_b, &mut FixedRng(v.yb.clone()));
    assert_eq!(msg_a.as_bytes(), expected_msg(&v.big_ya, &v.ad_a));
    assert_eq!(msg_b.as_bytes(), expected_msg(&v.big_yb, &v.ad_b));

    // Completion order must not matter: A finishes with B's message and
    // vice versa, and both match the draft's ISK_SY.
    let output_a = state_a
        .finish(&Msg::from_bytes(msg_b.as_bytes()).unwrap())
        .unwrap();
    let output_b = state_b
        .finish(&Msg::from_bytes(msg_a.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(output_a.isk.as_bytes().as_slice(), v.isk_sy);
    assert_eq!(output_b.isk.as_bytes().as_slice(), v.isk_sy);
    assert_eq!(output_a.sid_output.as_slice(), v.sid_output_oc);
    assert_eq!(output_b.sid_output.as_slice(), v.sid_output_oc);
}
