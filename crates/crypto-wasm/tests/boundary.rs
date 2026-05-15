//! Boundary fixture test — runs in a real headless browser via `wasm-pack test`.
//!
//! `crypto`'s own tests already prove the curve math. This file proves
//! something different and equally necessary: that the values survive the
//! **JS<->WASM boundary** unchanged — the `wasm32` codegen, the wasm-bindgen
//! string marshalling, the `.wasm` artifact wasm-pack actually emits.
//!
//! A passing `cargo test -p crypto` does NOT imply a passing boundary. The
//! native build and the wasm build are different codegen; only running the
//! binding *as a wasm module* exercises the edge `apps/curve` will hit.
//!
//! The vectors are the same ones pinned in `specs/babyjub-curve.md § Worked
//! Example` and checked natively in `crypto`'s fixture test — so this test
//! confirms the spec contract holds end-to-end, all the way out to the
//! browser, with no re-encoding in between.
//!
//! Run with: `wasm-pack test --headless --chrome --release crates/crypto-wasm`
//! (or `--firefox`).
//!
//! `--release` is required: arkworks generates functions whose local-count
//! exceeds the wasm spec's 50,000-per-function limit in debug builds. The
//! release profile inlines and shrinks them below the limit. This is not a
//! correctness issue — release builds are how the binding ships anyway —
//! but it is a non-obvious gotcha worth pinning here so a future contributor
//! does not waste time on a `--debug` invocation that cannot work.

use wasm_bindgen_test::*;

use crypto_wasm::{
    ecdh, generator, keypair_from_seed, mul_generator, pedersen_commit, pedersen_h,
    validate_point,
};

wasm_bindgen_test_configure!(run_in_browser);

/// `generator()` across the boundary must be `Base8` — the exact decimals from
/// `specs/babyjub-curve.md § Generator`.
#[wasm_bindgen_test]
fn generator_is_base8() {
    let g = generator();
    assert_eq!(
        g.x(),
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    );
    assert_eq!(
        g.y(),
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    );
}

/// Every `k · Base8` row from `specs/babyjub-curve.md § Worked Example`,
/// Anchor 2 — driven through `mul_generator` as a JS string, exactly as
/// `apps/curve` will call it.
#[wasm_bindgen_test]
fn base8_scalar_mul_vectors_survive_the_boundary() {
    // (scalar, expected x, expected y) — verbatim from the spec.
    let vectors: &[(&str, &str, &str)] = &[
        (
            "1",
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        ),
        (
            "2",
            "10031262171927540148667355526369034398030886437092045105752248699557385197826",
            "633281375905621697187330766174974863687049529291089048651929454608812697683",
        ),
        (
            "3",
            "2763488322167937039616325905516046217694264098671987087929565332380420898366",
            "15305195750036305661220525648961313310481046260814497672243197092298550508693",
        ),
        (
            "8",
            "7582035475627193640797276505418002166691739036475590846121162698650004832581",
            "7801528930831391612913542953849263092120765287178679640990215688947513841260",
        ),
        (
            "1000",
            "20366147795936572600700348767835863189204735700033902769792878907543918679364",
            "17979751125406099319734770781608767238997398840154679652223692501113096137972",
        ),
        (
            "4242424242",
            "8197680051882628970410681376493202672655988696749960149267822370593492838760",
            "12894077115825233362045965817688273159131941840146661890364266485669764812312",
        ),
    ];

    for (k, want_x, want_y) in vectors {
        let p = mul_generator(k).expect("valid scalar");
        assert_eq!(&p.x(), want_x, "k = {k}: x coordinate drifted across the boundary");
        assert_eq!(&p.y(), want_y, "k = {k}: y coordinate drifted across the boundary");
    }
}

/// The large-scalar vector: `2^200 · Base8`. Passed as a literal decimal
/// string — confirms a scalar far past `u64` range marshals correctly.
#[wasm_bindgen_test]
fn large_scalar_survives_the_boundary() {
    // 2^200 in base 10.
    let two_pow_200 =
        "1606938044258990275541962092341162602522202993782792835301376";
    let p = mul_generator(two_pow_200).expect("valid scalar");
    assert_eq!(
        p.x(),
        "5724625655608868645689535268422070084543995927732212059724113152068754891373",
    );
    assert_eq!(
        p.y(),
        "10308923700401579816603597606813811960552754413890927913080984195249222032507",
    );
}

/// A malformed scalar must come back as a JS exception (`Err`), not a panic
/// (which in wasm aborts the whole module). This is the boundary's error
/// contract.
#[wasm_bindgen_test]
fn malformed_scalar_is_an_error_not_a_panic() {
    for bad in ["", "abc", "-3", "1.5", "0x10"] {
        assert!(
            mul_generator(bad).is_err(),
            "expected an error for malformed scalar {bad:?}",
        );
    }
}

// --- keypair fixture (specs/babyjub-keypair.md § Worked Example) ----------

/// Seed of all zeros: spec § Worked Example, vector 1, driven through the
/// JS boundary as a `Uint8Array` (here, a `&[u8]`).
#[wasm_bindgen_test]
fn keypair_fixture_all_zero_seed() {
    let kp = keypair_from_seed(&[0u8; 64]).expect("64-byte seed");
    assert_eq!(
        kp.pk_x(),
        "9052145210158052161818611168469442415783119048928084171117132839267951576749",
    );
    assert_eq!(
        kp.pk_y(),
        "15138733388225546515036950290042250293266309799081989529651843475752774394912",
    );
}

/// Seed of `0x42 × 64`: spec § Worked Example, vector 2.
#[wasm_bindgen_test]
fn keypair_fixture_all_0x42_seed() {
    let kp = keypair_from_seed(&[0x42u8; 64]).expect("64-byte seed");
    assert_eq!(
        kp.pk_x(),
        "10242056643687748052026914853801031667608768151841054399444813507230536137636",
    );
    assert_eq!(
        kp.pk_y(),
        "17209935276727295699825960001966777169457960631433628415363271904988532178005",
    );
}

/// Seed `[0x01, 0x02, ..., 0x40]`: spec § Worked Example, vector 3. Catches
/// a byte-order mistake in the chunking that a single-symbol fixture would
/// not.
#[wasm_bindgen_test]
fn keypair_fixture_increasing_seed() {
    let mut seed = [0u8; 64];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i + 1) as u8;
    }
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    assert_eq!(
        kp.pk_x(),
        "20850129809617136780643076514291815738908181923486074779130442852041357820493",
    );
    assert_eq!(
        kp.pk_y(),
        "6638083023153244747644631095237619826300111037602892009430291132442244811183",
    );
}

/// A seed of the wrong length must come back as a JS exception, not a panic.
/// The boundary enforces the 64-byte contract.
#[wasm_bindgen_test]
fn keypair_rejects_wrong_seed_length() {
    assert!(keypair_from_seed(&[]).is_err(), "empty seed must be an error");
    assert!(keypair_from_seed(&[0u8; 32]).is_err(), "32-byte seed must be an error");
    assert!(keypair_from_seed(&[0u8; 63]).is_err(), "63-byte seed must be an error");
    assert!(keypair_from_seed(&[0u8; 65]).is_err(), "65-byte seed must be an error");
}

// --- validate_point boundary contract -------------------------------------

/// The generator survives `validate_point` — the simplest "is this point
/// even valid?" check passes for a known-good point.
#[wasm_bindgen_test]
fn validate_point_accepts_generator() {
    let g = generator();
    let v = validate_point(&g.x(), &g.y()).expect("Base8 is valid");
    assert_eq!(v.x(), g.x());
    assert_eq!(v.y(), g.y());
}

/// `validate_point` rejects an off-curve point as a JS exception. `(1, 1)`
/// is the simplest off-curve fixture.
#[wasm_bindgen_test]
fn validate_point_rejects_off_curve() {
    assert!(validate_point("1", "1").is_err());
}

/// `validate_point` rejects malformed coordinate strings the same way the
/// scalar entry points do.
#[wasm_bindgen_test]
fn validate_point_rejects_garbage_coords() {
    assert!(validate_point("abc", "1").is_err());
    assert!(validate_point("", "1").is_err());
    assert!(validate_point("-1", "1").is_err());
}

// --- ecdh fixture (specs/babyjub-ecdh.md § Worked Example) ----------------

/// Build Alice / Bob's spec seeds: 64 bytes, single non-zero in byte 0.
fn seed_with_byte_zero(byte: u8) -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = byte;
    s
}

/// `ecdh(Alice_seed, PK_Bob) == ecdh(Bob_seed, PK_Alice)`, and both
/// equal the spec's pinned shared point — byte-for-byte across the
/// JS<->WASM edge.
#[wasm_bindgen_test]
fn ecdh_matches_spec_and_is_symmetric() {
    let alice_seed = seed_with_byte_zero(1);
    let bob_seed = seed_with_byte_zero(2);

    let pk_a = keypair_from_seed(&alice_seed).expect("64-byte seed");
    let pk_b = keypair_from_seed(&bob_seed).expect("64-byte seed");

    let shared_ab = ecdh(&alice_seed, &pk_b.pk_x(), &pk_b.pk_y())
        .expect("valid seed and PK");
    let shared_ba = ecdh(&bob_seed, &pk_a.pk_x(), &pk_a.pk_y())
        .expect("valid seed and PK");

    let want_x =
        "4441722070262887487676852990759346353102280890264110527729805261601919952792";
    let want_y =
        "18505774984025635106527431283405915983682689754171973024874112571296549171475";

    assert_eq!(shared_ab.x(), want_x, "sk_A · PK_B x drifted across the boundary");
    assert_eq!(shared_ab.y(), want_y, "sk_A · PK_B y drifted across the boundary");
    assert_eq!(shared_ba.x(), want_x, "sk_B · PK_A x drifted across the boundary");
    assert_eq!(shared_ba.y(), want_y, "sk_B · PK_A y drifted across the boundary");
}

/// A peer key that does not survive validation (off-curve, garbage,
/// wrong-length seed) must come back as a JS exception, not a panic.
/// The boundary's error contract for ECDH inputs.
#[wasm_bindgen_test]
fn ecdh_rejects_invalid_inputs() {
    let seed = seed_with_byte_zero(1);
    // Off-curve peer point.
    assert!(ecdh(&seed, "1", "1").is_err(), "off-curve peer must error");
    // Garbage peer x.
    assert!(ecdh(&seed, "abc", "1").is_err(), "garbage peer x must error");
    // Wrong seed length.
    let g = generator();
    assert!(
        ecdh(&[0u8; 32], &g.x(), &g.y()).is_err(),
        "wrong seed length must error",
    );
}

// --- pedersen fixture (specs/babyjub-pedersen.md § Worked Example) -------

/// `pedersen_h()` returns the spec's pinned `H`. Catches an `H`
/// derivation drift end-to-end through the JS<->WASM edge.
#[wasm_bindgen_test]
fn pedersen_h_matches_spec() {
    let h = pedersen_h();
    assert_eq!(
        h.x(),
        "841592716755229802932648006577806087532565884664794707633999447952449024030",
    );
    assert_eq!(
        h.y(),
        "21165608275098473985804540174915770236470038226241417420449949757110115410790",
    );
}

/// `pedersen_commit(1, 2)` — spec vector 1, driven through the boundary
/// as decimal strings exactly as `apps/curve` will call it.
#[wasm_bindgen_test]
fn pedersen_commit_vector_1() {
    let c = pedersen_commit("1", "2").expect("valid scalars");
    assert_eq!(
        c.x(),
        "19911656000857052962597456184037789990217243984679140824149869840037557852443",
    );
    assert_eq!(
        c.y(),
        "34605269953567020705948092501852398380697724299788400696888085852242656086",
    );
}

/// `pedersen_commit(85, 7)` — spec vector 5, the homomorphic-sum
/// anchor. The TS-side panel will visualize `commit(42, 2) + commit(43,
/// 5) == commit(85, 7)`; this test pins the right-hand-side.
#[wasm_bindgen_test]
fn pedersen_commit_vector_5() {
    let c = pedersen_commit("85", "7").expect("valid scalars");
    assert_eq!(
        c.x(),
        "6870881176262591255209957784559476352128178258958653506281010548778139552124",
    );
    assert_eq!(
        c.y(),
        "21358251945557300339181094850512781582761528410355366539487020884672487905717",
    );
}

/// Malformed scalars come back as exceptions, not panics. The
/// boundary's error contract for `pedersen_commit`.
#[wasm_bindgen_test]
fn pedersen_commit_rejects_garbage() {
    assert!(pedersen_commit("abc", "2").is_err(), "garbage value must error");
    assert!(pedersen_commit("1", "-3").is_err(), "negative blinding must error");
    assert!(pedersen_commit("", "2").is_err(), "empty value must error");
}
