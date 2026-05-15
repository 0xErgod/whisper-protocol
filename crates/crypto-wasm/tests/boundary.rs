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
//! Run with: `wasm-pack test --headless --firefox crates/crypto-wasm`
//! (or `--chrome`).

use wasm_bindgen_test::*;

use crypto_wasm::{generator, mul_generator};

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
