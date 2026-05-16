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
    ecdh, generator, kdf_derive, keypair_from_seed, mul_generator, pedersen_commit, pedersen_g,
    pedersen_h, poseidon_hash_fixed, poseidon_hash_sponge, schnorr_sign, schnorr_verify,
    text_utf8_v1_decode, text_utf8_v1_encode, text_utf8_v1_id, validate_point,
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

/// `pedersen_h()` returns the spec's pinned `H` (the blinding
/// generator). Catches an `H` derivation drift end-to-end through
/// the JS<->WASM edge.
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

/// `pedersen_g(0)` returns the spec's pinned `G_0` (the first value
/// generator). Verifies the indexed-generator derivation makes it
/// through the boundary intact.
#[wasm_bindgen_test]
fn pedersen_g_0_matches_spec() {
    let g0 = pedersen_g(0);
    assert_eq!(
        g0.x(),
        "21825913315207187562682941426389735603195557456908788185325554283133704969469",
    );
    assert_eq!(
        g0.y(),
        "13858835039840996693419673582381761260939607442217267755302767527818398641731",
    );
}

/// Spec Vector 1: `commit([1, 2, 3], 7)` — small stream through the
/// boundary as a JS array of decimal strings.
#[wasm_bindgen_test]
fn pedersen_commit_vector_1() {
    let c = pedersen_commit(
        vec!["1".into(), "2".into(), "3".into()],
        "7",
    )
    .expect("valid stream and blinding");
    assert_eq!(
        c.x(),
        "13038198386731673912560721016555247709029515585051432629517992977316576071934",
    );
    assert_eq!(
        c.y(),
        "9212446836796220420114805122843851887604206441937641721882028388154348874834",
    );
}

/// Spec Vector 3: 9-element stream matching `text-utf8-v1`'s shape.
/// The "production" case — every commitment to an encoded text payload
/// has this stream length.
#[wasm_bindgen_test]
fn pedersen_commit_vector_3_text_utf8_shape() {
    let stream: Vec<String> = (0u64..9).map(|i| i.to_string()).collect();
    let c = pedersen_commit(stream, "42").expect("valid");
    assert_eq!(
        c.x(),
        "1816745010582515843223529375604165335664011795439985242868613130573867132011",
    );
    assert_eq!(
        c.y(),
        "1118057154514564837088862449882370788049673922232213149895810435579743690349",
    );
}

/// Spec Vector 4: empty stream produces `blinding · H`. The "no
/// content" edge case.
#[wasm_bindgen_test]
fn pedersen_commit_vector_4_empty_stream() {
    let c = pedersen_commit(vec![], "123").expect("empty is well-defined");
    assert_eq!(
        c.x(),
        "13828148247158678812499162641315699180347697370202244738700865095716896041487",
    );
    assert_eq!(
        c.y(),
        "15186219207262690188902497053707372380315160076221164591981113425196456829665",
    );
}

/// Spec Vector 5sum: the element-wise homomorphism anchor's
/// right-hand side. Pinned at the boundary.
#[wasm_bindgen_test]
fn pedersen_commit_vector_5_homomorphism_anchor() {
    let c = pedersen_commit(
        vec!["15".into(), "35".into(), "55".into()],
        "300",
    )
    .expect("valid");
    assert_eq!(
        c.x(),
        "7197332655677449090088671372714432917743021897248424654297871978491214754206",
    );
    assert_eq!(
        c.y(),
        "3491146607410882481913448536648113321671999435511322181830072546126502831366",
    );
}

/// Malformed inputs come back as exceptions, not panics. Boundary
/// error contract for the new stream-shaped binding.
#[wasm_bindgen_test]
fn pedersen_commit_rejects_garbage() {
    assert!(
        pedersen_commit(vec!["abc".into()], "2").is_err(),
        "garbage stream element must error",
    );
    assert!(
        pedersen_commit(vec!["1".into()], "-3").is_err(),
        "negative blinding must error",
    );
    assert!(
        pedersen_commit(vec!["".into()], "2").is_err(),
        "empty stream element must error",
    );
    assert!(
        pedersen_commit(vec!["1".into()], "abc").is_err(),
        "garbage blinding must error",
    );
}

// --- schnorr fixture (specs/babyjub-schnorr.md § Worked Example) -------

/// Build the spec's signer seed: byte 0 = 0x07, rest zero.
fn schnorr_signer_seed() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = 7;
    s
}

/// Vector 4 (the `text-utf8-v1`-shaped 9-element message): signing
/// `[0, 1, …, 8]` produces the pinned `(R, s)` byte-for-byte through
/// the JS<->WASM edge. The canonical production-use case.
#[wasm_bindgen_test]
fn schnorr_sign_vector_4_text_utf8_shape_matches_spec() {
    let seed = schnorr_signer_seed();
    let message: Vec<String> = (0u64..9).map(|i| i.to_string()).collect();
    let sig = schnorr_sign(&seed, message).expect("valid seed and message");
    assert_eq!(
        sig.r_x(),
        "9907919187759728836420608685439673743018415908584274981339045984432314418876",
    );
    assert_eq!(
        sig.r_y(),
        "14320670493132427095800905404319123040028993772245066136630070019717299866336",
    );
    assert_eq!(
        sig.s(),
        "690166825546950374194223969053258468670318750960230750355004980014353065874",
    );
}

/// Vector 4: verification accepts the spec's pinned signature when
/// supplied via decimal strings (the path a JS caller takes).
#[wasm_bindgen_test]
fn schnorr_verify_vector_4_accepts() {
    let kp = keypair_from_seed(&schnorr_signer_seed()).expect("64-byte seed");
    let message: Vec<String> = (0u64..9).map(|i| i.to_string()).collect();
    let ok = schnorr_verify(
        &kp.pk_x(),
        &kp.pk_y(),
        message,
        "9907919187759728836420608685439673743018415908584274981339045984432314418876",
        "14320670493132427095800905404319123040028993772245066136630070019717299866336",
        "690166825546950374194223969053258468670318750960230750355004980014353065874",
    )
    .expect("inputs are well-formed");
    assert!(ok, "spec vector 4 must verify");
}

/// Empty message (vector 1): signs and verifies. Pins the
/// length-zero edge case at the boundary.
#[wasm_bindgen_test]
fn schnorr_empty_message_signs_and_verifies() {
    let seed = schnorr_signer_seed();
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    let sig = schnorr_sign(&seed, vec![]).expect("empty is valid");
    assert_eq!(
        sig.r_x(),
        "19672181936203324131656225559501475555772993461869651448031019731729494125516",
    );
    let ok = schnorr_verify(
        &kp.pk_x(),
        &kp.pk_y(),
        vec![],
        &sig.r_x(),
        &sig.r_y(),
        &sig.s(),
    )
    .expect("ok");
    assert!(ok);
}

/// Sign-then-verify roundtrip on a fresh message. Catches "verify
/// wired wrong" bugs that the static fixture wouldn't (fixture pins
/// both sides; round-trip catches them being consistently wrong
/// together).
#[wasm_bindgen_test]
fn schnorr_sign_then_verify_roundtrips() {
    let seed = schnorr_signer_seed();
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    let message = vec!["100".to_string(), "200".to_string()];
    let sig = schnorr_sign(&seed, message.clone()).expect("sign");
    let ok = schnorr_verify(
        &kp.pk_x(),
        &kp.pk_y(),
        message,
        &sig.r_x(),
        &sig.r_y(),
        &sig.s(),
    )
    .expect("verify inputs are well-formed");
    assert!(ok);
}

/// Tamper with the message: verification returns `false`. The
/// "valid-but-bad signature" outcome — distinct from broken-input
/// throws.
#[wasm_bindgen_test]
fn schnorr_verify_rejects_tampered_message() {
    let seed = schnorr_signer_seed();
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    let message = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let sig = schnorr_sign(&seed, message).expect("sign");

    let tampered = vec!["1".to_string(), "2".to_string(), "4".to_string()];
    let ok = schnorr_verify(
        &kp.pk_x(),
        &kp.pk_y(),
        tampered,
        &sig.r_x(),
        &sig.r_y(),
        &sig.s(),
    )
    .expect("inputs are well-formed");
    assert!(!ok, "verification must reject a tampered message");
}

/// Tamper with `s` (swap in a different message's `s`): verification
/// returns `false`. Both scalars are valid `Fr` elements, the wire
/// decoder accepts them, but the signature equation no longer holds.
#[wasm_bindgen_test]
fn schnorr_verify_rejects_tampered_s() {
    let seed = schnorr_signer_seed();
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    let m_a = vec!["1".to_string()];
    let m_b = vec!["2".to_string()];
    let sig_a = schnorr_sign(&seed, m_a.clone()).expect("sign a");
    let sig_b = schnorr_sign(&seed, m_b).expect("sign b");

    let ok = schnorr_verify(
        &kp.pk_x(),
        &kp.pk_y(),
        m_a,
        &sig_a.r_x(),
        &sig_a.r_y(),
        &sig_b.s(),
    )
    .expect("inputs are well-formed");
    assert!(!ok, "verification must reject a tampered s");
}

/// Over-length message throws. The boundary's typed error for the
/// 11-element cap; matches the SchnorrError::MessageTooLong native
/// error.
#[wasm_bindgen_test]
fn schnorr_rejects_over_length_message() {
    let seed = schnorr_signer_seed();
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    let too_long: Vec<String> = (1u64..=12).map(|i| i.to_string()).collect();
    assert!(
        schnorr_sign(&seed, too_long.clone()).is_err(),
        "12-element message must throw on sign",
    );
    // For verify the placeholder signature can be anything — the
    // length check fires before signature math.
    let placeholder = schnorr_sign(&seed, vec![]).expect("empty fits");
    assert!(
        schnorr_verify(
            &kp.pk_x(),
            &kp.pk_y(),
            too_long,
            &placeholder.r_x(),
            &placeholder.r_y(),
            &placeholder.s(),
        )
        .is_err(),
        "12-element message must throw on verify",
    );
}

/// Malformed boundary inputs throw. Catches a regression where a
/// boundary panic would crash the wasm module instead of surfacing as
/// a JS exception.
#[wasm_bindgen_test]
fn schnorr_rejects_invalid_inputs() {
    let seed = schnorr_signer_seed();
    let kp = keypair_from_seed(&seed).expect("64-byte seed");
    let sig = schnorr_sign(&seed, vec!["42".to_string()]).expect("sign");

    // Wrong seed length on sign.
    assert!(
        schnorr_sign(&[0u8; 32], vec!["42".to_string()]).is_err(),
        "wrong seed length must throw",
    );
    // Negative element in the message on sign.
    assert!(
        schnorr_sign(&seed, vec!["-3".to_string()]).is_err(),
        "negative element must throw",
    );
    // Off-curve PK on verify.
    assert!(
        schnorr_verify(
            "1",
            "1",
            vec!["42".to_string()],
            &sig.r_x(),
            &sig.r_y(),
            &sig.s(),
        )
        .is_err(),
        "off-curve PK must throw",
    );
    // Off-curve R on verify.
    assert!(
        schnorr_verify(
            &kp.pk_x(),
            &kp.pk_y(),
            vec!["42".to_string()],
            "1",
            "1",
            &sig.s(),
        )
        .is_err(),
        "off-curve R must throw",
    );
    // Garbage element in the message on verify.
    assert!(
        schnorr_verify(
            &kp.pk_x(),
            &kp.pk_y(),
            vec!["abc".to_string()],
            &sig.r_x(),
            &sig.r_y(),
            &sig.s(),
        )
        .is_err(),
        "garbage element must throw",
    );
}

// --- text-utf8-v1 fixture (specs/encodings/text-utf8-v1.md) ---------------

/// `encoding_id` matches the spec. Catches any drift in the path-based
/// id derivation across the boundary.
#[wasm_bindgen_test]
fn text_utf8_v1_id_matches_spec() {
    assert_eq!(
        text_utf8_v1_id(),
        "10251905648233427808659162032937842155138269080868533503078341140126603942221",
    );
}

/// Vector 2 (`"hello, world!"`): encode produces the pinned field
/// stream and the round-trip decode yields the exact input bytes.
#[wasm_bindgen_test]
fn text_utf8_v1_hello_roundtrips_through_boundary() {
    let s = b"hello, world!";
    let stream = text_utf8_v1_encode(s).expect("encode");
    assert_eq!(stream.len(), 9);
    assert_eq!(stream[0], "13");
    assert_eq!(
        stream[1],
        "184452094211679030227880241948843765817935618364777678222724444834882387968",
    );
    for f in &stream[2..] {
        assert_eq!(f, "0");
    }
    let decoded = text_utf8_v1_decode(stream).expect("decode");
    assert_eq!(decoded.as_slice(), s);
}

/// Vector 3 (multibyte UTF-8). Length is in bytes; 7 chars × 3 = 21.
#[wasm_bindgen_test]
fn text_utf8_v1_multibyte_roundtrips_through_boundary() {
    let s = "こんにちは世界".as_bytes();
    let stream = text_utf8_v1_encode(s).expect("encode");
    assert_eq!(stream[0], "21");
    assert_eq!(
        stream[1],
        "401968596055196051537592476051840533583207957312700825760665297196064702464",
    );
    let decoded = text_utf8_v1_decode(stream).expect("decode");
    assert_eq!(decoded.as_slice(), s);
}

/// Vector 4 (full-length, 248 × `'x'`). Every chunk reads the same
/// pinned constant.
#[wasm_bindgen_test]
fn text_utf8_v1_full_length_through_boundary() {
    let s: Vec<u8> = vec![b'x'; 248];
    let stream = text_utf8_v1_encode(&s).expect("encode");
    assert_eq!(stream[0], "248");
    let chunk_x =
        "212853105215654770999211369501264536494981589458898095660767617661605017720";
    for f in &stream[1..] {
        assert_eq!(f, chunk_x);
    }
    let decoded = text_utf8_v1_decode(stream).expect("decode");
    assert_eq!(decoded, s);
}

/// The boundary's error contract: malformed inputs throw, not panic.
/// One assertion per failure mode the spec defines.
#[wasm_bindgen_test]
fn text_utf8_v1_rejects_invalid_inputs() {
    // Over-length on encode.
    let too_long = vec![b'x'; 249];
    assert!(text_utf8_v1_encode(&too_long).is_err(), "over-length must throw");

    // Non-UTF-8 on encode.
    let not_utf8 = [0xC3u8, 0x28];
    assert!(text_utf8_v1_encode(&not_utf8).is_err(), "non-utf8 must throw");

    // Wrong arity on decode (8 elements instead of 9).
    let too_few: Vec<String> = vec!["0".to_string(); 8];
    assert!(text_utf8_v1_decode(too_few).is_err(), "wrong arity must throw");

    // Garbage decimal string on decode.
    let mut garbage: Vec<String> = vec!["0".to_string(); 9];
    garbage[3] = "abc".to_string();
    assert!(text_utf8_v1_decode(garbage).is_err(), "garbage decimal must throw");

    // Length prefix > MAX_BYTES on decode.
    let mut oversize: Vec<String> = vec!["0".to_string(); 9];
    oversize[0] = "249".to_string();
    assert!(
        text_utf8_v1_decode(oversize).is_err(),
        "over-MAX length prefix must throw",
    );
}

// --- poseidon hash fixture (specs/poseidon-hash-{fixed,sponge}.md) -----

/// Pinned domain tag from the shared fixture: `domain_tag("poseidon-hash-fixture-v1")`.
/// Catches any drift in either Blake2b or the field-reduction.
const POSEIDON_FIXTURE_DOMAIN: &str =
    "3979466444311687069470688388412388132284863585885029621423754853532995657454";

/// Fixed Vector 2 (`[1, 2, 3]`): byte-exact through the boundary.
#[wasm_bindgen_test]
fn poseidon_fixed_vector_1_2_3_matches_spec() {
    let out = poseidon_hash_fixed(
        POSEIDON_FIXTURE_DOMAIN,
        vec!["1".into(), "2".into(), "3".into()],
    )
    .expect("valid inputs");
    assert_eq!(
        out,
        "12187659365913684405060258586364191053768216120494362944135933139066214817674",
    );
}

/// Sponge Vector 2 (`[1, 2, 3]`): byte-exact through the boundary.
/// Different from the fixed output on the same inputs — the
/// cross-construction differentiator at the boundary.
#[wasm_bindgen_test]
fn poseidon_sponge_vector_1_2_3_matches_spec() {
    let out = poseidon_hash_sponge(
        POSEIDON_FIXTURE_DOMAIN,
        vec!["1".into(), "2".into(), "3".into()],
    )
    .expect("valid inputs");
    assert_eq!(
        out,
        "3142103391069538918340996461610585237878047473358483513672836623723625048541",
    );
}

/// Sponge handles the 20-input vector the fixed sibling rejects. The
/// canonical "you need the sponge here" case.
#[wasm_bindgen_test]
fn poseidon_sponge_handles_20_inputs() {
    let inputs: Vec<String> = (0..20u64).map(|i| i.to_string()).collect();
    let out = poseidon_hash_sponge(POSEIDON_FIXTURE_DOMAIN, inputs).expect("valid");
    assert_eq!(
        out,
        "9741254265752179457738278212425315146396646303497642974741669492324356027870",
    );
}

/// Fixed throws on the 20-input vector; sponge handles it. The
/// error-contract version of the same test.
#[wasm_bindgen_test]
fn poseidon_fixed_rejects_20_inputs() {
    let inputs: Vec<String> = (0..20u64).map(|i| i.to_string()).collect();
    assert!(
        poseidon_hash_fixed(POSEIDON_FIXTURE_DOMAIN, inputs).is_err(),
        "20 inputs → arity 21 must throw on fixed",
    );
}

/// Empty inputs are well-defined for both constructions. Each
/// produces a per-domain constant; the two are distinct.
#[wasm_bindgen_test]
fn poseidon_empty_inputs_both_paths() {
    let fixed = poseidon_hash_fixed(POSEIDON_FIXTURE_DOMAIN, vec![]).expect("ok");
    let sponge = poseidon_hash_sponge(POSEIDON_FIXTURE_DOMAIN, vec![]).expect("ok");
    assert_eq!(
        fixed,
        "20041987324127481975055040243862195468401413291871545710243215988343495957297",
    );
    assert_eq!(
        sponge,
        "10642285785463773045920661422493220139048932562145189104824959581581429359133",
    );
    assert_ne!(fixed, sponge, "fixed and sponge MUST differ at the boundary");
}

/// Both functions reject garbage input. Boundary error contract.
#[wasm_bindgen_test]
fn poseidon_rejects_garbage() {
    // Garbage domain tag.
    assert!(poseidon_hash_fixed("abc", vec!["1".into()]).is_err());
    assert!(poseidon_hash_sponge("abc", vec!["1".into()]).is_err());
    // Garbage input element.
    assert!(
        poseidon_hash_fixed(POSEIDON_FIXTURE_DOMAIN, vec!["abc".into()]).is_err()
    );
    assert!(
        poseidon_hash_sponge(POSEIDON_FIXTURE_DOMAIN, vec!["abc".into()]).is_err()
    );
    // Negative number (boundary rejects leading signs).
    assert!(
        poseidon_hash_fixed(POSEIDON_FIXTURE_DOMAIN, vec!["-1".into()]).is_err()
    );
    assert!(
        poseidon_hash_sponge(POSEIDON_FIXTURE_DOMAIN, vec!["-1".into()]).is_err()
    );
}

// --- kdf fixture (specs/babyjub-kdf.md § Worked Example) ---------------

/// Alice/Bob ECDH shared point — same as the ECDH spec's worked
/// example. Reused here so the KDF fixture chains cleanly.
const ALICE_BOB_SHARED_X: &str =
    "4441722070262887487676852990759346353102280890264110527729805261601919952792";
const ALICE_BOB_SHARED_Y: &str =
    "18505774984025635106527431283405915983682689754171973024874112571296549171475";

/// Pinned role tags from the spec, in decimal-string form.
const ENC_ROLE_TAG: &str =
    "1509687719585944131241352475068886393759608140501623646780323187386706626075";
const MAC_ROLE_TAG: &str =
    "5516219051016623209397290384142210256012461986142239137807233927652814454837";

/// Vector 2: cipher key for envelope 42, byte-for-byte through the
/// boundary. The canonical production-use case.
#[wasm_bindgen_test]
fn kdf_vector_2_cipher_key_envelope_42() {
    let key = kdf_derive(
        ALICE_BOB_SHARED_X,
        ALICE_BOB_SHARED_Y,
        vec![ENC_ROLE_TAG.into(), "42".into()],
    )
    .expect("valid inputs");
    assert_eq!(
        key,
        "9799522521534548758133939899702695884003167902663631833387651174524282263857",
    );
}

/// Vector 3: MAC key for envelope 42. The cross-construction
/// differentiator at the boundary — same shared point and envelope
/// id as vector 2, only the role tag differs, but the key MUST
/// differ.
#[wasm_bindgen_test]
fn kdf_vector_3_mac_key_envelope_42() {
    let key = kdf_derive(
        ALICE_BOB_SHARED_X,
        ALICE_BOB_SHARED_Y,
        vec![MAC_ROLE_TAG.into(), "42".into()],
    )
    .expect("valid inputs");
    assert_eq!(
        key,
        "5302105009719633730025155498822445041452574923386899996802294480945238328306",
    );
}

/// Cipher and MAC keys for the same envelope MUST differ. Pins the
/// role-separation property at the boundary.
#[wasm_bindgen_test]
fn kdf_cipher_and_mac_keys_for_same_envelope_differ() {
    let k_enc = kdf_derive(
        ALICE_BOB_SHARED_X,
        ALICE_BOB_SHARED_Y,
        vec![ENC_ROLE_TAG.into(), "42".into()],
    )
    .expect("ok");
    let k_mac = kdf_derive(
        ALICE_BOB_SHARED_X,
        ALICE_BOB_SHARED_Y,
        vec![MAC_ROLE_TAG.into(), "42".into()],
    )
    .expect("ok");
    assert_ne!(k_enc, k_mac, "cipher and MAC keys MUST differ");
}

/// Empty context is valid; produces a per-shared-point constant.
#[wasm_bindgen_test]
fn kdf_empty_context_works() {
    let key = kdf_derive(ALICE_BOB_SHARED_X, ALICE_BOB_SHARED_Y, vec![]).expect("ok");
    assert_eq!(
        key,
        "17636122932579740171900542371485785762200772773883779227467254854068102551698",
    );
}

/// Boundary error contract: bad shared point, garbage context, and
/// over-length context all throw rather than silently producing a
/// wrong key.
#[wasm_bindgen_test]
fn kdf_rejects_invalid_inputs() {
    // Off-curve shared point.
    assert!(
        kdf_derive("1", "1", vec![]).is_err(),
        "off-curve shared point must throw",
    );
    // Garbage shared coordinate.
    assert!(
        kdf_derive("abc", ALICE_BOB_SHARED_Y, vec![]).is_err(),
        "garbage shared coord must throw",
    );
    // Garbage context element.
    assert!(
        kdf_derive(ALICE_BOB_SHARED_X, ALICE_BOB_SHARED_Y, vec!["abc".into()]).is_err(),
        "garbage context element must throw",
    );
    // Over-length context.
    let too_long: Vec<String> = (1u64..=10).map(|i| i.to_string()).collect();
    assert!(
        kdf_derive(ALICE_BOB_SHARED_X, ALICE_BOB_SHARED_Y, too_long).is_err(),
        "10-element context must throw",
    );
}
