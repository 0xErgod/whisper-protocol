//! Cross-language compatibility fixture for the two Poseidon hash
//! families.
//!
//! Executable form of:
//! - [`specs/poseidon-hash-fixed.md § Worked Example`](../../specs/poseidon-hash-fixed.md#worked-example)
//! - [`specs/poseidon-hash-sponge.md § Worked Example`](../../specs/poseidon-hash-sponge.md#worked-example)
//!
//! If any pinned value drifts, these tests fail. Integration tests
//! (in `tests/`) by design — they exercise the public surface as a
//! third-party crate would.

use ark_ff::PrimeField;

use crypto::babyjub::Fq;
use crypto::poseidon::{
    domain_tag, poseidon_hash_fixed, poseidon_hash_sponge, PoseidonError,
};

const FIXTURE_DOMAIN: &str = "poseidon-hash-fixture-v1";

fn dec(f: Fq) -> String {
    f.into_bigint().to_string()
}

/// Domain-tag derivation matches the spec.
#[test]
fn fixture_domain_tag_matches_spec() {
    let d = domain_tag(FIXTURE_DOMAIN);
    assert_eq!(
        dec(d),
        "3979466444311687069470688388412388132284863585885029621423754853532995657454",
    );
}

// --- poseidon_hash_fixed ----------------------------------------------

/// Vector 1: empty inputs. `Poseidon-1(domain_tag)`.
#[test]
fn fixed_vector_1_empty() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let h = poseidon_hash_fixed(d, &[]).expect("arity 1 is in range");
    assert_eq!(
        dec(h),
        "20041987324127481975055040243862195468401413291871545710243215988343495957297",
    );
}

/// Vector 2: `[1, 2, 3]`. Poseidon-4.
#[test]
fn fixed_vector_2_one_two_three() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let h = poseidon_hash_fixed(d, &[Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)])
        .expect("arity 4 is in range");
    assert_eq!(
        dec(h),
        "12187659365913684405060258586364191053768216120494362944135933139066214817674",
    );
}

/// Vector 3: `[42; 8]`. Poseidon-9.
#[test]
fn fixed_vector_3_eight_forty_twos() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let inputs: Vec<Fq> = (0..8).map(|_| Fq::from(42u64)).collect();
    let h = poseidon_hash_fixed(d, &inputs).expect("arity 9 is in range");
    assert_eq!(
        dec(h),
        "2868523744403348874235778030142570132454685527577859032935933827672336794306",
    );
}

/// Vector 4: 20 inputs is out of range; fixed errors.
#[test]
fn fixed_vector_4_out_of_range_errors() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let inputs: Vec<Fq> = (0u64..20).map(Fq::from).collect();
    assert!(matches!(
        poseidon_hash_fixed(d, &inputs),
        Err(PoseidonError::ArityOutOfRange { total_arity: 21 })
    ));
}

// --- poseidon_hash_sponge ---------------------------------------------

/// Sponge Vector 1: empty inputs. One permutation, well-defined
/// per-domain constant.
#[test]
fn sponge_vector_1_empty() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let h = poseidon_hash_sponge(d, &[]);
    assert_eq!(
        dec(h),
        "10642285785463773045920661422493220139048932562145189104824959581581429359133",
    );
}

/// Sponge Vector 2: `[1, 2, 3]`.
#[test]
fn sponge_vector_2_one_two_three() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let h = poseidon_hash_sponge(d, &[Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)]);
    assert_eq!(
        dec(h),
        "3142103391069538918340996461610585237878047473358483513672836623723625048541",
    );
}

/// Sponge Vector 3: `[42; 8]`.
#[test]
fn sponge_vector_3_eight_forty_twos() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let inputs: Vec<Fq> = (0..8).map(|_| Fq::from(42u64)).collect();
    let h = poseidon_hash_sponge(d, &inputs);
    assert_eq!(
        dec(h),
        "5990019678255268617078544532103655242415209041127922847673813392906627566777",
    );
}

/// Sponge Vector 4: 20 inputs. The fixed-arity sibling errors here;
/// sponge handles it cleanly. This vector demonstrates the regime
/// where the sponge is the only available primitive.
#[test]
fn sponge_vector_4_twenty_inputs() {
    let d = domain_tag(FIXTURE_DOMAIN);
    let inputs: Vec<Fq> = (0u64..20).map(Fq::from).collect();
    let h = poseidon_hash_sponge(d, &inputs);
    assert_eq!(
        dec(h),
        "9741254265752179457738278212425315146396646303497642974741669492324356027870",
    );
}

// --- the cross-construction differentiator (load-bearing) -------------

/// On every input where both constructions produce a defined output,
/// the two MUST differ. The contract a consumer's spec relies on:
/// "fixed and sponge are different hash functions, and the choice
/// between them is irreversibly part of the consumer's spec."
#[test]
fn fixed_and_sponge_disagree_on_shared_vectors() {
    let d = domain_tag(FIXTURE_DOMAIN);

    let cases: Vec<Vec<Fq>> = vec![
        vec![],
        vec![Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)],
        (0..8).map(|_| Fq::from(42u64)).collect(),
    ];

    for inputs in cases {
        let h_fixed = poseidon_hash_fixed(d, &inputs).expect("fits");
        let h_sponge = poseidon_hash_sponge(d, &inputs);
        assert_ne!(
            h_fixed, h_sponge,
            "fixed and sponge MUST be distinguishable hashes (input len = {})",
            inputs.len(),
        );
    }
}
