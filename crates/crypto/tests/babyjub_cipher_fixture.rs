//! Cross-language compatibility fixture for `babyjub-cipher`.
//!
//! Executable form of `specs/babyjub-cipher.md § Worked Example`. If
//! anything drifts — domain tag, counter encoding, field arithmetic
//! direction, Poseidon parameters — these fail. Integration test
//! (in `tests/`) by design.
//!
//! Pinning strategy: chain from the KDF fixture's key (envelope 42,
//! cipher role), then assert every ciphertext element for each
//! vector matches the spec's exact decimal.

use ark_ff::PrimeField;

use crypto::babyjub::{
    decrypt, encrypt, kdf_derive, keypair_from_seed, shared_secret, Fq, Seed,
};
use crypto::poseidon::domain_tag;

fn alice_bob_cipher_key() -> Fq {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
    let shared = shared_secret(&sk_a, &pk_b);
    kdf_derive(
        &shared,
        &[domain_tag("envelope-cipher-key"), Fq::from(42u64)],
    )
    .expect("ok")
}

fn alice_bob_mac_key() -> Fq {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, _) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
    let shared = shared_secret(&sk_a, &pk_b);
    kdf_derive(
        &shared,
        &[domain_tag("envelope-mac-key"), Fq::from(42u64)],
    )
    .expect("ok")
}

fn dec(f: Fq) -> String {
    f.into_bigint().to_string()
}

fn dec_vec(stream: &[Fq]) -> Vec<String> {
    stream.iter().map(|f| dec(*f)).collect()
}

/// Sanity: the cipher key used by this fixture must equal the one
/// `specs/babyjub-kdf.md` Vector 2 pins. If it drifts, every
/// ciphertext vector below is computed against the wrong key.
#[test]
fn cipher_key_matches_kdf_spec() {
    assert_eq!(
        dec(alice_bob_cipher_key()),
        "9799522521534548758133939899702695884003167902663631833387651174524282263857",
    );
}

/// Vector 1: empty plaintext encrypts to empty ciphertext.
#[test]
fn fixture_vector_1_empty_stream() {
    let key = alice_bob_cipher_key();
    let pt: Vec<Fq> = vec![];
    let ct = encrypt(key, &pt);
    assert!(ct.is_empty());
    let back = decrypt(key, &ct);
    assert!(back.is_empty());
}

/// Vector 2: single zero element — exposes `keystream_0` directly.
#[test]
fn fixture_vector_2_single_zero() {
    let key = alice_bob_cipher_key();
    let pt = vec![Fq::from(0u64)];
    let ct = encrypt(key, &pt);
    assert_eq!(
        dec_vec(&ct),
        vec![
            "10787321779190226554676337514347691875659477298610453494316095697639731105524",
        ],
    );
    assert_eq!(decrypt(key, &ct), pt);
}

/// Vector 3: small structured stream `[1, 2, 3, 4]`.
#[test]
fn fixture_vector_3_small_stream() {
    let key = alice_bob_cipher_key();
    let pt: Vec<Fq> = vec![
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let ct = encrypt(key, &pt);
    assert_eq!(
        dec_vec(&ct),
        vec![
            "10787321779190226554676337514347691875659477298610453494316095697639731105525",
            "11005131623232030623906867189653141067415173065234117331769608574160093139922",
            "11791314040563090199526129580738560103220176213914809365331933459954108858858",
            "7865039964291077852173468667319105421171640084683400461629880408575490986497",
        ],
    );
    assert_eq!(decrypt(key, &ct), pt);
}

/// Vector 4: 9-element stream `[1..=9]`.
#[test]
fn fixture_vector_4_nine_element_stream() {
    let key = alice_bob_cipher_key();
    let pt: Vec<Fq> = (1u64..=9).map(Fq::from).collect();
    let ct = encrypt(key, &pt);
    assert_eq!(
        dec_vec(&ct),
        vec![
            "10787321779190226554676337514347691875659477298610453494316095697639731105525",
            "11005131623232030623906867189653141067415173065234117331769608574160093139922",
            "11791314040563090199526129580738560103220176213914809365331933459954108858858",
            "7865039964291077852173468667319105421171640084683400461629880408575490986497",
            "2229138201795589665836767366228584476563000856384984963522822284776068932630",
            "11702069139758725090303111831331195321446015655716158873298318997122786844126",
            "21827964982986497021603458608987397530066910094307594093465521210581113049125",
            "5740201568618975964672094667205897157857936348884108865070928080450242112246",
            "6187684344249448887322373286095556400810738367783748855733293931088165175507",
        ],
    );
    assert_eq!(decrypt(key, &ct), pt);
}

/// Vector 4's first four elements MUST match Vector 3's ciphertext
/// element-for-element — position-only keystream dependence.
#[test]
fn vector_4_prefix_matches_vector_3() {
    let key = alice_bob_cipher_key();
    let pt_short: Vec<Fq> = vec![
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let pt_long: Vec<Fq> = (1u64..=9).map(Fq::from).collect();
    let ct_short = encrypt(key, &pt_short);
    let ct_long = encrypt(key, &pt_long);
    assert_eq!(ct_short[..], ct_long[..4]);
}

/// Vector 5: same plaintext as Vector 3 under the MAC-role key.
/// Pins key-dependence.
#[test]
fn fixture_vector_5_same_plaintext_different_key() {
    let key = alice_bob_mac_key();
    let pt: Vec<Fq> = vec![
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let ct = encrypt(key, &pt);
    assert_eq!(
        dec_vec(&ct),
        vec![
            "16506928987906569383944781504684601770814262391889970105684093521341732525754",
            "7731186885346303069632096810963599601471099092800449051344926221212941321164",
            "16960104434118179033056841776385404401539280326058795617003206515921385327816",
            "9750714252119089106587215089218327748956786451850137551892779329943517333788",
        ],
    );
    assert_eq!(decrypt(key, &ct), pt);
}

/// Cross-construction: ciphertext under cipher-role key MUST differ
/// element-for-element from ciphertext under mac-role key on the
/// same plaintext.
#[test]
fn cipher_and_mac_key_ciphertexts_diverge() {
    let pt: Vec<Fq> = vec![
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
    ];
    let ct_enc = encrypt(alice_bob_cipher_key(), &pt);
    let ct_mac = encrypt(alice_bob_mac_key(), &pt);
    for (a, b) in ct_enc.iter().zip(ct_mac.iter()) {
        assert_ne!(a, b);
    }
}
