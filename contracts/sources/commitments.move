/// Public commit/open of text secrets.
///
/// `commit_secret` posts a salted hash of an encoded text secret on
/// chain without revealing the secret. The caller keeps `(secret, salt)`
/// off chain. Later, `open_secret` reveals both publicly via a
/// `SecretOpened` event so anyone can verify
/// `H(domain || encoded_secret || salt) == commitment.commitment`.
///
/// Hash verification is intentionally client-side. This is the spec's
/// PoC pattern: cheaper gas, simpler contract, and verification can be
/// re-run independently by any reader. A future iteration may add
/// on-chain hash assertion for game-enforced reveals.
///
/// Commitment objects are owned by the author. Sui ownership is the
/// authorization story for `open_secret` — only the author can pass
/// `&mut SecretCommitment` into the entry function. Readers reconstruct
/// state from `SecretCommitted` / `SecretOpened` events.
module secret_sharing_poc::commitments;

use sui::clock::{Self, Clock};
use sui::event;

const E_EMPTY_FIELD: u64 = 0;
const E_TOO_LARGE: u64 = 1;
const E_ALREADY_OPENED: u64 = 100;

const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_HASH_SCHEME_BYTES: u64 = 64;
const MAX_COMMITMENT_BYTES: u64 = 64;
const MAX_SECRET_BYTES: u64 = 4096;
const MAX_SALT_BYTES: u64 = 64;

const CURRENT_COMMITMENT_FORMAT_VERSION: u16 = 1;

public struct SecretCommitment has key, store {
    id: UID,
    format_version: u16,
    author: address,
    schema: vector<u8>,
    hash_scheme: vector<u8>,
    commitment: vector<u8>,
    created_at_ms: u64,
    opened: bool,
    opened_at_ms: u64,
}

public struct SecretCommitted has copy, drop {
    commitment_id: ID,
    format_version: u16,
    author: address,
    schema: vector<u8>,
    hash_scheme: vector<u8>,
    commitment: vector<u8>,
    created_at_ms: u64,
}

public struct SecretOpened has copy, drop {
    commitment_id: ID,
    author: address,
    schema: vector<u8>,
    hash_scheme: vector<u8>,
    commitment: vector<u8>,
    encoded_secret: vector<u8>,
    salt: vector<u8>,
    opened_at_ms: u64,
}

public fun current_commitment_format_version(): u16 { CURRENT_COMMITMENT_FORMAT_VERSION }

public fun is_opened(c: &SecretCommitment): bool { c.opened }

public fun author_of(c: &SecretCommitment): address { c.author }

public fun commitment_bytes_of(c: &SecretCommitment): &vector<u8> { &c.commitment }

public fun schema_of(c: &SecretCommitment): &vector<u8> { &c.schema }

entry fun commit_secret(
    schema: vector<u8>,
    hash_scheme: vector<u8>,
    commitment: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&schema, MAX_SCHEMA_BYTES);
    assert_non_empty_and_max(&hash_scheme, MAX_HASH_SCHEME_BYTES);
    assert_non_empty_and_max(&commitment, MAX_COMMITMENT_BYTES);

    let author = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);

    let obj = SecretCommitment {
        id: object::new(ctx),
        format_version: CURRENT_COMMITMENT_FORMAT_VERSION,
        author,
        schema: copy schema,
        hash_scheme: copy hash_scheme,
        commitment: copy commitment,
        created_at_ms,
        opened: false,
        opened_at_ms: 0,
    };
    let commitment_id = object::id(&obj);

    event::emit(SecretCommitted {
        commitment_id,
        format_version: CURRENT_COMMITMENT_FORMAT_VERSION,
        author,
        schema,
        hash_scheme,
        commitment,
        created_at_ms,
    });

    transfer::public_transfer(obj, author);
}

entry fun open_secret(
    commitment: &mut SecretCommitment,
    encoded_secret: vector<u8>,
    salt: vector<u8>,
    clock: &Clock,
) {
    assert!(!commitment.opened, E_ALREADY_OPENED);
    assert_non_empty_and_max(&encoded_secret, MAX_SECRET_BYTES);
    assert_non_empty_and_max(&salt, MAX_SALT_BYTES);

    let opened_at_ms = clock::timestamp_ms(clock);
    commitment.opened = true;
    commitment.opened_at_ms = opened_at_ms;

    event::emit(SecretOpened {
        commitment_id: object::id(commitment),
        author: commitment.author,
        schema: commitment.schema,
        hash_scheme: commitment.hash_scheme,
        commitment: commitment.commitment,
        encoded_secret,
        salt,
        opened_at_ms,
    });
}

fun assert_non_empty_and_max(bytes: &vector<u8>, max: u64) {
    let len = bytes.length();
    assert!(len > 0, E_EMPTY_FIELD);
    assert!(len <= max, E_TOO_LARGE);
}

#[test]
fun commit_creates_unopened_commitment() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 100);

    let author = @0xA;
    let obj = SecretCommitment {
        id: object::new(ctx),
        format_version: CURRENT_COMMITMENT_FORMAT_VERSION,
        author,
        schema: b"asset_location_v1",
        hash_scheme: b"blake2b-256",
        commitment: b"\x01\x02\x03\x04",
        created_at_ms: 100,
        opened: false,
        opened_at_ms: 0,
    };

    assert!(!obj.opened, 300);
    assert!(obj.author == author, 301);
    assert!(obj.format_version == CURRENT_COMMITMENT_FORMAT_VERSION, 302);
    assert!(obj.commitment == b"\x01\x02\x03\x04", 303);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}

#[test]
fun open_marks_opened_true_and_records_timestamp() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 50);
    let author = @0xA;

    let mut obj = SecretCommitment {
        id: object::new(ctx),
        format_version: CURRENT_COMMITMENT_FORMAT_VERSION,
        author,
        schema: b"asset_location_v1",
        hash_scheme: b"blake2b-256",
        commitment: b"\x01\x02\x03\x04",
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    clock::set_for_testing(&mut clock, 200);
    open_secret(&mut obj, b"asset_id=fortress-001;x=42;y=9", b"salt-bytes", &clock);

    assert!(obj.opened, 310);
    assert!(obj.opened_at_ms == 200, 311);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}

#[test, expected_failure(abort_code = E_ALREADY_OPENED)]
fun double_open_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 50);
    let author = @0xA;

    let mut obj = SecretCommitment {
        id: object::new(ctx),
        format_version: CURRENT_COMMITMENT_FORMAT_VERSION,
        author,
        schema: b"asset_location_v1",
        hash_scheme: b"blake2b-256",
        commitment: b"\x01\x02\x03\x04",
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    open_secret(&mut obj, b"first-open", b"salt-1", &clock);
    open_secret(&mut obj, b"second-open", b"salt-2", &clock);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}

#[test, expected_failure(abort_code = E_EMPTY_FIELD)]
fun open_with_empty_secret_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 50);
    let author = @0xA;

    let mut obj = SecretCommitment {
        id: object::new(ctx),
        format_version: CURRENT_COMMITMENT_FORMAT_VERSION,
        author,
        schema: b"asset_location_v1",
        hash_scheme: b"blake2b-256",
        commitment: b"\x01\x02",
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    open_secret(&mut obj, b"", b"salt", &clock);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}

#[test, expected_failure(abort_code = E_TOO_LARGE)]
fun commit_with_oversized_commitment_bytes_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 50);
    let mut bad_commitment = vector[];
    let mut i = 0;
    while (i <= MAX_COMMITMENT_BYTES) {
        bad_commitment.push_back(0);
        i = i + 1;
    };

    commit_secret(b"schema", b"blake2b-256", bad_commitment, &clock, ctx);

    clock::destroy_for_testing(clock);
}
