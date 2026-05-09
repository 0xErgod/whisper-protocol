/// Single-recipient encrypted envelopes (`format_version = 2`).
///
/// One ciphertext, one recipient, one ephemeral pubkey, one nonce.
/// The envelope is transferred to the recipient as an owned object;
/// inbox discovery uses `getOwnedObjects` filtered by struct type.
///
/// Per-recipient binding is enforced on chain: the registered
/// `current_key_id` and `key_version` must match exactly, and the
/// envelope's declared `encryption_scheme` must match what the recipient
/// has on file in the registry.
module secret_sharing_poc::envelopes;

use sui::clock::{Self, Clock};
use sui::event;

use secret_sharing_poc::registry::{Self, KeyRegistry};

const E_EMPTY_FIELD: u64 = 0;
const E_TOO_LARGE: u64 = 1;
const E_RECIPIENT_NOT_REGISTERED: u64 = 2;
const E_STALE_KEY_VERSION: u64 = 3;
const E_UNSUPPORTED_FORMAT_VERSION: u64 = 4;
const E_STALE_KEY_REFERENCE: u64 = 5;
const E_SCHEME_MISMATCH: u64 = 6;

const CURRENT_ENVELOPE_FORMAT_VERSION: u16 = 2;

const MAX_SCHEME_BYTES: u64 = 128;
const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_CONTEXT_BYTES: u64 = 64;
const MAX_EPHEMERAL_KEY_BYTES: u64 = 128;
const MAX_NONCE_BYTES: u64 = 64;
const MAX_CIPHERTEXT_BYTES: u64 = 4096;

public struct EncryptedEnvelope has key, store {
    id: UID,
    format_version: u16,
    sender: address,
    recipient: address,
    recipient_key_id: ID,
    context: vector<u8>,
    schema: vector<u8>,
    encryption_scheme: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
}

public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    format_version: u16,
    sender: address,
    recipient: address,
    recipient_key_id: ID,
    context: vector<u8>,
    schema: vector<u8>,
    encryption_scheme: vector<u8>,
    key_version: u64,
    created_at_ms: u64,
}

public fun current_envelope_format_version(): u16 { CURRENT_ENVELOPE_FORMAT_VERSION }

entry fun post_envelope(
    registry: &KeyRegistry,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    format_version: u16,
    recipient_key_id: ID,
    encryption_scheme: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(format_version == CURRENT_ENVELOPE_FORMAT_VERSION, E_UNSUPPORTED_FORMAT_VERSION);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let (envelope, posted) = build_envelope_v2(
        registry,
        sender,
        recipient,
        recipient_key_id,
        context,
        schema,
        encryption_scheme,
        key_version,
        eph_pubkey,
        nonce,
        ciphertext,
        created_at_ms,
        ctx,
    );

    event::emit(posted);
    transfer::public_transfer(envelope, recipient);
}

fun build_envelope_v2(
    registry: &KeyRegistry,
    sender: address,
    recipient: address,
    recipient_key_id: ID,
    context: vector<u8>,
    schema: vector<u8>,
    encryption_scheme: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
    ctx: &mut TxContext,
): (EncryptedEnvelope, EnvelopePosted) {
    assert_non_empty_and_max(&schema, MAX_SCHEMA_BYTES);
    assert_non_empty_and_max(&encryption_scheme, MAX_SCHEME_BYTES);
    assert_non_empty_and_max(&eph_pubkey, MAX_EPHEMERAL_KEY_BYTES);
    assert_non_empty_and_max(&nonce, MAX_NONCE_BYTES);
    assert_non_empty_and_max(&ciphertext, MAX_CIPHERTEXT_BYTES);
    assert!(context.length() <= MAX_CONTEXT_BYTES, E_TOO_LARGE);

    assert!(registry::has_entry(registry, recipient), E_RECIPIENT_NOT_REGISTERED);
    let entry = registry::current_key(registry, recipient);
    assert!(registry::key_version_of(entry) == key_version, E_STALE_KEY_VERSION);
    assert!(registry::current_key_id_of(entry) == recipient_key_id, E_STALE_KEY_REFERENCE);
    assert!(registry::encryption_scheme_of(entry) == &encryption_scheme, E_SCHEME_MISMATCH);

    let envelope = EncryptedEnvelope {
        id: object::new(ctx),
        format_version: CURRENT_ENVELOPE_FORMAT_VERSION,
        sender,
        recipient,
        recipient_key_id,
        context,
        schema,
        encryption_scheme,
        key_version,
        eph_pubkey,
        nonce,
        ciphertext,
        created_at_ms,
    };
    let envelope_id = object::id(&envelope);
    let posted = EnvelopePosted {
        envelope_id,
        format_version: envelope.format_version,
        sender,
        recipient,
        recipient_key_id: envelope.recipient_key_id,
        context: copy envelope.context,
        schema: copy envelope.schema,
        encryption_scheme: copy envelope.encryption_scheme,
        key_version,
        created_at_ms,
    };

    (envelope, posted)
}

fun assert_non_empty_and_max(bytes: &vector<u8>, max: u64) {
    let len = bytes.length();
    assert!(len > 0, E_EMPTY_FIELD);
    assert!(len <= max, E_TOO_LARGE);
}

#[test_only]
use secret_sharing_poc::registry::{new_registry, register_encryption_key_for_test};

#[test]
fun build_v2_envelope_carries_format_suite_and_key_anchor() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let sender = @0xA;
    let recipient = @0xB;
    let key = register_encryption_key_for_test(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_id = object::id(&key);
    let (envelope, posted) = build_envelope_v2(
        &registry,
        sender,
        recipient,
        key_id,
        b"ctx",
        b"schema",
        b"x25519",
        1,
        b"eph",
        b"nonce",
        b"ciphertext",
        55,
        ctx,
    );

    assert!(envelope.format_version == CURRENT_ENVELOPE_FORMAT_VERSION, 120);
    assert!(envelope.recipient_key_id == key_id, 121);
    assert!(envelope.encryption_scheme == b"x25519", 122);
    assert!(posted.format_version == envelope.format_version, 123);
    assert!(posted.recipient_key_id == envelope.recipient_key_id, 124);
    assert!(posted.encryption_scheme == envelope.encryption_scheme, 125);
    assert!(posted.key_version == envelope.key_version, 126);

    transfer::public_transfer(key, recipient);
    transfer::public_transfer(envelope, recipient);
    transfer::public_transfer(registry, sender);
}

#[test, expected_failure(abort_code = E_STALE_KEY_VERSION)]
fun stale_key_version_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let recipient = @0xB;
    let key = register_encryption_key_for_test(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_id = object::id(&key);

    let (envelope, _posted) = build_envelope_v2(
        &registry,
        @0xA,
        recipient,
        key_id,
        b"ctx",
        b"schema",
        b"x25519",
        99,
        b"eph",
        b"nonce",
        b"ciphertext",
        55,
        ctx,
    );

    transfer::public_transfer(key, recipient);
    transfer::public_transfer(envelope, recipient);
    transfer::public_transfer(registry, recipient);
}

#[test, expected_failure(abort_code = E_STALE_KEY_REFERENCE)]
fun stale_key_reference_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let recipient = @0xB;
    let key_1 = register_encryption_key_for_test(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_2 = register_encryption_key_for_test(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-2",
        20,
        ctx,
    );
    let stale_key_id = object::id(&key_1);
    let (envelope, _posted) = build_envelope_v2(
        &registry,
        @0xA,
        recipient,
        stale_key_id,
        b"ctx",
        b"schema",
        b"x25519",
        2,
        b"eph",
        b"nonce",
        b"ciphertext",
        55,
        ctx,
    );

    transfer::public_transfer(key_1, recipient);
    transfer::public_transfer(key_2, recipient);
    transfer::public_transfer(envelope, recipient);
    transfer::public_transfer(registry, recipient);
}

#[test, expected_failure(abort_code = E_UNSUPPORTED_FORMAT_VERSION)]
fun unsupported_format_version_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 10);
    let key = register_encryption_key_for_test(
        &mut registry,
        @0xB,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_id = object::id(&key);

    post_envelope(
        &registry,
        @0xB,
        b"ctx",
        b"schema",
        999,
        key_id,
        b"x25519",
        1,
        b"eph",
        b"nonce",
        b"ciphertext",
        &clock,
        ctx,
    );

    transfer::public_transfer(key, @0xB);
    clock::destroy_for_testing(clock);
    transfer::public_transfer(registry, @0xB);
}

#[test, expected_failure(abort_code = E_EMPTY_FIELD)]
fun missing_encryption_scheme_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let recipient = @0xB;
    let key = register_encryption_key_for_test(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_id = object::id(&key);

    let (envelope, _posted) = build_envelope_v2(
        &registry,
        @0xA,
        recipient,
        key_id,
        b"ctx",
        b"schema",
        b"",
        1,
        b"eph",
        b"nonce",
        b"ciphertext",
        55,
        ctx,
    );

    transfer::public_transfer(key, recipient);
    transfer::public_transfer(envelope, recipient);
    transfer::public_transfer(registry, recipient);
}

#[test, expected_failure(abort_code = E_TOO_LARGE)]
fun oversized_ciphertext_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let recipient = @0xB;
    let key = register_encryption_key_for_test(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_id = object::id(&key);
    let mut ciphertext = vector[];
    let mut i = 0;
    while (i <= MAX_CIPHERTEXT_BYTES) {
        ciphertext.push_back(0);
        i = i + 1;
    };

    let (envelope, _posted) = build_envelope_v2(
        &registry,
        @0xA,
        recipient,
        key_id,
        b"ctx",
        b"schema",
        b"x25519",
        1,
        b"eph",
        b"nonce",
        ciphertext,
        55,
        ctx,
    );

    transfer::public_transfer(key, recipient);
    transfer::public_transfer(envelope, recipient);
    transfer::public_transfer(registry, recipient);
}

#[test, expected_failure(abort_code = E_RECIPIENT_NOT_REGISTERED)]
fun missing_recipient_registration_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let dummy_key = register_encryption_key_for_test(
        &mut registry,
        @0xC,
        b"x25519",
        b"pubkey-9",
        10,
        ctx,
    );
    let dummy_key_id = object::id(&dummy_key);

    let (envelope, _posted) = build_envelope_v2(
        &registry,
        @0xA,
        @0xB,
        dummy_key_id,
        b"ctx",
        b"schema",
        b"x25519",
        1,
        b"eph",
        b"nonce",
        b"ciphertext",
        55,
        ctx,
    );

    transfer::public_transfer(dummy_key, @0xC);
    transfer::public_transfer(envelope, @0xB);
    transfer::public_transfer(registry, @0xC);
}
