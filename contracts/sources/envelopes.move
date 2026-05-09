/// Unified encrypted envelopes.
///
/// One envelope shape, one lifecycle, one cryptographic construction
/// for both direct messages and group messages. The recipient list is
/// always a `vector<address>` of length 1..MAX_RECIPIENTS; N=1 is a
/// degenerate case of the same primitive, not a separate one.
///
/// The construction is hybrid every time:
/// - `K_msg` is a random message key generated client-side per
///   envelope.
/// - The plaintext is encrypted once under `K_msg` →
///   `(payload_nonce, ciphertext)`.
/// - For each recipient, `K_msg` is wrapped via X25519 ECDH + HKDF +
///   AEAD with a domain-separated salt, producing
///   `(wrapped_keys[i], wrap_nonces[i])`.
///
/// Lifecycle: every envelope is frozen on post. Frozen objects are
/// immutable, publicly readable, and don't pay the consensus
/// surcharge that shared objects do. Inbox discovery is event-driven
/// through `EnvelopePosted` (filter by recipient address client-side).
/// This is uniform across N=1 and N≥2 — no special-casing for
/// "direct messages stay owned" — which makes proof-layer reasoning
/// in future iterations strictly simpler.
///
/// Recipient binding is enforced on chain per recipient: the
/// registered `current_key_id` and `key_version` must match for each
/// listed recipient. We do NOT require literal string equality
/// between the registered single-recipient suite and the envelope's
/// hybrid suite identifier — KEM compatibility is enforced
/// client-side by the suite registry. Same rule we used for v3.
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
const E_RECIPIENT_ARITY_MISMATCH: u64 = 7;
const E_DUPLICATE_RECIPIENT: u64 = 8;

const CURRENT_ENVELOPE_FORMAT_VERSION: u16 = 5;

const MAX_SCHEME_BYTES: u64 = 128;
const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_CONTEXT_BYTES: u64 = 64;
const MAX_EPHEMERAL_KEY_BYTES: u64 = 128;
const MAX_NONCE_BYTES: u64 = 64;
const MAX_CIPHERTEXT_BYTES: u64 = 4096;
const MAX_RECIPIENTS: u64 = 8;
const MAX_WRAPPED_KEY_BYTES: u64 = 256;

public struct Envelope has key, store {
    id: UID,
    format_version: u16,
    sender: address,
    recipients: vector<address>,
    recipient_key_ids: vector<ID>,
    recipient_key_versions: vector<u64>,
    context: vector<u8>,
    schema: vector<u8>,
    encryption_scheme: vector<u8>,
    eph_pubkey: vector<u8>,
    payload_nonce: vector<u8>,
    ciphertext: vector<u8>,
    wrapped_keys: vector<vector<u8>>,
    wrap_nonces: vector<vector<u8>>,
    created_at_ms: u64,
}

public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    format_version: u16,
    sender: address,
    recipients: vector<address>,
    recipient_key_ids: vector<ID>,
    recipient_key_versions: vector<u64>,
    context: vector<u8>,
    schema: vector<u8>,
    encryption_scheme: vector<u8>,
    created_at_ms: u64,
}

public fun current_envelope_format_version(): u16 { CURRENT_ENVELOPE_FORMAT_VERSION }

public fun max_recipients(): u64 { MAX_RECIPIENTS }

entry fun post_envelope(
    registry: &KeyRegistry,
    recipients: vector<address>,
    recipient_key_ids: vector<ID>,
    recipient_key_versions: vector<u64>,
    context: vector<u8>,
    schema: vector<u8>,
    format_version: u16,
    encryption_scheme: vector<u8>,
    eph_pubkey: vector<u8>,
    payload_nonce: vector<u8>,
    ciphertext: vector<u8>,
    wrapped_keys: vector<vector<u8>>,
    wrap_nonces: vector<vector<u8>>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(format_version == CURRENT_ENVELOPE_FORMAT_VERSION, E_UNSUPPORTED_FORMAT_VERSION);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let (envelope, posted) = build_envelope_v5(
        registry,
        sender,
        recipients,
        recipient_key_ids,
        recipient_key_versions,
        context,
        schema,
        encryption_scheme,
        eph_pubkey,
        payload_nonce,
        ciphertext,
        wrapped_keys,
        wrap_nonces,
        created_at_ms,
        ctx,
    );

    event::emit(posted);
    transfer::freeze_object(envelope);
}

fun build_envelope_v5(
    registry: &KeyRegistry,
    sender: address,
    recipients: vector<address>,
    recipient_key_ids: vector<ID>,
    recipient_key_versions: vector<u64>,
    context: vector<u8>,
    schema: vector<u8>,
    encryption_scheme: vector<u8>,
    eph_pubkey: vector<u8>,
    payload_nonce: vector<u8>,
    ciphertext: vector<u8>,
    wrapped_keys: vector<vector<u8>>,
    wrap_nonces: vector<vector<u8>>,
    created_at_ms: u64,
    ctx: &mut TxContext,
): (Envelope, EnvelopePosted) {
    assert_non_empty_and_max(&schema, MAX_SCHEMA_BYTES);
    assert_non_empty_and_max(&encryption_scheme, MAX_SCHEME_BYTES);
    assert_non_empty_and_max(&eph_pubkey, MAX_EPHEMERAL_KEY_BYTES);
    assert_non_empty_and_max(&payload_nonce, MAX_NONCE_BYTES);
    assert_non_empty_and_max(&ciphertext, MAX_CIPHERTEXT_BYTES);
    assert!(context.length() <= MAX_CONTEXT_BYTES, E_TOO_LARGE);

    let n = recipients.length();
    assert!(n > 0, E_EMPTY_FIELD);
    assert!(n <= MAX_RECIPIENTS, E_TOO_LARGE);
    assert!(recipient_key_ids.length() == n, E_RECIPIENT_ARITY_MISMATCH);
    assert!(recipient_key_versions.length() == n, E_RECIPIENT_ARITY_MISMATCH);
    assert!(wrapped_keys.length() == n, E_RECIPIENT_ARITY_MISMATCH);
    assert!(wrap_nonces.length() == n, E_RECIPIENT_ARITY_MISMATCH);

    let mut i = 0;
    while (i < n) {
        let recipient = *recipients.borrow(i);
        let claimed_key_id = *recipient_key_ids.borrow(i);
        let claimed_key_version = *recipient_key_versions.borrow(i);

        assert!(registry::has_entry(registry, recipient), E_RECIPIENT_NOT_REGISTERED);
        let entry = registry::current_key(registry, recipient);
        assert!(registry::key_version_of(entry) == claimed_key_version, E_STALE_KEY_VERSION);
        assert!(registry::current_key_id_of(entry) == claimed_key_id, E_STALE_KEY_REFERENCE);

        // Reject duplicate recipients in the same envelope. O(n^2) but
        // bounded by MAX_RECIPIENTS so worst-case work is small.
        let mut j = 0;
        while (j < i) {
            assert!(*recipients.borrow(j) != recipient, E_DUPLICATE_RECIPIENT);
            j = j + 1;
        };

        assert_non_empty_and_max(wrapped_keys.borrow(i), MAX_WRAPPED_KEY_BYTES);
        assert_non_empty_and_max(wrap_nonces.borrow(i), MAX_NONCE_BYTES);

        i = i + 1;
    };

    let envelope = Envelope {
        id: object::new(ctx),
        format_version: CURRENT_ENVELOPE_FORMAT_VERSION,
        sender,
        recipients,
        recipient_key_ids,
        recipient_key_versions,
        context,
        schema,
        encryption_scheme,
        eph_pubkey,
        payload_nonce,
        ciphertext,
        wrapped_keys,
        wrap_nonces,
        created_at_ms,
    };
    let envelope_id = object::id(&envelope);
    let posted = EnvelopePosted {
        envelope_id,
        format_version: envelope.format_version,
        sender,
        recipients: copy envelope.recipients,
        recipient_key_ids: copy envelope.recipient_key_ids,
        recipient_key_versions: copy envelope.recipient_key_versions,
        context: copy envelope.context,
        schema: copy envelope.schema,
        encryption_scheme: copy envelope.encryption_scheme,
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
fun build_v5_envelope_n_equals_one_carries_all_fields() {
    // The N=1 case is a degenerate group; the on-chain shape is
    // identical to N>1 and uses the same hybrid construction.
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_key = register_encryption_key_for_test(
        &mut registry,
        @0xB,
        b"x25519",
        b"pubkey-bob",
        10,
        ctx,
    );
    let bob_key_id = object::id(&bob_key);

    let (envelope, posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB],
        vector[bob_key_id],
        vector[1],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-bob"],
        vector[b"wrap-nonce-bob"],
        55,
        ctx,
    );

    assert!(envelope.format_version == CURRENT_ENVELOPE_FORMAT_VERSION, 200);
    assert!(envelope.recipients.length() == 1, 201);
    assert!(*envelope.recipients.borrow(0) == @0xB, 202);
    assert!(envelope.wrapped_keys.length() == 1, 203);
    assert!(posted.recipients.length() == 1, 204);

    transfer::public_transfer(bob_key, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test]
fun build_v5_envelope_n_equals_two_carries_all_recipients() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_key = register_encryption_key_for_test(
        &mut registry, @0xB, b"x25519", b"pubkey-bob", 10, ctx,
    );
    let charlie_key = register_encryption_key_for_test(
        &mut registry, @0xC, b"x25519", b"pubkey-charlie", 10, ctx,
    );
    let bob_key_id = object::id(&bob_key);
    let charlie_key_id = object::id(&charlie_key);

    let (envelope, posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB, @0xC],
        vector[bob_key_id, charlie_key_id],
        vector[1, 1],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-bob", b"wrapped-charlie"],
        vector[b"wrap-nonce-bob", b"wrap-nonce-charlie"],
        55,
        ctx,
    );

    assert!(envelope.recipients.length() == 2, 210);
    assert!(envelope.wrapped_keys.length() == 2, 211);
    assert!(posted.format_version == envelope.format_version, 212);

    transfer::public_transfer(bob_key, @0xB);
    transfer::public_transfer(charlie_key, @0xC);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_RECIPIENT_ARITY_MISMATCH)]
fun v5_arity_mismatch_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_key = register_encryption_key_for_test(
        &mut registry, @0xB, b"x25519", b"pubkey-bob", 10, ctx,
    );
    let bob_key_id = object::id(&bob_key);

    let (envelope, _posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB, @0xB],
        vector[bob_key_id, bob_key_id],
        vector[1, 1],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-only-one"],
        vector[b"wrap-nonce-bob", b"wrap-nonce-bob"],
        55,
        ctx,
    );

    transfer::public_transfer(bob_key, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_DUPLICATE_RECIPIENT)]
fun v5_duplicate_recipients_are_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_key = register_encryption_key_for_test(
        &mut registry, @0xB, b"x25519", b"pubkey-bob", 10, ctx,
    );
    let bob_key_id = object::id(&bob_key);

    let (envelope, _posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB, @0xB],
        vector[bob_key_id, bob_key_id],
        vector[1, 1],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-bob-1", b"wrapped-bob-2"],
        vector[b"wrap-nonce-1", b"wrap-nonce-2"],
        55,
        ctx,
    );

    transfer::public_transfer(bob_key, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_TOO_LARGE)]
fun v5_too_many_recipients_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let r0 = register_encryption_key_for_test(&mut registry, @0xB0, b"x25519", b"pk-0", 10, ctx);
    let r1 = register_encryption_key_for_test(&mut registry, @0xB1, b"x25519", b"pk-1", 10, ctx);
    let r2 = register_encryption_key_for_test(&mut registry, @0xB2, b"x25519", b"pk-2", 10, ctx);
    let r3 = register_encryption_key_for_test(&mut registry, @0xB3, b"x25519", b"pk-3", 10, ctx);
    let r4 = register_encryption_key_for_test(&mut registry, @0xB4, b"x25519", b"pk-4", 10, ctx);
    let r5 = register_encryption_key_for_test(&mut registry, @0xB5, b"x25519", b"pk-5", 10, ctx);
    let r6 = register_encryption_key_for_test(&mut registry, @0xB6, b"x25519", b"pk-6", 10, ctx);
    let r7 = register_encryption_key_for_test(&mut registry, @0xB7, b"x25519", b"pk-7", 10, ctx);
    let r8 = register_encryption_key_for_test(&mut registry, @0xB8, b"x25519", b"pk-8", 10, ctx);

    let (envelope, _posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB0, @0xB1, @0xB2, @0xB3, @0xB4, @0xB5, @0xB6, @0xB7, @0xB8],
        vector[
            object::id(&r0), object::id(&r1), object::id(&r2),
            object::id(&r3), object::id(&r4), object::id(&r5),
            object::id(&r6), object::id(&r7), object::id(&r8),
        ],
        vector[1, 1, 1, 1, 1, 1, 1, 1, 1],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"w0", b"w1", b"w2", b"w3", b"w4", b"w5", b"w6", b"w7", b"w8"],
        vector[b"n0", b"n1", b"n2", b"n3", b"n4", b"n5", b"n6", b"n7", b"n8"],
        55,
        ctx,
    );

    transfer::public_transfer(r0, @0xB0);
    transfer::public_transfer(r1, @0xB1);
    transfer::public_transfer(r2, @0xB2);
    transfer::public_transfer(r3, @0xB3);
    transfer::public_transfer(r4, @0xB4);
    transfer::public_transfer(r5, @0xB5);
    transfer::public_transfer(r6, @0xB6);
    transfer::public_transfer(r7, @0xB7);
    transfer::public_transfer(r8, @0xB8);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_STALE_KEY_REFERENCE)]
fun v5_stale_recipient_key_ref_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_v1 = register_encryption_key_for_test(&mut registry, @0xB, b"x25519", b"pk-bob-1", 10, ctx);
    let bob_v2 = register_encryption_key_for_test(&mut registry, @0xB, b"x25519", b"pk-bob-2", 20, ctx);
    let stale_id = object::id(&bob_v1);

    let (envelope, _posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB],
        vector[stale_id],
        vector[2],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-bob"],
        vector[b"wrap-nonce-bob"],
        55,
        ctx,
    );

    transfer::public_transfer(bob_v1, @0xB);
    transfer::public_transfer(bob_v2, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_RECIPIENT_NOT_REGISTERED)]
fun v5_unregistered_recipient_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let dummy_key = register_encryption_key_for_test(
        &mut registry, @0xC, b"x25519", b"pubkey-9", 10, ctx,
    );
    let dummy_key_id = object::id(&dummy_key);

    let (envelope, _posted) = build_envelope_v5(
        &registry,
        @0xA,
        vector[@0xB],
        vector[dummy_key_id],
        vector[1],
        b"ctx",
        b"schema",
        b"x25519-unified",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-bob"],
        vector[b"wrap-nonce-bob"],
        55,
        ctx,
    );

    transfer::public_transfer(dummy_key, @0xC);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xC);
}
