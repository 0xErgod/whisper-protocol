/// Authenticated, confidential message envelope.
///
/// Single-recipient by design — the on-chain shape mirrors
/// [`crates/protocol::envelope::Envelope`](../../crates/protocol/src/envelope.rs)
/// and [`specs/protocol-envelope.md`](../../specs/protocol-envelope.md)
/// exactly: one sender public key, one recipient public key, one
/// MAC tag. Multi-recipient delivery is composed at the SDK layer
/// by posting N envelopes — each one a self-contained encrypt-then-
/// MAC bundle with its own ECDH-derived keys.
///
/// The cryptographic construction is Baby Jubjub ECDH + Poseidon
/// KDF + Poseidon stream cipher + Poseidon MAC. All field elements
/// are BN254 base-field values stored as `u256`. The chain does NOT
/// run the crypto — it stores the wire form, binds the recipient
/// to a registered key, and freezes the object for public read.
///
/// Lifecycle: every envelope is frozen on post. Frozen objects are
/// immutable, publicly readable, and don't pay the consensus
/// surcharge that shared objects do. Inbox discovery is event-
/// driven through `EnvelopePosted` (filter by `recipient` address
/// client-side).
///
/// Recipient binding: the chain enforces that the supplied
/// `recipient_key_id` matches the registry's current key id for
/// the recipient address, and `recipient_key_version` matches the
/// current version. Key rotation invalidates in-flight envelopes
/// targeted at the previous key — they cannot be posted, the
/// sender must re-encrypt against the new key. This is the same
/// freshness story the registry's `EncryptionKey` lifecycle has
/// always told.
module whisper_protocol::envelopes;

use sui::clock::{Self, Clock};
use sui::event;

use whisper_protocol::registry::{Self, KeyRegistry};

const E_EMPTY_CIPHERTEXT: u64 = 0;
const E_RECIPIENT_NOT_REGISTERED: u64 = 2;
const E_STALE_KEY_VERSION: u64 = 3;
const E_STALE_KEY_REFERENCE: u64 = 5;

public struct Envelope has key, store {
    id: UID,
    sender: address,
    recipient: address,
    recipient_key_id: ID,
    recipient_key_version: u64,
    sender_pk_x: u256,
    sender_pk_y: u256,
    recipient_pk_x: u256,
    recipient_pk_y: u256,
    envelope_id: u256,
    encoding_id: u256,
    ciphertext: vector<u256>,
    mac_tag: u256,
    created_at_ms: u64,
}

public struct EnvelopePosted has copy, drop {
    envelope_object_id: ID,
    sender: address,
    recipient: address,
    recipient_key_id: ID,
    recipient_key_version: u64,
    sender_pk_x: u256,
    sender_pk_y: u256,
    recipient_pk_x: u256,
    recipient_pk_y: u256,
    envelope_id: u256,
    encoding_id: u256,
    mac_tag: u256,
    created_at_ms: u64,
}

entry fun post_envelope(
    registry: &KeyRegistry,
    recipient: address,
    recipient_key_id: ID,
    recipient_key_version: u64,
    sender_pk_x: u256,
    sender_pk_y: u256,
    recipient_pk_x: u256,
    recipient_pk_y: u256,
    envelope_id: u256,
    encoding_id: u256,
    ciphertext: vector<u256>,
    mac_tag: u256,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let (envelope, posted) = build_envelope(
        registry,
        sender,
        recipient,
        recipient_key_id,
        recipient_key_version,
        sender_pk_x,
        sender_pk_y,
        recipient_pk_x,
        recipient_pk_y,
        envelope_id,
        encoding_id,
        ciphertext,
        mac_tag,
        created_at_ms,
        ctx,
    );

    event::emit(posted);
    transfer::freeze_object(envelope);
}

fun build_envelope(
    registry: &KeyRegistry,
    sender: address,
    recipient: address,
    recipient_key_id: ID,
    recipient_key_version: u64,
    sender_pk_x: u256,
    sender_pk_y: u256,
    recipient_pk_x: u256,
    recipient_pk_y: u256,
    envelope_id: u256,
    encoding_id: u256,
    ciphertext: vector<u256>,
    mac_tag: u256,
    created_at_ms: u64,
    ctx: &mut TxContext,
): (Envelope, EnvelopePosted) {
    assert!(ciphertext.length() > 0, E_EMPTY_CIPHERTEXT);

    assert!(registry::has_entry(registry, recipient), E_RECIPIENT_NOT_REGISTERED);
    let entry = registry::current_key(registry, recipient);
    assert!(registry::key_version_of(entry) == recipient_key_version, E_STALE_KEY_VERSION);
    assert!(registry::current_key_id_of(entry) == recipient_key_id, E_STALE_KEY_REFERENCE);

    let envelope = Envelope {
        id: object::new(ctx),
        sender,
        recipient,
        recipient_key_id,
        recipient_key_version,
        sender_pk_x,
        sender_pk_y,
        recipient_pk_x,
        recipient_pk_y,
        envelope_id,
        encoding_id,
        ciphertext,
        mac_tag,
        created_at_ms,
    };
    let envelope_object_id = object::id(&envelope);
    let posted = EnvelopePosted {
        envelope_object_id,
        sender,
        recipient,
        recipient_key_id,
        recipient_key_version,
        sender_pk_x,
        sender_pk_y,
        recipient_pk_x,
        recipient_pk_y,
        envelope_id,
        encoding_id,
        mac_tag,
        created_at_ms,
    };

    (envelope, posted)
}

#[test_only]
use whisper_protocol::registry::{new_registry, register_encryption_key_for_test};

#[test]
fun build_envelope_carries_all_fields() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_key = register_encryption_key_for_test(
        &mut registry,
        @0xB,
        0xB1,
        0xB2,
        10,
        ctx,
    );
    let bob_key_id = object::id(&bob_key);

    let (envelope, posted) = build_envelope(
        &registry,
        @0xA,
        @0xB,
        bob_key_id,
        1,
        0xA1, 0xA2,
        0xB1, 0xB2,
        0xE17,
        0xE1D,
        vector[0xC1, 0xC2, 0xC3],
        0x47AC,
        55,
        ctx,
    );

    assert!(envelope.sender == @0xA, 200);
    assert!(envelope.recipient == @0xB, 201);
    assert!(envelope.recipient_pk_x == 0xB1, 202);
    assert!(envelope.recipient_pk_y == 0xB2, 203);
    assert!(envelope.encoding_id == 0xE1D, 204);
    assert!(envelope.ciphertext.length() == 3, 205);
    assert!(envelope.mac_tag == 0x47AC, 206);
    assert!(posted.envelope_object_id == object::id(&envelope), 207);

    transfer::public_transfer(bob_key, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_EMPTY_CIPHERTEXT)]
fun empty_ciphertext_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_key = register_encryption_key_for_test(&mut registry, @0xB, 0xB1, 0xB2, 10, ctx);
    let bob_key_id = object::id(&bob_key);

    let (envelope, _posted) = build_envelope(
        &registry, @0xA, @0xB, bob_key_id, 1,
        0xA1, 0xA2, 0xB1, 0xB2,
        0xE17, 0xE1D,
        vector[],
        0x47AC, 55, ctx,
    );

    transfer::public_transfer(bob_key, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_RECIPIENT_NOT_REGISTERED)]
fun unregistered_recipient_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let unrelated_key = register_encryption_key_for_test(&mut registry, @0xC, 0xC1, 0xC2, 10, ctx);
    let unrelated_key_id = object::id(&unrelated_key);

    let (envelope, _posted) = build_envelope(
        &registry, @0xA, @0xB, unrelated_key_id, 1,
        0xA1, 0xA2, 0xB1, 0xB2,
        0xE17, 0xE1D,
        vector[0xC1],
        0x47AC, 55, ctx,
    );

    transfer::public_transfer(unrelated_key, @0xC);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xC);
}

#[test, expected_failure(abort_code = E_STALE_KEY_REFERENCE)]
fun stale_recipient_key_ref_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_v1 = register_encryption_key_for_test(&mut registry, @0xB, 0xB1, 0xB2, 10, ctx);
    let bob_v2 = register_encryption_key_for_test(&mut registry, @0xB, 0xB3, 0xB4, 20, ctx);
    let stale_id = object::id(&bob_v1);

    let (envelope, _posted) = build_envelope(
        &registry, @0xA, @0xB, stale_id, 2,
        0xA1, 0xA2, 0xB3, 0xB4,
        0xE17, 0xE1D,
        vector[0xC1],
        0x47AC, 55, ctx,
    );

    transfer::public_transfer(bob_v1, @0xB);
    transfer::public_transfer(bob_v2, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_STALE_KEY_VERSION)]
fun stale_recipient_key_version_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let bob_v1 = register_encryption_key_for_test(&mut registry, @0xB, 0xB1, 0xB2, 10, ctx);
    let bob_v2 = register_encryption_key_for_test(&mut registry, @0xB, 0xB3, 0xB4, 20, ctx);
    let current_key_id = object::id(&bob_v2);

    // Claims version 1 against current_key_id of v2 — version assertion fires
    // before the key_id assertion since version is checked first.
    let (envelope, _posted) = build_envelope(
        &registry, @0xA, @0xB, current_key_id, 1,
        0xA1, 0xA2, 0xB3, 0xB4,
        0xE17, 0xE1D,
        vector[0xC1],
        0x47AC, 55, ctx,
    );

    transfer::public_transfer(bob_v1, @0xB);
    transfer::public_transfer(bob_v2, @0xB);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}
