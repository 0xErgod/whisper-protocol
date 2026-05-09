#[allow(unused_mut_parameter)]
module secret_sharing_poc::secret_sharing;

use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};

const E_EMPTY_FIELD: u64 = 0;
const E_TOO_LARGE: u64 = 1;
const E_RECIPIENT_NOT_REGISTERED: u64 = 2;
const E_STALE_KEY_VERSION: u64 = 3;
const E_UNSUPPORTED_FORMAT_VERSION: u64 = 4;
const E_STALE_KEY_REFERENCE: u64 = 5;
const E_SCHEME_MISMATCH: u64 = 6;

// Wire-protocol version. Bump on any change that breaks write
// compatibility (entry-point shape, event field additions/renames,
// envelope layout changes). Historical envelope reads are versioned at
// the envelope level; this deployment-wide version is only for deciding
// whether a client can safely write its current format.
const PROTOCOL_VERSION: u32 = 2;
const CURRENT_ENVELOPE_FORMAT_VERSION: u16 = 2;

const MAX_SCHEME_BYTES: u64 = 64;
const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_CONTEXT_BYTES: u64 = 64;
const MAX_PUBLIC_KEY_BYTES: u64 = 128;
const MAX_EPHEMERAL_KEY_BYTES: u64 = 128;
const MAX_NONCE_BYTES: u64 = 64;
const MAX_CIPHERTEXT_BYTES: u64 = 4096;

// === Key registry ===

public struct KeyRegistry has key, store {
    id: UID,
    entries: Table<address, KeyEntry>,
}

public struct KeyEntry has store {
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    current_key_id: ID,
    key_version: u64,
    rotated_at_ms: u64,
}

public struct EncryptionKey has key, store {
    id: UID,
    account: address,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    rotated_at_ms: u64,
}

public struct EncryptionKeyRegistered has copy, drop {
    key_id: ID,
    account: address,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    rotated_at_ms: u64,
}

fun init(ctx: &mut TxContext) {
    let registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    transfer::share_object(registry);
}

entry fun register_encryption_key(
    registry: &mut KeyRegistry,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&encryption_scheme, MAX_SCHEME_BYTES);
    assert_non_empty_and_max(&encryption_pubkey, MAX_PUBLIC_KEY_BYTES);

    let account = tx_context::sender(ctx);
    let now = clock::timestamp_ms(clock);
    let key = register_encryption_key_impl(
        registry,
        account,
        encryption_scheme,
        encryption_pubkey,
        now,
        ctx,
    );
    let key_id = object::id(&key);
    let key_version = key.key_version;

    event::emit(EncryptionKeyRegistered {
        key_id,
        account,
        encryption_scheme: copy key.encryption_scheme,
        encryption_pubkey: copy key.encryption_pubkey,
        key_version,
        rotated_at_ms: now,
    });

    transfer::public_transfer(key, account);
}

public fun protocol_version(): u32 { PROTOCOL_VERSION }

public fun current_envelope_format_version(): u16 { CURRENT_ENVELOPE_FORMAT_VERSION }

public fun current_key(registry: &KeyRegistry, who: address): &KeyEntry {
    assert!(registry.entries.contains(who), E_RECIPIENT_NOT_REGISTERED);
    registry.entries.borrow(who)
}

public fun key_version_of(entry: &KeyEntry): u64 { entry.key_version }

public fun encryption_pubkey_of(entry: &KeyEntry): &vector<u8> { &entry.encryption_pubkey }

public fun encryption_scheme_of(entry: &KeyEntry): &vector<u8> { &entry.encryption_scheme }

public fun current_key_id_of(entry: &KeyEntry): ID { entry.current_key_id }

fun register_encryption_key_impl(
    registry: &mut KeyRegistry,
    account: address,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    rotated_at_ms: u64,
    ctx: &mut TxContext,
): EncryptionKey {
    let next_version = if (registry.entries.contains(account)) {
        registry.entries.borrow(account).key_version + 1
    } else {
        1
    };

    let key = EncryptionKey {
        id: object::new(ctx),
        account,
        encryption_scheme: copy encryption_scheme,
        encryption_pubkey: copy encryption_pubkey,
        key_version: next_version,
        rotated_at_ms,
    };
    let key_id = object::id(&key);

    if (registry.entries.contains(account)) {
        let existing = registry.entries.borrow_mut(account);
        existing.encryption_scheme = encryption_scheme;
        existing.encryption_pubkey = encryption_pubkey;
        existing.current_key_id = key_id;
        existing.key_version = next_version;
        existing.rotated_at_ms = rotated_at_ms;
    } else {
        registry.entries.add(account, KeyEntry {
            encryption_scheme,
            encryption_pubkey,
            current_key_id: key_id,
            key_version: next_version,
            rotated_at_ms,
        });
    };

    key
}

// === Encrypted envelopes (1:1 transport) ===

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

    assert!(registry.entries.contains(recipient), E_RECIPIENT_NOT_REGISTERED);
    let entry = registry.entries.borrow(recipient);
    assert!(entry.key_version == key_version, E_STALE_KEY_VERSION);
    assert!(entry.current_key_id == recipient_key_id, E_STALE_KEY_REFERENCE);
    assert!(entry.encryption_scheme == encryption_scheme, E_SCHEME_MISMATCH);

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

#[test]
fun register_first_key_creates_current_key_entry() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let account = @0xA;
    let key = register_encryption_key_impl(
        &mut registry,
        account,
        b"x25519",
        b"pubkey-1",
        42,
        ctx,
    );
    let key_id = object::id(&key);
    let entry = current_key(&registry, account);

    assert!(entry.key_version == 1, 100);
    assert!(entry.current_key_id == key_id, 101);
    assert!(entry.encryption_scheme == b"x25519", 102);
    assert!(entry.encryption_pubkey == b"pubkey-1", 103);
    assert!(key.key_version == 1, 104);

    transfer::public_transfer(key, account);
    transfer::public_transfer(registry, account);
}

#[test]
fun rotate_key_creates_new_key_object_and_updates_registry() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let account = @0xA;

    let key_1 = register_encryption_key_impl(
        &mut registry,
        account,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_1_id = object::id(&key_1);

    let key_2 = register_encryption_key_impl(
        &mut registry,
        account,
        b"x25519",
        b"pubkey-2",
        20,
        ctx,
    );
    let key_2_id = object::id(&key_2);
    let entry = current_key(&registry, account);

    assert!(entry.key_version == 2, 110);
    assert!(entry.current_key_id == key_2_id, 111);
    assert!(key_1_id != key_2_id, 112);
    assert!(entry.encryption_pubkey == b"pubkey-2", 113);

    transfer::public_transfer(key_1, account);
    transfer::public_transfer(key_2, account);
    transfer::public_transfer(registry, account);
}

#[test]
fun build_v2_envelope_carries_format_suite_and_key_anchor() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let sender = @0xA;
    let recipient = @0xB;
    let key = register_encryption_key_impl(
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
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let recipient = @0xB;
    let key = register_encryption_key_impl(
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
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let recipient = @0xB;
    let key_1 = register_encryption_key_impl(
        &mut registry,
        recipient,
        b"x25519",
        b"pubkey-1",
        10,
        ctx,
    );
    let key_2 = register_encryption_key_impl(
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
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 10);
    let key = register_encryption_key_impl(
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
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let recipient = @0xB;
    let key = register_encryption_key_impl(
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
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let recipient = @0xB;
    let key = register_encryption_key_impl(
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
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let dummy_key = register_encryption_key_impl(
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
