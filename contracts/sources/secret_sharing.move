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
const E_RECIPIENT_ARITY_MISMATCH: u64 = 7;
const E_DUPLICATE_RECIPIENT: u64 = 8;

// Wire-protocol version. Bump on any change that breaks write
// compatibility (entry-point shape, event field additions/renames,
// envelope layout changes). Historical envelope reads are versioned at
// the envelope level; this deployment-wide version is only for deciding
// whether a client can safely write its current format.
const PROTOCOL_VERSION: u32 = 3;
const CURRENT_ENVELOPE_FORMAT_VERSION: u16 = 2;
const CURRENT_MULTI_ENVELOPE_FORMAT_VERSION: u16 = 3;

const MAX_SCHEME_BYTES: u64 = 128;
const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_CONTEXT_BYTES: u64 = 64;
const MAX_PUBLIC_KEY_BYTES: u64 = 128;
const MAX_EPHEMERAL_KEY_BYTES: u64 = 128;
const MAX_NONCE_BYTES: u64 = 64;
const MAX_CIPHERTEXT_BYTES: u64 = 4096;
const MAX_RECIPIENTS: u64 = 8;
const MAX_WRAPPED_KEY_BYTES: u64 = 256;

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

public fun current_multi_envelope_format_version(): u16 { CURRENT_MULTI_ENVELOPE_FORMAT_VERSION }

public fun max_recipients(): u64 { MAX_RECIPIENTS }

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

// === Multi-recipient envelopes (1:N transport) ===

public struct MultiRecipientEnvelope has key, store {
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

public struct MultiEnvelopePosted has copy, drop {
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

entry fun post_multi_envelope(
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
    assert!(format_version == CURRENT_MULTI_ENVELOPE_FORMAT_VERSION, E_UNSUPPORTED_FORMAT_VERSION);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let (envelope, posted) = build_multi_envelope_v3(
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

fun build_multi_envelope_v3(
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
): (MultiRecipientEnvelope, MultiEnvelopePosted) {
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

        assert!(registry.entries.contains(recipient), E_RECIPIENT_NOT_REGISTERED);
        let entry = registry.entries.borrow(recipient);
        assert!(entry.key_version == claimed_key_version, E_STALE_KEY_VERSION);
        assert!(entry.current_key_id == claimed_key_id, E_STALE_KEY_REFERENCE);
        // Note: we deliberately do NOT assert
        // entry.encryption_scheme == encryption_scheme here. v3 multi-wrap
        // envelopes layer hybrid encryption on top of the recipient's
        // existing X25519 KEM keypair, so the registered suite (e.g.
        // "x25519-...+chacha20poly1305") and the envelope suite (e.g.
        // "x25519-...+chacha20poly1305+multi-wrap-v1") legitimately differ.
        // KEM-compatibility is enforced client-side by the suite registry.

        // Reject duplicate recipients in the same envelope. The check is
        // O(n^2) but bounded by MAX_RECIPIENTS so worst-case work is small.
        let mut j = 0;
        while (j < i) {
            assert!(*recipients.borrow(j) != recipient, E_DUPLICATE_RECIPIENT);
            j = j + 1;
        };

        assert_non_empty_and_max(wrapped_keys.borrow(i), MAX_WRAPPED_KEY_BYTES);
        assert_non_empty_and_max(wrap_nonces.borrow(i), MAX_NONCE_BYTES);

        i = i + 1;
    };

    let envelope = MultiRecipientEnvelope {
        id: object::new(ctx),
        format_version: CURRENT_MULTI_ENVELOPE_FORMAT_VERSION,
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
    let posted = MultiEnvelopePosted {
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

#[test]
fun build_v3_multi_envelope_carries_all_recipients() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let bob_key = register_encryption_key_impl(
        &mut registry,
        @0xB,
        b"x25519",
        b"pubkey-bob",
        10,
        ctx,
    );
    let charlie_key = register_encryption_key_impl(
        &mut registry,
        @0xC,
        b"x25519",
        b"pubkey-charlie",
        10,
        ctx,
    );
    let bob_key_id = object::id(&bob_key);
    let charlie_key_id = object::id(&charlie_key);

    let (envelope, posted) = build_multi_envelope_v3(
        &registry,
        @0xA,
        vector[@0xB, @0xC],
        vector[bob_key_id, charlie_key_id],
        vector[1, 1],
        b"ctx",
        b"schema",
        b"x25519",
        b"eph",
        b"payload-nonce",
        b"payload-ct",
        vector[b"wrapped-bob", b"wrapped-charlie"],
        vector[b"wrap-nonce-bob", b"wrap-nonce-charlie"],
        55,
        ctx,
    );

    assert!(envelope.format_version == CURRENT_MULTI_ENVELOPE_FORMAT_VERSION, 200);
    assert!(envelope.recipients.length() == 2, 201);
    assert!(*envelope.recipients.borrow(0) == @0xB, 202);
    assert!(*envelope.recipients.borrow(1) == @0xC, 203);
    assert!(*envelope.recipient_key_ids.borrow(0) == bob_key_id, 204);
    assert!(*envelope.recipient_key_ids.borrow(1) == charlie_key_id, 205);
    assert!(envelope.wrapped_keys.length() == 2, 206);
    assert!(posted.recipients.length() == 2, 207);
    assert!(posted.format_version == envelope.format_version, 208);

    transfer::public_transfer(bob_key, @0xB);
    transfer::public_transfer(charlie_key, @0xC);
    transfer::freeze_object(envelope);
    transfer::public_transfer(registry, @0xA);
}

#[test, expected_failure(abort_code = E_RECIPIENT_ARITY_MISMATCH)]
fun v3_arity_mismatch_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let bob_key = register_encryption_key_impl(
        &mut registry,
        @0xB,
        b"x25519",
        b"pubkey-bob",
        10,
        ctx,
    );
    let bob_key_id = object::id(&bob_key);

    // 2 recipients but only 1 wrapped key
    let (envelope, _posted) = build_multi_envelope_v3(
        &registry,
        @0xA,
        vector[@0xB, @0xB],
        vector[bob_key_id, bob_key_id],
        vector[1, 1],
        b"ctx",
        b"schema",
        b"x25519",
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
fun v3_duplicate_recipients_are_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let bob_key = register_encryption_key_impl(
        &mut registry,
        @0xB,
        b"x25519",
        b"pubkey-bob",
        10,
        ctx,
    );
    let bob_key_id = object::id(&bob_key);

    let (envelope, _posted) = build_multi_envelope_v3(
        &registry,
        @0xA,
        vector[@0xB, @0xB],
        vector[bob_key_id, bob_key_id],
        vector[1, 1],
        b"ctx",
        b"schema",
        b"x25519",
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
fun v3_too_many_recipients_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    // Register 9 distinct accounts (one over MAX_RECIPIENTS=8)
    let r0 = register_encryption_key_impl(&mut registry, @0xB0, b"x25519", b"pk-0", 10, ctx);
    let r1 = register_encryption_key_impl(&mut registry, @0xB1, b"x25519", b"pk-1", 10, ctx);
    let r2 = register_encryption_key_impl(&mut registry, @0xB2, b"x25519", b"pk-2", 10, ctx);
    let r3 = register_encryption_key_impl(&mut registry, @0xB3, b"x25519", b"pk-3", 10, ctx);
    let r4 = register_encryption_key_impl(&mut registry, @0xB4, b"x25519", b"pk-4", 10, ctx);
    let r5 = register_encryption_key_impl(&mut registry, @0xB5, b"x25519", b"pk-5", 10, ctx);
    let r6 = register_encryption_key_impl(&mut registry, @0xB6, b"x25519", b"pk-6", 10, ctx);
    let r7 = register_encryption_key_impl(&mut registry, @0xB7, b"x25519", b"pk-7", 10, ctx);
    let r8 = register_encryption_key_impl(&mut registry, @0xB8, b"x25519", b"pk-8", 10, ctx);

    let (envelope, _posted) = build_multi_envelope_v3(
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
        b"x25519",
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
fun v3_stale_recipient_key_ref_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut registry = KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    };
    let bob_v1 = register_encryption_key_impl(&mut registry, @0xB, b"x25519", b"pk-bob-1", 10, ctx);
    let bob_v2 = register_encryption_key_impl(&mut registry, @0xB, b"x25519", b"pk-bob-2", 20, ctx);
    let stale_id = object::id(&bob_v1);

    let (envelope, _posted) = build_multi_envelope_v3(
        &registry,
        @0xA,
        vector[@0xB],
        vector[stale_id],
        vector[2],
        b"ctx",
        b"schema",
        b"x25519",
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
