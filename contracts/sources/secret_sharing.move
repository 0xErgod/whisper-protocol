#[allow(unused_mut_parameter)]
module secret_sharing_poc::secret_sharing;

use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};

const E_EMPTY_FIELD: u64 = 0;
const E_TOO_LARGE: u64 = 1;
const E_RECIPIENT_NOT_REGISTERED: u64 = 2;
const E_STALE_KEY_VERSION: u64 = 3;

// Wire-protocol version. Bump on any change that breaks SDK
// compatibility (event field additions/renames, function signature
// changes, derivation/AEAD parameter changes). The SDK reads this via
// `protocol_version()` on first use and refuses to talk to an
// unfamiliar registry.
const PROTOCOL_VERSION: u32 = 1;

const MAX_SCHEME_BYTES: u64 = 64;
const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_CONTEXT_BYTES: u64 = 64;
const MAX_PUBLIC_KEY_BYTES: u64 = 128;
const MAX_EPHEMERAL_KEY_BYTES: u64 = 128;
const MAX_NONCE_BYTES: u64 = 64;
const MAX_CIPHERTEXT_BYTES: u64 = 4096;
const MAX_PUBLIC_NOTE_BYTES: u64 = 1024;

// === Key registry ===

public struct KeyRegistry has key {
    id: UID,
    entries: Table<address, KeyEntry>,
}

public struct KeyEntry has store {
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    rotated_at_ms: u64,
}

public struct EncryptionKeyRegistered has copy, drop {
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

    let key_version = if (registry.entries.contains(account)) {
        let existing = registry.entries.borrow_mut(account);
        existing.key_version = existing.key_version + 1;
        existing.encryption_scheme = encryption_scheme;
        existing.encryption_pubkey = encryption_pubkey;
        existing.rotated_at_ms = now;
        existing.key_version
    } else {
        registry.entries.add(account, KeyEntry {
            encryption_scheme,
            encryption_pubkey,
            key_version: 1,
            rotated_at_ms: now,
        });
        1
    };

    let entry = registry.entries.borrow(account);
    event::emit(EncryptionKeyRegistered {
        account,
        encryption_scheme: entry.encryption_scheme,
        encryption_pubkey: entry.encryption_pubkey,
        key_version,
        rotated_at_ms: now,
    });
}

public fun protocol_version(): u32 { PROTOCOL_VERSION }

public fun current_key(registry: &KeyRegistry, who: address): &KeyEntry {
    assert!(registry.entries.contains(who), E_RECIPIENT_NOT_REGISTERED);
    registry.entries.borrow(who)
}

public fun key_version_of(entry: &KeyEntry): u64 { entry.key_version }

public fun encryption_pubkey_of(entry: &KeyEntry): &vector<u8> { &entry.encryption_pubkey }

public fun encryption_scheme_of(entry: &KeyEntry): &vector<u8> { &entry.encryption_scheme }

// === Encrypted envelopes (1:1 transport) ===

public struct EncryptedEnvelope has key, store {
    id: UID,
    sender: address,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
}

public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    sender: address,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    key_version: u64,
    created_at_ms: u64,
}

entry fun post_envelope(
    registry: &KeyRegistry,
    recipient: address,
    context: vector<u8>,
    schema: vector<u8>,
    key_version: u64,
    eph_pubkey: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&schema, MAX_SCHEMA_BYTES);
    assert_non_empty_and_max(&eph_pubkey, MAX_EPHEMERAL_KEY_BYTES);
    assert_non_empty_and_max(&nonce, MAX_NONCE_BYTES);
    assert_non_empty_and_max(&ciphertext, MAX_CIPHERTEXT_BYTES);
    assert!(context.length() <= MAX_CONTEXT_BYTES, E_TOO_LARGE);

    assert!(registry.entries.contains(recipient), E_RECIPIENT_NOT_REGISTERED);
    let entry = registry.entries.borrow(recipient);
    assert!(entry.key_version == key_version, E_STALE_KEY_VERSION);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let envelope = EncryptedEnvelope {
        id: object::new(ctx),
        sender,
        recipient,
        context,
        schema,
        key_version,
        eph_pubkey,
        nonce,
        ciphertext,
        created_at_ms,
    };
    let envelope_id = object::id(&envelope);

    event::emit(EnvelopePosted {
        envelope_id,
        sender,
        recipient,
        context: envelope.context,
        schema: envelope.schema,
        key_version,
        created_at_ms,
    });

    transfer::public_transfer(envelope, recipient);
}

entry fun delete_envelope(envelope: EncryptedEnvelope) {
    let EncryptedEnvelope {
        id,
        sender: _,
        recipient: _,
        context: _,
        schema: _,
        key_version: _,
        eph_pubkey: _,
        nonce: _,
        ciphertext: _,
        created_at_ms: _,
    } = envelope;
    object::delete(id);
}

// === Public notes (broadcast primitive; not part of transport core) ===

public struct PublicNote has key, store {
    id: UID,
    sender: address,
    context: vector<u8>,
    text: vector<u8>,
    created_at_ms: u64,
}

public struct PublicNotePosted has copy, drop {
    note_id: ID,
    sender: address,
    context: vector<u8>,
    created_at_ms: u64,
}

entry fun post_public_note(
    context: vector<u8>,
    text: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&text, MAX_PUBLIC_NOTE_BYTES);
    assert!(context.length() <= MAX_CONTEXT_BYTES, E_TOO_LARGE);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let note = PublicNote {
        id: object::new(ctx),
        sender,
        context,
        text,
        created_at_ms,
    };
    let note_id = object::id(&note);

    event::emit(PublicNotePosted {
        note_id,
        sender,
        context: note.context,
        created_at_ms,
    });

    transfer::public_transfer(note, sender);
}

fun assert_non_empty_and_max(bytes: &vector<u8>, max: u64) {
    let len = bytes.length();
    assert!(len > 0, E_EMPTY_FIELD);
    assert!(len <= max, E_TOO_LARGE);
}
