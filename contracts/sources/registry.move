/// Public-key registry. Each Sui account that wants to receive
/// encrypted envelopes registers an X25519 (or other suite) public key
/// here. Envelopes reference the registry to assert that the sender
/// targeted the recipient's current key.
///
/// The on-chain `KeyRegistry` is a shared object created in `init`.
/// Each registration also mints an immutable `EncryptionKey` object
/// transferred to the registrant — that gives historical envelopes a
/// stable key reference even after the account rotates.
module secret_sharing_poc::registry;

use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};

const E_EMPTY_FIELD: u64 = 0;
const E_TOO_LARGE: u64 = 1;
const E_RECIPIENT_NOT_REGISTERED: u64 = 2;

const MAX_SCHEME_BYTES: u64 = 128;
const MAX_PUBLIC_KEY_BYTES: u64 = 128;

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

/// Create the shared registry object. Called by the package's init
/// function so there is exactly one canonical KeyRegistry per
/// deployment.
public(package) fun new_registry(ctx: &mut TxContext): KeyRegistry {
    KeyRegistry {
        id: object::new(ctx),
        entries: table::new<address, KeyEntry>(ctx),
    }
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

public fun current_key(registry: &KeyRegistry, who: address): &KeyEntry {
    assert!(registry.entries.contains(who), E_RECIPIENT_NOT_REGISTERED);
    registry.entries.borrow(who)
}

public fun has_entry(registry: &KeyRegistry, who: address): bool {
    registry.entries.contains(who)
}

public fun key_version_of(entry: &KeyEntry): u64 { entry.key_version }

public fun encryption_pubkey_of(entry: &KeyEntry): &vector<u8> { &entry.encryption_pubkey }

public fun encryption_scheme_of(entry: &KeyEntry): &vector<u8> { &entry.encryption_scheme }

public fun current_key_id_of(entry: &KeyEntry): ID { entry.current_key_id }

#[test_only]
public(package) fun register_encryption_key_for_test(
    registry: &mut KeyRegistry,
    account: address,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    rotated_at_ms: u64,
    ctx: &mut TxContext,
): EncryptionKey {
    register_encryption_key_impl(
        registry,
        account,
        encryption_scheme,
        encryption_pubkey,
        rotated_at_ms,
        ctx,
    )
}

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

fun assert_non_empty_and_max(bytes: &vector<u8>, max: u64) {
    let len = bytes.length();
    assert!(len > 0, E_EMPTY_FIELD);
    assert!(len <= max, E_TOO_LARGE);
}

#[test]
fun register_first_key_creates_current_key_entry() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
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
    let mut registry = new_registry(ctx);
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
