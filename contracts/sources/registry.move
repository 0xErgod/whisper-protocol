/// Public-key registry. Each Sui account that wants to receive
/// encrypted envelopes registers a Baby Jubjub public key here.
/// Envelopes reference the registry to assert that the sender
/// targeted the recipient's current key.
///
/// The on-chain `KeyRegistry` is a shared object created in `init`.
/// Each registration also mints an immutable `EncryptionKey` object
/// transferred to the registrant — that gives historical envelopes a
/// stable key reference even after the account rotates.
///
/// A Baby Jubjub public key is two BN254-base-field coordinates
/// (`pubkey_x`, `pubkey_y`), stored as `u256`. The wire shape and
/// validity discipline are pinned in
/// [`specs/babyjub-curve.md`](../../specs/babyjub-curve.md). The
/// registry does NOT verify on-curve / prime-subgroup membership
/// on chain — those checks happen client-side at registration time
/// (and inside any ZK circuit that consumes the key), since the
/// arithmetic isn't cheap in Move. A malformed key would just fail
/// to participate in a working envelope flow.
module whisper_protocol::registry;

use sui::clock::{Self, Clock};
use sui::event;
use sui::table::{Self, Table};

const E_RECIPIENT_NOT_REGISTERED: u64 = 2;

public struct KeyRegistry has key, store {
    id: UID,
    entries: Table<address, KeyEntry>,
}

public struct KeyEntry has store {
    pubkey_x: u256,
    pubkey_y: u256,
    current_key_id: ID,
    key_version: u64,
    rotated_at_ms: u64,
}

public struct EncryptionKey has key, store {
    id: UID,
    account: address,
    pubkey_x: u256,
    pubkey_y: u256,
    key_version: u64,
    rotated_at_ms: u64,
}

public struct EncryptionKeyRegistered has copy, drop {
    key_id: ID,
    account: address,
    pubkey_x: u256,
    pubkey_y: u256,
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
    pubkey_x: u256,
    pubkey_y: u256,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let account = tx_context::sender(ctx);
    let now = clock::timestamp_ms(clock);
    let key = register_encryption_key_impl(
        registry,
        account,
        pubkey_x,
        pubkey_y,
        now,
        ctx,
    );
    let key_id = object::id(&key);
    let key_version = key.key_version;

    event::emit(EncryptionKeyRegistered {
        key_id,
        account,
        pubkey_x,
        pubkey_y,
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

public fun pubkey_x_of(entry: &KeyEntry): u256 { entry.pubkey_x }

public fun pubkey_y_of(entry: &KeyEntry): u256 { entry.pubkey_y }

public fun current_key_id_of(entry: &KeyEntry): ID { entry.current_key_id }

#[test_only]
public(package) fun register_encryption_key_for_test(
    registry: &mut KeyRegistry,
    account: address,
    pubkey_x: u256,
    pubkey_y: u256,
    rotated_at_ms: u64,
    ctx: &mut TxContext,
): EncryptionKey {
    register_encryption_key_impl(
        registry,
        account,
        pubkey_x,
        pubkey_y,
        rotated_at_ms,
        ctx,
    )
}

fun register_encryption_key_impl(
    registry: &mut KeyRegistry,
    account: address,
    pubkey_x: u256,
    pubkey_y: u256,
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
        pubkey_x,
        pubkey_y,
        key_version: next_version,
        rotated_at_ms,
    };
    let key_id = object::id(&key);

    if (registry.entries.contains(account)) {
        let existing = registry.entries.borrow_mut(account);
        existing.pubkey_x = pubkey_x;
        existing.pubkey_y = pubkey_y;
        existing.current_key_id = key_id;
        existing.key_version = next_version;
        existing.rotated_at_ms = rotated_at_ms;
    } else {
        registry.entries.add(account, KeyEntry {
            pubkey_x,
            pubkey_y,
            current_key_id: key_id,
            key_version: next_version,
            rotated_at_ms,
        });
    };

    key
}

#[test]
fun register_first_key_creates_current_key_entry() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let account = @0xA;
    let key = register_encryption_key_impl(
        &mut registry,
        account,
        0x111,
        0x222,
        42,
        ctx,
    );
    let key_id = object::id(&key);
    let entry = current_key(&registry, account);

    assert!(entry.key_version == 1, 100);
    assert!(entry.current_key_id == key_id, 101);
    assert!(entry.pubkey_x == 0x111, 102);
    assert!(entry.pubkey_y == 0x222, 103);
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
        0x111,
        0x222,
        10,
        ctx,
    );
    let key_1_id = object::id(&key_1);

    let key_2 = register_encryption_key_impl(
        &mut registry,
        account,
        0x333,
        0x444,
        20,
        ctx,
    );
    let key_2_id = object::id(&key_2);
    let entry = current_key(&registry, account);

    assert!(entry.key_version == 2, 110);
    assert!(entry.current_key_id == key_2_id, 111);
    assert!(key_1_id != key_2_id, 112);
    assert!(entry.pubkey_x == 0x333, 113);
    assert!(entry.pubkey_y == 0x444, 114);

    transfer::public_transfer(key_1, account);
    transfer::public_transfer(key_2, account);
    transfer::public_transfer(registry, account);
}

#[test]
fun current_key_aborts_on_unregistered_address() {
    let ctx = &mut tx_context::dummy();
    let mut registry = new_registry(ctx);
    let key = register_encryption_key_impl(&mut registry, @0xA, 1, 2, 0, ctx);

    assert!(!has_entry(&registry, @0xB), 120);

    transfer::public_transfer(key, @0xA);
    transfer::public_transfer(registry, @0xA);
}
