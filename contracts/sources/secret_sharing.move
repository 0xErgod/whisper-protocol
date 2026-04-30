#[allow(unused_mut_parameter)]
module secret_sharing_poc::secret_sharing;

use sui::clock::{Self, Clock};
use sui::event;

const E_EMPTY_FIELD: u64 = 0;
const E_TOO_LARGE: u64 = 1;

const MAX_SCHEME_BYTES: u64 = 64;
const MAX_SCHEMA_BYTES: u64 = 64;
const MAX_PUBLIC_KEY_BYTES: u64 = 128;
const MAX_EPHEMERAL_KEY_BYTES: u64 = 128;
const MAX_WRAPPED_KEY_BYTES: u64 = 512;
const MAX_NONCE_BYTES: u64 = 64;
const MAX_CIPHERTEXT_BYTES: u64 = 4096;
const MAX_PUBLIC_NOTE_BYTES: u64 = 1024;

public struct EncryptionKeyRegistered has copy, drop {
    game_id: ID,
    player: address,
    signing_scheme: vector<u8>,
    signing_pubkey: vector<u8>,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    created_at_ms: u64,
}

public struct EncryptedEnvelope has key, store {
    id: UID,
    game_id: ID,
    sender: address,
    recipient_hint: address,
    schema: vector<u8>,
    key_version_hint: u64,
    eph_pubkey: vector<u8>,
    wrapped_key: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    created_at_ms: u64,
}

public struct EnvelopePosted has copy, drop {
    envelope_id: ID,
    game_id: ID,
    sender: address,
    recipient_hint: address,
    schema: vector<u8>,
    key_version_hint: u64,
    created_at_ms: u64,
}

public struct PublicNote has key, store {
    id: UID,
    game_id: ID,
    sender: address,
    text: vector<u8>,
    created_at_ms: u64,
}

public struct PublicNotePosted has copy, drop {
    note_id: ID,
    game_id: ID,
    sender: address,
    created_at_ms: u64,
}

entry fun register_encryption_key(
    game_id: ID,
    signing_scheme: vector<u8>,
    signing_pubkey: vector<u8>,
    encryption_scheme: vector<u8>,
    encryption_pubkey: vector<u8>,
    key_version: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&signing_scheme, MAX_SCHEME_BYTES);
    assert_non_empty_and_max(&signing_pubkey, MAX_PUBLIC_KEY_BYTES);
    assert_non_empty_and_max(&encryption_scheme, MAX_SCHEME_BYTES);
    assert_non_empty_and_max(&encryption_pubkey, MAX_PUBLIC_KEY_BYTES);

    event::emit(EncryptionKeyRegistered {
        game_id,
        player: tx_context::sender(ctx),
        signing_scheme,
        signing_pubkey,
        encryption_scheme,
        encryption_pubkey,
        key_version,
        created_at_ms: clock::timestamp_ms(clock),
    });
}

entry fun post_envelope(
    game_id: ID,
    recipient_hint: address,
    schema: vector<u8>,
    key_version_hint: u64,
    eph_pubkey: vector<u8>,
    wrapped_key: vector<u8>,
    nonce: vector<u8>,
    ciphertext: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&schema, MAX_SCHEMA_BYTES);
    assert_non_empty_and_max(&eph_pubkey, MAX_EPHEMERAL_KEY_BYTES);
    assert_non_empty_and_max(&wrapped_key, MAX_WRAPPED_KEY_BYTES);
    assert_non_empty_and_max(&nonce, MAX_NONCE_BYTES);
    assert_non_empty_and_max(&ciphertext, MAX_CIPHERTEXT_BYTES);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let envelope = EncryptedEnvelope {
        id: object::new(ctx),
        game_id,
        sender,
        recipient_hint,
        schema,
        key_version_hint,
        eph_pubkey,
        wrapped_key,
        nonce,
        ciphertext,
        created_at_ms,
    };
    let envelope_id = object::id(&envelope);

    event::emit(EnvelopePosted {
        envelope_id,
        game_id,
        sender,
        recipient_hint,
        schema: envelope.schema,
        key_version_hint,
        created_at_ms,
    });

    transfer::public_transfer(envelope, recipient_hint);
}

entry fun post_public_note(
    game_id: ID,
    text: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert_non_empty_and_max(&text, MAX_PUBLIC_NOTE_BYTES);

    let sender = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);
    let note = PublicNote {
        id: object::new(ctx),
        game_id,
        sender,
        text,
        created_at_ms,
    };
    let note_id = object::id(&note);

    event::emit(PublicNotePosted {
        note_id,
        game_id,
        sender,
        created_at_ms,
    });

    transfer::public_transfer(note, sender);
}

fun assert_non_empty_and_max(bytes: &vector<u8>, max: u64) {
    let len = bytes.length();
    assert!(len > 0, E_EMPTY_FIELD);
    assert!(len <= max, E_TOO_LARGE);
}
