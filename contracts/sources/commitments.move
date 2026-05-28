/// Public commit/open of payload-shaped secrets.
///
/// `commit_secret` posts a vector Pedersen commitment on chain
/// without revealing the underlying payload. The caller keeps
/// `(stream, blinding)` off chain. Later, `open_secret` reveals
/// both publicly via a `SecretOpened` event so anyone can verify
/// `commit(encoding_id || stream, blinding).point == (commitment_x, commitment_y)`.
///
/// The commitment construction is pinned in
/// [`specs/protocol-commitment.md`](../../specs/protocol-commitment.md):
/// a Baby Jubjub vector Pedersen commitment with the payload's
/// `encoding_id` committed at generator slot `G_0`, and the stream
/// elements at `G_1..G_n`. The encoding id is also stored as a
/// public field on the struct for fast off-chain decoder dispatch,
/// but its presence inside the commitment point is what makes it
/// cryptographically *bound* (not merely labelled).
///
/// On-chain opening verification is intentionally NOT done here —
/// this is the PoC pattern: cheaper gas, simpler contract, and
/// verification can be re-run independently by any reader given
/// the event payload. The future ZK-verified open (Phase 5,
/// `proofs.move`) will let a third party become convinced that
/// the prover knows an opening without the opening leaving their
/// machine.
///
/// Commitment objects are owned by the author. Sui ownership is
/// the authorization story for `open_secret` — only the author
/// can pass `&mut SecretCommitment` into the entry function.
/// Readers reconstruct state from `SecretCommitted` / `SecretOpened`
/// events.
module whisper_protocol::commitments;

use sui::clock::{Self, Clock};
use sui::event;

use whisper_protocol::proofs;

const E_ALREADY_OPENED: u64 = 100;
const E_EMPTY_STREAM: u64 = 101;

public struct SecretCommitment has key, store {
    id: UID,
    author: address,
    encoding_id: u256,
    commitment_x: u256,
    commitment_y: u256,
    created_at_ms: u64,
    opened: bool,
    opened_at_ms: u64,
}

public struct SecretCommitted has copy, drop {
    commitment_id: ID,
    author: address,
    encoding_id: u256,
    commitment_x: u256,
    commitment_y: u256,
    created_at_ms: u64,
}

public struct SecretOpened has copy, drop {
    commitment_id: ID,
    author: address,
    encoding_id: u256,
    commitment_x: u256,
    commitment_y: u256,
    stream: vector<u256>,
    blinding: u256,
    opened_at_ms: u64,
}

/// Emitted by `open_with_proof` when a Groth16 proof of partial
/// opening verifies. Unlike `SecretOpened`, this reveals only the
/// proven public value (`claimed_first_value` — the payload's
/// `stream[0]`); the rest of the stream and the blinding stay
/// private. The commitment object is NOT consumed or marked opened,
/// so partial-opening can be repeated (e.g. proving different
/// claims) and a later full `open_secret` is still possible.
public struct SecretPartialOpened has copy, drop {
    commitment_id: ID,
    author: address,
    encoding_id: u256,
    commitment_x: u256,
    commitment_y: u256,
    claimed_first_value: u256,
    opened_at_ms: u64,
}

public fun is_opened(c: &SecretCommitment): bool { c.opened }

public fun author_of(c: &SecretCommitment): address { c.author }

public fun encoding_id_of(c: &SecretCommitment): u256 { c.encoding_id }

public fun commitment_x_of(c: &SecretCommitment): u256 { c.commitment_x }

public fun commitment_y_of(c: &SecretCommitment): u256 { c.commitment_y }

entry fun commit_secret(
    encoding_id: u256,
    commitment_x: u256,
    commitment_y: u256,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let author = tx_context::sender(ctx);
    let created_at_ms = clock::timestamp_ms(clock);

    let obj = SecretCommitment {
        id: object::new(ctx),
        author,
        encoding_id,
        commitment_x,
        commitment_y,
        created_at_ms,
        opened: false,
        opened_at_ms: 0,
    };
    let commitment_id = object::id(&obj);

    event::emit(SecretCommitted {
        commitment_id,
        author,
        encoding_id,
        commitment_x,
        commitment_y,
        created_at_ms,
    });

    transfer::public_transfer(obj, author);
}

entry fun open_secret(
    commitment: &mut SecretCommitment,
    stream: vector<u256>,
    blinding: u256,
    clock: &Clock,
) {
    assert!(!commitment.opened, E_ALREADY_OPENED);
    // The native `crates/protocol::commitment` accepts an empty stream
    // (the "no content with hiding" degenerate case — commits to just
    // `blinding · H`). The on-chain commit path here doesn't refuse
    // those either: it stores whatever point the caller supplied. We
    // refuse to *open* with an empty stream, though, because an
    // empty-stream opening reveals nothing useful to a reader and is
    // almost always a client bug (forgot to pass the stream). If a
    // future use case wants empty-stream opens, drop this assert.
    assert!(stream.length() > 0, E_EMPTY_STREAM);

    let opened_at_ms = clock::timestamp_ms(clock);
    commitment.opened = true;
    commitment.opened_at_ms = opened_at_ms;

    event::emit(SecretOpened {
        commitment_id: object::id(commitment),
        author: commitment.author,
        encoding_id: commitment.encoding_id,
        commitment_x: commitment.commitment_x,
        commitment_y: commitment.commitment_y,
        stream,
        blinding,
        opened_at_ms,
    });
}

/// Verify a Groth16 proof that the prover knows an opening of this
/// commitment whose payload `stream[0]` equals `claimed_first_value`,
/// without revealing the rest of the opening.
///
/// The proof's public inputs are reconstructed from the commitment's
/// own on-chain fields (`commitment_x`, `commitment_y`, `encoding_id`)
/// plus the caller-supplied `claimed_first_value`. Because the point
/// coordinates come from the stored object — not from the caller —
/// a proof generated for a different commitment fails verification:
/// its public inputs won't match this object's point. That binding is
/// the whole security argument for the partial open.
///
/// Takes `&SecretCommitment` (shared read, no mutation): a partial
/// open neither consumes the commitment nor flips its `opened` flag.
/// It can be repeated for different claims, and a later full
/// `open_secret` is still possible. Because the commitment is an
/// owned object, only its owner (the author) can pass it here — the
/// proof is cryptographically self-authorizing, but Sui's object
/// model is the submission gate.
///
/// Aborts (via `proofs::verify_pedersen_opens_to`) if the proof does
/// not verify. On success, emits `SecretPartialOpened`.
entry fun open_with_proof(
    commitment: &SecretCommitment,
    claimed_first_value: u256,
    proof_bytes: vector<u8>,
    clock: &Clock,
) {
    proofs::verify_pedersen_opens_to(
        commitment.commitment_x,
        commitment.commitment_y,
        commitment.encoding_id,
        claimed_first_value,
        proof_bytes,
    );

    event::emit(SecretPartialOpened {
        commitment_id: object::id(commitment),
        author: commitment.author,
        encoding_id: commitment.encoding_id,
        commitment_x: commitment.commitment_x,
        commitment_y: commitment.commitment_y,
        claimed_first_value,
        opened_at_ms: clock::timestamp_ms(clock),
    });
}

#[test]
fun commit_creates_unopened_commitment() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 100);

    let author = @0xA;
    let obj = SecretCommitment {
        id: object::new(ctx),
        author,
        encoding_id: 0xAAAA,
        commitment_x: 0x1111,
        commitment_y: 0x2222,
        created_at_ms: 100,
        opened: false,
        opened_at_ms: 0,
    };

    assert!(!obj.opened, 300);
    assert!(obj.author == author, 301);
    assert!(obj.encoding_id == 0xAAAA, 302);
    assert!(obj.commitment_x == 0x1111, 303);
    assert!(obj.commitment_y == 0x2222, 304);

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
        author,
        encoding_id: 0xAAAA,
        commitment_x: 0x1111,
        commitment_y: 0x2222,
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    clock::set_for_testing(&mut clock, 200);
    open_secret(&mut obj, vector[1, 2, 3], 0xBEEF, &clock);

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
        author,
        encoding_id: 0xAAAA,
        commitment_x: 0x1111,
        commitment_y: 0x2222,
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    open_secret(&mut obj, vector[1, 2, 3], 0xAAA, &clock);
    open_secret(&mut obj, vector[4, 5, 6], 0xBBB, &clock);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}

#[test, expected_failure(abort_code = E_EMPTY_STREAM)]
fun open_with_empty_stream_is_rejected() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 50);
    let author = @0xA;

    let mut obj = SecretCommitment {
        id: object::new(ctx),
        author,
        encoding_id: 0xAAAA,
        commitment_x: 0x1111,
        commitment_y: 0x2222,
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    open_secret(&mut obj, vector[], 0xBEEF, &clock);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}

#[test_only]
fun zero_bytes(n: u64): vector<u8> {
    let mut v = vector[];
    let mut i = 0;
    while (i < n) {
        v.push_back(0);
        i = i + 1;
    };
    v
}

// A garbage proof (128 zero bytes — the compressed-Groth16-proof
// length) does not verify, so `open_with_proof` aborts inside
// `proofs::verify_pedersen_opens_to` with that module's
// `E_INVALID_PROOF` (200). The happy path needs a real proof from
// the off-chain prover and is covered by the end-to-end flow, per
// the behavior-only Move-test discipline.
#[test, expected_failure(abort_code = whisper_protocol::proofs::E_INVALID_PROOF)]
fun open_with_proof_rejects_garbage_proof() {
    let ctx = &mut tx_context::dummy();
    let mut clock = clock::create_for_testing(ctx);
    clock::set_for_testing(&mut clock, 50);
    let author = @0xA;

    let obj = SecretCommitment {
        id: object::new(ctx),
        author,
        encoding_id: 0xAAAA,
        commitment_x: 0x1111,
        commitment_y: 0x2222,
        created_at_ms: 50,
        opened: false,
        opened_at_ms: 0,
    };

    open_with_proof(&obj, 0x7, zero_bytes(128), &clock);

    transfer::public_transfer(obj, author);
    clock::destroy_for_testing(clock);
}
