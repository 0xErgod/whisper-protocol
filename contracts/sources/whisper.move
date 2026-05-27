/// Package facade.
///
/// Whisper Protocol on Sui is laid out as a small set of cooperating
/// modules:
///
/// - `registry`     — Baby Jubjub public-key registry +
///                    `register_encryption_key`
/// - `envelopes`    — single-recipient authenticated, confidential
///                    transport mirroring `crates/protocol::envelope`
/// - `commitments`  — vector Pedersen commit/open of payload-shaped
///                    secrets, with encoding-id binding
/// - `proofs`       — Groth16 verifier wrappers for the protocol's
///                    circuits, with hardcoded VK constants
///
/// This module owns the deployment-wide write-compatibility marker
/// (`protocol_version`) and the package's `init` function, which is
/// the single source of truth for the canonical shared `KeyRegistry`.
///
/// `protocol_version` is pinned at `1` for this package and is not
/// expected to change. A schema break does not bump it — schema
/// breaks publish a new package id instead. The field is kept as a
/// cheap defensive parsing aid for SDKs that want to assert "I am
/// talking to a package I understand" before writing.
module whisper_protocol::whisper;

use whisper_protocol::registry::{Self, KeyRegistry};

/// Wire-protocol version. Pinned at 1 for this package. A wire-break
/// (entry-point shape, struct field additions) lands as a new
/// published package, not as a bump here.
const PROTOCOL_VERSION: u32 = 1;

public fun protocol_version(): u32 { PROTOCOL_VERSION }

fun init(ctx: &mut TxContext) {
    let registry: KeyRegistry = registry::new_registry(ctx);
    transfer::public_share_object(registry);
}
