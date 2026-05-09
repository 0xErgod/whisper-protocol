/// Package facade.
///
/// Whisper Protocol on Sui is laid out as a small set of cooperating
/// modules:
///
/// - `registry`     — public-key registry + `register_encryption_key`
/// - `envelopes`    — unified encrypted transport (fmt v5: 1..N
///                    recipients, hybrid construction, frozen)
/// - `commitments`  — public commit/open of text secrets
///
/// This module owns the deployment-wide write-compatibility marker
/// (`protocol_version`) and the package's `init` function, which is the
/// single source of truth for the canonical shared `KeyRegistry`.
///
/// Historical note: v2 (single-recipient owned) and v3 (multi-recipient
/// frozen) envelopes existed in earlier deployments. Their on-chain
/// types are gone from this package, but their decoders live on in the
/// SDK so prior-deployment envelopes stay readable. Going forward only
/// the unified v5 envelope module accepts writes.
module secret_sharing_poc::secret_sharing;

use secret_sharing_poc::registry::{Self, KeyRegistry};

/// Wire-protocol version. Bump on any change that breaks write
/// compatibility (entry-point shape, event field additions/renames,
/// envelope layout changes). Historical envelope reads are versioned
/// at the envelope level; this deployment-wide version is only for
/// deciding whether a client can safely write its current format.
const PROTOCOL_VERSION: u32 = 5;

public fun protocol_version(): u32 { PROTOCOL_VERSION }

fun init(ctx: &mut TxContext) {
    let registry: KeyRegistry = registry::new_registry(ctx);
    transfer::public_share_object(registry);
}
