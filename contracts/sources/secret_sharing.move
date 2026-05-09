/// Package facade.
///
/// Whisper Protocol on Sui is laid out as a small set of cooperating
/// modules:
///
/// - `registry`         — public-key registry + `register_encryption_key`
/// - `envelopes`        — single-recipient encrypted transport (fmt v2)
/// - `multi_envelopes`  — multi-recipient encrypted transport (fmt v3)
/// - `commitments`      — public commit/open of text secrets (planned)
///
/// This module owns the deployment-wide write-compatibility marker
/// (`protocol_version`) and the package's `init` function, which is the
/// single source of truth for the canonical shared `KeyRegistry`.
module secret_sharing_poc::secret_sharing;

use secret_sharing_poc::registry::{Self, KeyRegistry};

/// Wire-protocol version. Bump on any change that breaks write
/// compatibility (entry-point shape, event field additions/renames,
/// envelope layout changes). Historical envelope reads are versioned
/// at the envelope level; this deployment-wide version is only for
/// deciding whether a client can safely write its current format.
const PROTOCOL_VERSION: u32 = 4;

public fun protocol_version(): u32 { PROTOCOL_VERSION }

fun init(ctx: &mut TxContext) {
    let registry: KeyRegistry = registry::new_registry(ctx);
    transfer::public_share_object(registry);
}
