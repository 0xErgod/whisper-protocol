/**
 * Whisper protocol constants.
 *
 * Single source of truth for the strings that participate in
 * canonical-message construction or wallet-feature dispatch. Anything
 * that ends up byte-stable across users and devices belongs here.
 *
 * Bumping any of these is a breaking change to the derivation pipeline:
 * existing derived keypairs will not match the new output. Treat this
 * file the way you would treat a magic-number table in a serialization
 * format.
 */

/** Identifier embedded as the first line of the canonical message. */
export const WHISPER_PROTOCOL_NAME = "whisper-protocol";

/**
 * Current canonical-message version. Bumping this is the documented
 * way to rotate keys forward without breaking past envelopes (which
 * remain decryptable by re-deriving with the old version).
 *
 * See specs/wallet-signature-derived-keys.md §"Rotation".
 */
export const CURRENT_DERIVATION_VERSION = 1;

/**
 * Scope tag for the default per-wallet keypair. Future per-conversation
 * derivations will use scopes like `dm:0xabc...`.
 */
export const ROOT_SCOPE = "root";

/**
 * Scope tag we send to wallets that implement the `misc:deriveSignature`
 * Wallet-Standard feature. Different scope values produce unrelated
 * deterministic keys *inside the wallet*; using a stable, Whisper-
 * specific scope means every Whisper integration agrees on which
 * sub-key to pull from any compatible wallet.
 *
 * The version suffix is independent of `CURRENT_DERIVATION_VERSION`
 * above. The latter rotates the canonical message Whisper sends; this
 * one rotates the sub-key the wallet selects. We bump them together
 * only when the rotation should land in both places.
 */
export const DERIVE_SIGNATURE_FEATURE_SCOPE = "whisper-protocol/v1";
