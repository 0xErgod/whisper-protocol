import type { SuiClient } from "@mysten/sui/client";
import { encryptForRecipient, tryDecrypt, tryDecryptUtf8 } from "./encrypt.js";
import type { EncryptedPayload } from "./encrypt.js";
import {
  buildPostEnvelopeTx,
  buildRegisterKeyTx,
} from "./tx.js";
import {
  fetchRegistryEntries,
  fetchRegistryEntry,
} from "./registry.js";
import type { RegistryEntry } from "./registry.js";
import { fetchEnvelope, fetchInbox } from "./envelope.js";
import type { OnChainEnvelope } from "./envelope.js";
import { normalizeAddress } from "./address.js";
import { SDK_PROTOCOL_VERSION } from "./constants.js";
import { readOnChainProtocolVersion } from "./protocol.js";

export interface WhisperClientConfig {
  suiClient: SuiClient;
  packageId: string;
  registryId: string;
  /**
   * Expected on-chain protocol_version. Defaults to the SDK's compiled-in
   * SDK_PROTOCOL_VERSION. Override only when intentionally targeting a
   * different deployment.
   */
  protocolVersion?: number;
}

export interface PrepareSendArgs {
  senderAddress: string;
  recipientAddress: string;
  plaintext: Uint8Array | string;
  /** Schema string written into the envelope; defaults to `text_secret_v1`. */
  schema?: string;
  /** Optional opaque indexer tag stored in the envelope's `context` field. */
  context?: Uint8Array;
}

export interface PreparedSend {
  /** Built but unsigned transaction — caller signs and executes it. */
  tx: ReturnType<typeof buildPostEnvelopeTx>;
  /** The encrypted bytes the transaction will post. Useful for receipts. */
  payload: EncryptedPayload;
  /** Recipient registry entry the SDK encrypted to. */
  recipient: RegistryEntry;
  /** Asserted on-chain key_version. Sender races a rotation = abort. */
  keyVersion: number;
}

/**
 * Convenience facade around the protocol primitives. Holds zero secrets;
 * every encryption step takes the caller's keys as explicit input.
 */
export class WhisperClient {
  readonly suiClient: SuiClient;
  readonly packageId: string;
  readonly registryId: string;
  readonly expectedProtocolVersion: number;

  // Memoised result of the on-chain protocol_version() view call. Cached
  // for the lifetime of the client — package id is immutable, so the
  // version can't change under us.
  private _onChainProtocolVersion: number | null = null;
  private _protocolCheckPromise: Promise<number> | null = null;

  constructor(config: WhisperClientConfig) {
    this.suiClient = config.suiClient;
    this.packageId = config.packageId;
    this.registryId = config.registryId;
    this.expectedProtocolVersion = config.protocolVersion ?? SDK_PROTOCOL_VERSION;
  }

  /**
   * Read the deployed Move module's `protocol_version()` and assert it
   * matches `expectedProtocolVersion`. Cached after the first call.
   *
   * Throws if the deployed module reports a different version than the
   * SDK was built for, or if the deployed package predates the
   * protocol_version function (pre-SDK-compat deployments). Callers
   * should run this once at startup before any send/decrypt work to
   * avoid silently posting envelopes against an incompatible registry.
   */
  async assertProtocolCompatible(): Promise<number> {
    if (this._onChainProtocolVersion !== null) {
      return this._onChainProtocolVersion;
    }
    if (this._protocolCheckPromise !== null) {
      return this._protocolCheckPromise;
    }
    this._protocolCheckPromise = (async () => {
      const onChain = await readOnChainProtocolVersion(this.suiClient, this.packageId);
      if (onChain !== this.expectedProtocolVersion) {
        throw new Error(
          `Whisper protocol version mismatch: deployed package ${this.packageId} reports protocol_version=${onChain}, but this SDK was built for ${this.expectedProtocolVersion}. Upgrade the SDK (or downgrade the package) before continuing — wire formats may differ.`,
        );
      }
      this._onChainProtocolVersion = onChain;
      return onChain;
    })();
    try {
      return await this._protocolCheckPromise;
    } finally {
      this._protocolCheckPromise = null;
    }
  }

  /** Return the cached on-chain protocol version, or null if unchecked yet. */
  get onChainProtocolVersion(): number | null {
    return this._onChainProtocolVersion;
  }

  fetchRegistry(): Promise<RegistryEntry[]> {
    return fetchRegistryEntries(this.suiClient, this.registryId);
  }

  fetchRegistryEntry(account: string): Promise<RegistryEntry | null> {
    return fetchRegistryEntry(this.suiClient, this.registryId, account);
  }

  fetchInbox(ownerAddress: string): Promise<OnChainEnvelope[]> {
    return fetchInbox(this.suiClient, this.packageId, ownerAddress);
  }

  fetchEnvelope(envelopeId: string): Promise<OnChainEnvelope | null> {
    return fetchEnvelope(this.suiClient, envelopeId);
  }

  buildRegisterKeyTx(encryptionPublicKey: Uint8Array, encryptionScheme?: string) {
    return buildRegisterKeyTx({
      packageId: this.packageId,
      registryId: this.registryId,
      encryptionPublicKey,
      encryptionScheme,
    });
  }

  /**
   * Look up the recipient, encrypt the plaintext, and build a
   * post_envelope transaction. The returned `tx` is unsigned — caller
   * signs it with the sender's wallet (`signAndExecute`,
   * `useSignAndExecuteTransaction`, or equivalent).
   */
  async prepareSend(args: PrepareSendArgs): Promise<PreparedSend> {
    const recipient = await this.fetchRegistryEntry(args.recipientAddress);
    if (!recipient) {
      throw new Error(
        `Recipient ${normalizeAddress(args.recipientAddress)} has no registry entry. They must call register_encryption_key first.`,
      );
    }
    const payload = encryptForRecipient({
      senderAddress: args.senderAddress,
      recipientAddress: args.recipientAddress,
      recipientPublicKey: recipient.encryptionPubkey,
      plaintext: args.plaintext,
    });
    const tx = buildPostEnvelopeTx({
      packageId: this.packageId,
      registryId: this.registryId,
      recipientAddress: args.recipientAddress,
      schema: args.schema,
      context: args.context,
      keyVersion: recipient.keyVersion,
      payload,
    });
    return { tx, payload, recipient, keyVersion: recipient.keyVersion };
  }

  /**
   * Decrypt an envelope addressed to the given address using the
   * provided X25519 private key. Returns `null` on any failure
   * (wrong key, wrong recipient, tampered ciphertext).
   */
  decryptEnvelope(input: {
    envelope: Pick<
      OnChainEnvelope,
      "sender" | "recipient" | "ephPubkey" | "nonce" | "ciphertext"
    >;
    recipientAddress: string;
    recipientPrivateKey: Uint8Array;
  }): Uint8Array | null {
    if (
      normalizeAddress(input.envelope.recipient) !==
      normalizeAddress(input.recipientAddress)
    ) {
      return null;
    }
    return tryDecrypt({
      recipientPrivateKey: input.recipientPrivateKey,
      senderAddress: input.envelope.sender,
      recipientAddress: input.envelope.recipient,
      ephPubkey: input.envelope.ephPubkey,
      nonce: input.envelope.nonce,
      ciphertext: input.envelope.ciphertext,
    });
  }

  decryptEnvelopeUtf8(input: Parameters<WhisperClient["decryptEnvelope"]>[0]): string | null {
    const bytes = this.decryptEnvelope(input);
    return bytes === null ? null : new TextDecoder().decode(bytes);
  }

  // Re-exports of the pure helpers, surfaced for convenience.
  static encrypt = encryptForRecipient;
  static tryDecrypt = tryDecrypt;
  static tryDecryptUtf8 = tryDecryptUtf8;
}
