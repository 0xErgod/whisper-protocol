import type { SuiClient } from "@mysten/sui/client";
import { encryptForRecipientsV5, tryDecryptV5, tryDecryptV5Utf8 } from "./encrypt-unified.js";
import type { UnifiedEncryptedPayload } from "./encrypt-unified.js";
import { buildPostV5EnvelopeTx, buildRegisterKeyTx } from "./tx.js";
import {
  fetchEncryptionKeyRecord,
  fetchRegistryEntries,
  fetchRegistryEntry,
} from "./registry.js";
import type { EncryptionKeyRecord, RegistryEntry } from "./registry.js";
import {
  fetchV5Envelope,
  fetchV5Inbox,
  recipientIndexInV5Envelope,
  assertCanReadV5Envelope,
  canReadV5Envelope,
} from "./envelope-unified.js";
import type { OnChainV5Envelope } from "./envelope-unified.js";
import { fetchEnvelope as fetchLegacyEnvelope } from "./envelope.js";
import type { OnChainEnvelope as OnChainLegacyEnvelope } from "./envelope.js";
import { normalizeAddress } from "./address.js";
import {
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME_UNIFIED,
  MAX_RECIPIENTS,
  SDK_PROTOCOL_VERSION,
} from "./constants.js";
import {
  assertWriteCompatible,
  readOnChainProtocolVersion,
} from "./protocol.js";
import { requireUnifiedEncryptionSuite } from "./suites-unified.js";

export interface WhisperClientConfig {
  suiClient: SuiClient;
  packageId: string;
  registryId: string;
  protocolVersion?: number;
}

export interface PrepareSendV5Args {
  senderAddress: string;
  /** 1..MAX_RECIPIENTS recipient addresses. N=1 is a degenerate group, not a separate primitive. */
  recipientAddresses: string[];
  plaintext: Uint8Array | string;
  schema?: string;
  context?: Uint8Array;
}

export interface PreparedSendV5 {
  tx: ReturnType<typeof buildPostV5EnvelopeTx>;
  payload: UnifiedEncryptedPayload;
  recipients: RegistryEntry[];
  formatVersion: number;
  encryptionScheme: string;
}

export interface RecipientKeyResolution {
  recipientKeyId: string | null;
  keyVersion: number;
  encryptionScheme: string;
}

export class WhisperClient {
  readonly suiClient: SuiClient;
  readonly packageId: string;
  readonly registryId: string;
  readonly expectedProtocolVersion: number;

  private _onChainProtocolVersion: number | null = null;
  private _protocolCheckPromise: Promise<number> | null = null;

  constructor(config: WhisperClientConfig) {
    this.suiClient = config.suiClient;
    this.packageId = config.packageId;
    this.registryId = config.registryId;
    this.expectedProtocolVersion = config.protocolVersion ?? SDK_PROTOCOL_VERSION;
  }

  async assertWriteCompatible(input?: {
    formatVersion?: number;
    encryptionScheme?: string;
  }): Promise<number> {
    if (this._onChainProtocolVersion !== null) {
      return this._onChainProtocolVersion;
    }
    if (this._protocolCheckPromise !== null) {
      return this._protocolCheckPromise;
    }
    this._protocolCheckPromise = (async () => {
      const onChain = await assertWriteCompatible(this.suiClient, this.packageId, {
        expectedProtocolVersion: this.expectedProtocolVersion,
        formatVersion: input?.formatVersion ?? CURRENT_ENVELOPE_FORMAT_VERSION,
        encryptionScheme: input?.encryptionScheme ?? ENCRYPTION_SCHEME_UNIFIED,
      });
      this._onChainProtocolVersion = onChain;
      return onChain;
    })();
    try {
      return await this._protocolCheckPromise;
    } finally {
      this._protocolCheckPromise = null;
    }
  }

  async assertProtocolCompatible(): Promise<number> {
    return this.assertWriteCompatible();
  }

  get onChainProtocolVersion(): number | null {
    return this._onChainProtocolVersion;
  }

  fetchRegistry(): Promise<RegistryEntry[]> {
    return fetchRegistryEntries(this.suiClient, this.registryId);
  }

  fetchRegistryEntry(account: string): Promise<RegistryEntry | null> {
    return fetchRegistryEntry(this.suiClient, this.registryId, account);
  }

  fetchEncryptionKeyRecord(keyObjectId: string): Promise<EncryptionKeyRecord | null> {
    return fetchEncryptionKeyRecord(this.suiClient, keyObjectId);
  }

  fetchInbox(
    ownerAddress: string,
    options?: { limit?: number },
  ): Promise<OnChainV5Envelope[]> {
    return fetchV5Inbox(this.suiClient, this.packageId, ownerAddress, options);
  }

  fetchEnvelope(envelopeId: string): Promise<OnChainV5Envelope | null> {
    return fetchV5Envelope(this.suiClient, envelopeId);
  }

  /**
   * Read a v1/v2 envelope from a prior deployment. Use this only when
   * you know the envelope predates the v5 unification — for current
   * deployments call `fetchEnvelope` instead.
   */
  fetchLegacyEnvelope(envelopeId: string): Promise<OnChainLegacyEnvelope | null> {
    return fetchLegacyEnvelope(this.suiClient, envelopeId);
  }

  canReadEnvelope(envelope: Pick<OnChainV5Envelope, "formatVersion" | "encryptionScheme">): boolean {
    return canReadV5Envelope(envelope);
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
   * Prepare a v5 envelope send for 1..N recipients.
   *
   * The recipient list is de-duplicated client-side (preserving order)
   * so the on-chain duplicate-recipient guard never fires for innocent
   * input. N=1 is a degenerate group; the on-chain entry point and the
   * cryptographic construction are identical to N≥2.
   */
  async prepareSendV5(args: PrepareSendV5Args): Promise<PreparedSendV5> {
    if (args.recipientAddresses.length === 0) {
      throw new Error("prepareSendV5 requires at least one recipient");
    }
    if (args.recipientAddresses.length > MAX_RECIPIENTS) {
      throw new Error(
        `prepareSendV5 supports at most ${MAX_RECIPIENTS} recipients (got ${args.recipientAddresses.length})`,
      );
    }
    const seen = new Set<string>();
    const dedupedAddresses: string[] = [];
    for (const a of args.recipientAddresses) {
      const norm = normalizeAddress(a);
      if (seen.has(norm)) continue;
      seen.add(norm);
      dedupedAddresses.push(a);
    }
    const recipients: RegistryEntry[] = [];
    for (const addr of dedupedAddresses) {
      const entry = await this.fetchRegistryEntry(addr);
      if (!entry) {
        throw new Error(
          `Recipient ${normalizeAddress(addr)} has no registry entry. They must call register_encryption_key first.`,
        );
      }
      recipients.push(entry);
    }
    const payload = encryptForRecipientsV5({
      senderAddress: args.senderAddress,
      recipients: recipients.map((r) => ({
        address: r.account,
        publicKey: r.encryptionPubkey,
      })),
      plaintext: args.plaintext,
    });
    const tx = buildPostV5EnvelopeTx({
      packageId: this.packageId,
      registryId: this.registryId,
      recipients: recipients.map((r) => ({
        address: r.account,
        keyId: r.currentKeyId,
        keyVersion: r.keyVersion,
      })),
      schema: args.schema,
      context: args.context,
      formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
      payload,
    });
    return {
      tx,
      payload,
      recipients,
      formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
      encryptionScheme: payload.encryptionScheme,
    };
  }

  assertCanReadEnvelope(
    envelope: Pick<OnChainV5Envelope, "formatVersion" | "encryptionScheme">,
  ): void {
    assertCanReadV5Envelope(envelope);
  }

  /**
   * Decrypt a v5 envelope addressed to (or co-addressed to)
   * `recipientAddress`. Returns null if the address isn't in the
   * envelope's recipient list, if the wrap fails (wrong private key),
   * or if the AEAD verification fails.
   */
  decryptEnvelope(input: {
    envelope: OnChainV5Envelope;
    recipientAddress: string;
    recipientPrivateKey: Uint8Array;
  }): Uint8Array | null {
    const idx = recipientIndexInV5Envelope(input.envelope, input.recipientAddress);
    if (idx < 0) return null;
    const wrappedKey = input.envelope.wrappedKeys[idx];
    const wrapNonce = input.envelope.wrapNonces[idx];
    if (!wrappedKey || !wrapNonce) return null;
    const suite = requireUnifiedEncryptionSuite(input.envelope.encryptionScheme);
    return suite.decrypt({
      encryptionScheme: input.envelope.encryptionScheme,
      senderAddress: input.envelope.sender,
      recipientAddress: input.recipientAddress,
      recipientPrivateKey: input.recipientPrivateKey,
      ephPubkey: input.envelope.ephPubkey,
      payloadNonce: input.envelope.payloadNonce,
      ciphertext: input.envelope.ciphertext,
      wrappedKey,
      wrapNonce,
    });
  }

  decryptEnvelopeUtf8(
    input: Parameters<WhisperClient["decryptEnvelope"]>[0],
  ): string | null {
    const bytes = this.decryptEnvelope(input);
    return bytes === null ? null : new TextDecoder().decode(bytes);
  }

  static encryptForRecipientsV5 = encryptForRecipientsV5;
  static tryDecryptV5 = tryDecryptV5;
  static tryDecryptV5Utf8 = tryDecryptV5Utf8;
  static readOnChainProtocolVersion = readOnChainProtocolVersion;
}
