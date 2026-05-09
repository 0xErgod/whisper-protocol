import type { SuiClient } from "@mysten/sui/client";
import { encryptForRecipient, tryDecrypt, tryDecryptUtf8 } from "./encrypt.js";
import type { EncryptedPayload } from "./encrypt.js";
import { buildPostEnvelopeTx, buildRegisterKeyTx } from "./tx.js";
import {
  fetchEncryptionKeyRecord,
  fetchRegistryEntries,
  fetchRegistryEntry,
} from "./registry.js";
import type { EncryptionKeyRecord, RegistryEntry } from "./registry.js";
import {
  assertCanReadEnvelope,
  canReadEnvelope,
  fetchEnvelope,
  fetchInbox,
} from "./envelope.js";
import type { OnChainEnvelope } from "./envelope.js";
import { normalizeAddress } from "./address.js";
import {
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENCRYPTION_SCHEME,
  SDK_PROTOCOL_VERSION,
} from "./constants.js";
import {
  assertWriteCompatible,
  readOnChainProtocolVersion,
} from "./protocol.js";
import { requireEncryptionSuite, supportsEncryptionScheme } from "./suites.js";

export interface WhisperClientConfig {
  suiClient: SuiClient;
  packageId: string;
  registryId: string;
  protocolVersion?: number;
}

export interface PrepareSendArgs {
  senderAddress: string;
  recipientAddress: string;
  plaintext: Uint8Array | string;
  schema?: string;
  context?: Uint8Array;
}

export interface PreparedSend {
  tx: ReturnType<typeof buildPostEnvelopeTx>;
  payload: EncryptedPayload;
  recipient: RegistryEntry;
  formatVersion: number;
  recipientKeyId: string;
  keyVersion: number;
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
        encryptionScheme: input?.encryptionScheme ?? ENCRYPTION_SCHEME,
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

  fetchInbox(ownerAddress: string): Promise<OnChainEnvelope[]> {
    return fetchInbox(this.suiClient, this.packageId, ownerAddress);
  }

  fetchEnvelope(envelopeId: string): Promise<OnChainEnvelope | null> {
    return fetchEnvelope(this.suiClient, envelopeId);
  }

  canReadEnvelope(envelope: Pick<OnChainEnvelope, "formatVersion" | "encryptionScheme">): boolean {
    return canReadEnvelope(envelope);
  }

  buildRegisterKeyTx(encryptionPublicKey: Uint8Array, encryptionScheme?: string) {
    return buildRegisterKeyTx({
      packageId: this.packageId,
      registryId: this.registryId,
      encryptionPublicKey,
      encryptionScheme,
    });
  }

  async prepareSend(args: PrepareSendArgs): Promise<PreparedSend> {
    const recipient = await this.fetchRegistryEntry(args.recipientAddress);
    if (!recipient) {
      throw new Error(
        `Recipient ${normalizeAddress(args.recipientAddress)} has no registry entry. They must call register_encryption_key first.`,
      );
    }
    const payload = encryptForRecipient({
      encryptionScheme: recipient.encryptionScheme,
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
      formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
      recipientKeyId: recipient.currentKeyId,
      keyVersion: recipient.keyVersion,
      payload,
    });
    return {
      tx,
      payload,
      recipient,
      formatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
      recipientKeyId: recipient.currentKeyId,
      keyVersion: recipient.keyVersion,
    };
  }

  assertCanReadEnvelope(
    envelope: Pick<OnChainEnvelope, "formatVersion" | "encryptionScheme">,
  ): void {
    assertCanReadEnvelope(envelope);
  }

  decryptEnvelope(input: {
    envelope: Pick<
      OnChainEnvelope,
      "formatVersion" | "sender" | "recipient" | "encryptionScheme" | "ephPubkey" | "nonce" | "ciphertext"
    >;
    recipientAddress: string;
    recipientPrivateKey: Uint8Array;
  }): Uint8Array | null {
    this.assertCanReadEnvelope(input.envelope);
    if (
      normalizeAddress(input.envelope.recipient) !==
      normalizeAddress(input.recipientAddress)
    ) {
      return null;
    }
    return tryDecrypt({
      recipientPrivateKey: input.recipientPrivateKey,
      encryptionScheme: input.envelope.encryptionScheme,
      senderAddress: input.envelope.sender,
      recipientAddress: input.envelope.recipient,
      ephPubkey: input.envelope.ephPubkey,
      nonce: input.envelope.nonce,
      ciphertext: input.envelope.ciphertext,
    });
  }

  async decryptEnvelopeWithKeyResolver(input: {
    envelope: Pick<
      OnChainEnvelope,
      | "formatVersion"
      | "sender"
      | "recipient"
      | "recipientKeyId"
      | "encryptionScheme"
      | "keyVersion"
      | "ephPubkey"
      | "nonce"
      | "ciphertext"
    >;
    recipientAddress: string;
    resolveRecipientPrivateKey: (
      key: RecipientKeyResolution,
    ) => Promise<Uint8Array | null> | Uint8Array | null;
  }): Promise<Uint8Array | null> {
    this.assertCanReadEnvelope(input.envelope);
    if (
      normalizeAddress(input.envelope.recipient) !==
      normalizeAddress(input.recipientAddress)
    ) {
      return null;
    }
    const recipientPrivateKey = await input.resolveRecipientPrivateKey({
      recipientKeyId: input.envelope.recipientKeyId,
      keyVersion: input.envelope.keyVersion,
      encryptionScheme: input.envelope.encryptionScheme,
    });
    if (!recipientPrivateKey) return null;
    return requireEncryptionSuite(input.envelope.encryptionScheme).decrypt({
      recipientPrivateKey,
      encryptionScheme: input.envelope.encryptionScheme,
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

  static encrypt = encryptForRecipient;
  static tryDecrypt = tryDecrypt;
  static tryDecryptUtf8 = tryDecryptUtf8;
  static readOnChainProtocolVersion = readOnChainProtocolVersion;
}
