// `WhisperClient` — the SDK's entry point. Holds the Sui client,
// package id, and registry id, and exposes the operations a dApp
// composes to send and read envelopes.
//
// Single-recipient by design: every envelope mirrors
// `crates/protocol::envelope`, with the BJJ seal/open construction
// running over crypto-wasm. Multi-recipient delivery is "post N
// envelopes" composed at the dApp layer.

import type { SuiClient } from "@mysten/sui/client";
import { buildPostEnvelopeTx, buildRegisterKeyTx } from "./tx.js";
import {
  fetchEncryptionKeyRecord,
  fetchRegistryEntries,
  fetchRegistryEntry,
} from "./registry.js";
import type { EncryptionKeyRecord, RegistryEntry } from "./registry.js";
import { fetchEnvelope } from "./envelope.js";
import type { OnChainEnvelope } from "./envelope.js";
import { open, seal } from "./suite.js";
import type { Envelope, Payload } from "./suite.js";
import { normalizeAddress } from "./address.js";
import { SDK_PROTOCOL_VERSION } from "./constants.js";
import {
  assertWriteCompatible,
  readOnChainProtocolVersion,
} from "./protocol.js";

export interface WhisperClientConfig {
  suiClient: SuiClient;
  packageId: string;
  registryId: string;
  protocolVersion?: number;
}

/**
 * Inputs for `prepareSend`: caller supplies the sender's BJJ keypair
 * (seed + pubkey) and the recipient's Sui address. The client looks
 * up the recipient's current key in the registry, runs `suite.seal`,
 * and builds the matching PTB.
 */
export interface PrepareSendArgs {
  senderAddress: string;
  senderSeed: Uint8Array;
  senderPubkeyX: string;
  senderPubkeyY: string;
  recipientAddress: string;
  envelopeId: string;
  payload: Payload;
}

export interface PreparedSend {
  /** PTB ready to sign + execute. */
  tx: ReturnType<typeof buildPostEnvelopeTx>;
  /** Sealed envelope (the on-chain post mirrors these fields). */
  envelope: Envelope;
  /** The recipient's resolved registry entry. */
  recipient: RegistryEntry;
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

  /**
   * Refuse to write if the deployed package doesn't match this SDK's
   * expected `protocol_version`. Memoizes the first successful check
   * so repeated callers don't re-dev-inspect.
   */
  async assertWriteCompatible(): Promise<number> {
    if (this._onChainProtocolVersion !== null) {
      return this._onChainProtocolVersion;
    }
    if (this._protocolCheckPromise !== null) {
      return this._protocolCheckPromise;
    }
    this._protocolCheckPromise = (async () => {
      const onChain = await assertWriteCompatible(this.suiClient, this.packageId, {
        expectedProtocolVersion: this.expectedProtocolVersion,
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

  fetchEnvelope(envelopeObjectId: string): Promise<OnChainEnvelope | null> {
    return fetchEnvelope(this.suiClient, envelopeObjectId);
  }

  buildRegisterKeyTx(args: { pubkeyX: string; pubkeyY: string }) {
    return buildRegisterKeyTx({
      packageId: this.packageId,
      registryId: this.registryId,
      pubkeyX: args.pubkeyX,
      pubkeyY: args.pubkeyY,
    });
  }

  /**
   * Look up the recipient's current registry entry, seal the payload
   * client-side via `suite.seal`, and build the on-chain post PTB.
   * Returns the prepared transaction plus the sealed envelope (so the
   * dApp can log it, hash it, etc. before signing).
   */
  async prepareSend(args: PrepareSendArgs): Promise<PreparedSend> {
    const recipient = await this.fetchRegistryEntry(args.recipientAddress);
    if (!recipient) {
      throw new Error(
        `Recipient ${normalizeAddress(args.recipientAddress)} has no registry entry. They must call register_encryption_key first.`,
      );
    }
    const envelope = seal({
      senderSeed: args.senderSeed,
      senderPkX: args.senderPubkeyX,
      senderPkY: args.senderPubkeyY,
      recipientPkX: recipient.pubkeyX,
      recipientPkY: recipient.pubkeyY,
      envelopeId: args.envelopeId,
      payload: args.payload,
    });
    const tx = buildPostEnvelopeTx({
      packageId: this.packageId,
      registryId: this.registryId,
      recipient: recipient.account,
      recipientKeyId: recipient.currentKeyId,
      recipientKeyVersion: recipient.keyVersion,
      envelope,
    });
    return { tx, envelope, recipient };
  }

  /**
   * Decrypt an on-chain envelope addressed to `recipientPubkey`.
   * Returns the recovered payload or throws `WhisperOpenError` if the
   * envelope isn't for this recipient or the MAC fails.
   */
  decryptEnvelope(args: {
    envelope: OnChainEnvelope;
    recipientSeed: Uint8Array;
    recipientPubkeyX: string;
    recipientPubkeyY: string;
  }): Payload {
    const projection: Envelope = {
      senderPkX: args.envelope.senderPkX,
      senderPkY: args.envelope.senderPkY,
      recipientPkX: args.envelope.recipientPkX,
      recipientPkY: args.envelope.recipientPkY,
      envelopeId: args.envelope.envelopeId,
      encodingId: args.envelope.encodingId,
      ciphertext: args.envelope.ciphertext,
      macTag: args.envelope.macTag,
    };
    return open({
      recipientSeed: args.recipientSeed,
      recipientPkX: args.recipientPubkeyX,
      recipientPkY: args.recipientPubkeyY,
      envelope: projection,
    });
  }

  static readOnChainProtocolVersion = readOnChainProtocolVersion;
}
