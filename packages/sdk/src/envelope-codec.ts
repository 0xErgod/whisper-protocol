import { ENCRYPTION_SCHEME, LEGACY_ENVELOPE_FORMAT_VERSION } from "./constants.js";
import { UnsupportedEnvelopeFormatVersionError } from "./errors.js";

export interface EnvelopeCompatibilityMetadata {
  formatVersion: number;
  encryptionScheme: string;
}

interface EnvelopeDecoder<TInput, TOutput> {
  decode(input: TInput): TOutput;
}

function numberFromUnknown(input: unknown): number {
  if (typeof input === "number") return input;
  if (typeof input === "string" && input.length > 0) return Number(input);
  return 0;
}

export function bytesFromArray(input: unknown): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (Array.isArray(input)) return Uint8Array.from(input as number[]);
  if (typeof input === "string") {
    if (input.startsWith("0x")) {
      const hex = input.slice(2);
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    const bin = atob(input);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array();
}

export function stringFromBytes(input: unknown): string {
  return new TextDecoder().decode(bytesFromArray(input));
}

export function idFromUnknown(input: unknown): string | null {
  if (typeof input === "string" && input.length > 0) return input;
  if (typeof input !== "object" || input === null) return null;
  const record = input as Record<string, unknown>;
  if (typeof record.id === "string") return record.id;
  if (typeof record.bytes === "string") return record.bytes;
  if (typeof record.value === "string") return record.value;
  return null;
}

export function detectEnvelopeFormatVersion(fields: Record<string, unknown>): number {
  if (!("format_version" in fields)) return LEGACY_ENVELOPE_FORMAT_VERSION;
  return numberFromUnknown(fields.format_version);
}

export function canDecodeEnvelopeFormatVersion(formatVersion: number): boolean {
  return formatVersion === LEGACY_ENVELOPE_FORMAT_VERSION || formatVersion === 2;
}

export function assertSupportedEnvelopeFormatVersion(formatVersion: number): void {
  if (!canDecodeEnvelopeFormatVersion(formatVersion)) {
    throw new UnsupportedEnvelopeFormatVersionError(formatVersion);
  }
}

const legacyEnvelopeMetadataDecoder: EnvelopeDecoder<Record<string, unknown>, EnvelopeCompatibilityMetadata> = {
  decode() {
    return {
      formatVersion: LEGACY_ENVELOPE_FORMAT_VERSION,
      encryptionScheme: ENCRYPTION_SCHEME,
    };
  },
};

const v2EnvelopeMetadataDecoder: EnvelopeDecoder<Record<string, unknown>, EnvelopeCompatibilityMetadata> = {
  decode(input) {
    return {
      formatVersion: detectEnvelopeFormatVersion(input),
      encryptionScheme: stringFromBytes(input.encryption_scheme),
    };
  },
};

export function decodeEnvelopeCompatibilityMetadata(
  fields: Record<string, unknown>,
): EnvelopeCompatibilityMetadata {
  const formatVersion = detectEnvelopeFormatVersion(fields);
  assertSupportedEnvelopeFormatVersion(formatVersion);
  return formatVersion === LEGACY_ENVELOPE_FORMAT_VERSION
    ? legacyEnvelopeMetadataDecoder.decode(fields)
    : v2EnvelopeMetadataDecoder.decode(fields);
}
