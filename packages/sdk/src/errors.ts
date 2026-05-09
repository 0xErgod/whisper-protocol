export class UnsupportedEnvelopeFormatVersionError extends Error {
  readonly formatVersion: number;

  constructor(formatVersion: number) {
    super(`Unsupported Whisper envelope format_version=${formatVersion}.`);
    this.name = "UnsupportedEnvelopeFormatVersionError";
    this.formatVersion = formatVersion;
  }
}

export class UnsupportedEncryptionSchemeError extends Error {
  readonly encryptionScheme: string;

  constructor(encryptionScheme: string) {
    super(`Unsupported Whisper encryption scheme "${encryptionScheme}".`);
    this.name = "UnsupportedEncryptionSchemeError";
    this.encryptionScheme = encryptionScheme;
  }
}

export class WriteCompatibilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WriteCompatibilityError";
  }
}
