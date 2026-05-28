// Cross-cutting SDK errors. Per-module errors live in the modules
// that throw them (e.g. `WhisperOpenError` in `suite.ts`).

/**
 * The deployed package's `protocol_version` doesn't match the version
 * this SDK is willing to write to. Thrown by `assertWriteCompatible`.
 */
export class WriteCompatibilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WriteCompatibilityError";
  }
}
