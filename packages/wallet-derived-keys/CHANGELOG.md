# Changelog

All notable changes to `@whisper-protocol/wallet-derived-keys` are documented here.

This file is curated by hand for breaking-change visibility. Mechanically-
generated release notes also live on the GitHub Releases page under
the `wallet-derived-v*` tag prefix.

## 0.2.0 — 2026-05-04

### Features

- **Wallet-Standard dispatch.** New top-level entry point
  `deriveEncryptionKeypairFromWallet(wallet, account, message, options?)`
  inspects the connected wallet's `features` map and routes to the
  right signing path automatically. Consumers no longer have to know
  which wallet they're talking to. Returns `{ keypair, path }` so
  callers can surface which path was used for UI / observability.
- **`misc:deriveSignature` support.** Adds Path B: when a wallet
  exposes the `misc:deriveSignature` Wallet-Standard custom feature
  (e.g. EVE Vault for zkLogin users), the SDK uses it instead of
  `sui:signPersonalMessage` and skips the Ed25519 scheme gate. This
  is what unblocks zkLogin wallets, whose personal-message signatures
  are non-deterministic by design.
- **Centralized protocol constants.** New `constants.ts` module exports
  `WHISPER_PROTOCOL_NAME`, `CURRENT_DERIVATION_VERSION`, `ROOT_SCOPE`,
  and `DERIVE_SIGNATURE_FEATURE_SCOPE`. These are the strings that
  participate in canonical-message construction or feature dispatch;
  bumping any of them is a documented breaking change.
- **`deriveFromDeterministicSigner` helper** added to `derive.ts` for
  callers who want to drive the deterministic-sign path manually
  (mirrors the existing `deriveFromWalletSigner`).
- **Cross-device stability tests.** Pinned X25519 public keys for both
  Path A and Path B against fixed identity + canonical-message inputs.
  Any future change to canonical-message format, HKDF parameters, or
  X25519 derivation that would silently rotate every existing user's
  key now fails CI loudly. See
  `src/__tests__/crossDevice.golden.test.ts`.

### Bug Fixes

- **Slush flagged-pubkey detection.** `detectSchemeFromAccount` now
  accepts both raw (32-byte) and flagged (33-byte, with leading scheme
  flag byte) shapes for `account.publicKey`. Slush emits the flagged
  shape; most other Sui wallets emit raw. Both are valid under
  Wallet-Standard, both must work. Previously, Slush accounts failed
  scheme detection at registration time even though they are Ed25519.

### Documentation

- Spec updated: `specs/wallet-signature-derived-keys.md` gains a
  "Wallet Integration Paths" section documenting Path A, Path B, the
  selection rule, cross-path key incompatibility, the `scope`
  override option, and trade-offs §11a–c (Path B's second
  deterministic-signing dependency, unverified wrapped envelope, no
  runtime drift detection). Future Work §8–9 captures the hardening
  steps.

### Release-tagging note

The first release containing these changes mis-routed through
semantic-release: PR #23 used `feat(sdk):` / `fix(sdk):` commit
scopes, which the repo's release config maps to the
`@whisper-protocol/sdk` package rather than this one. As a result,
`@whisper-protocol/sdk@0.2.0` was published containing no actual SDK
changes (functionally identical to `0.1.1`), and that version was
deprecated on npm with a pointer here.

This `wallet-derived-v0.2.0` release is the corrected re-route. The
underlying code shipped on `main` at commit
[7e4ec27](https://github.com/0xErgod/whisper-protocol/commit/7e4ec27)
on 2026-05-03 — same code, correct package and version slot.

## 0.1.0 — 2026-05-02

Initial release.
