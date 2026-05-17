# Wallet-Signature-Derived Encryption Keys

## Status

Draft. Supersedes the "client has direct Ed25519 private key" assumption in
[wallet-bound-private-messaging.md](./wallet-bound-private-messaging.md).
This document replaces *Phase 1* of that spec's PoC plan; the on-chain data
model, hybrid encryption, associated-data rules, and indexer design from that
document still apply unchanged.

## Goal

Let any Sui wallet — without exporting private key material, without a
custodial server, and without a wallet plugin — derive a stable X25519
encryption keypair that other users can address.

The current PoC reads Ed25519 seeds from `.env`. That works for three demo
characters; it does not work for real users. This spec defines the path to
real-wallet support.

## Core Idea

The user signs a fixed, domain-separated message with their Sui wallet. The
signature bytes are deterministic key material. We feed them through HKDF
to produce an X25519 seed and publish the corresponding public key to the
on-chain `KeyRegistry` exactly as today.

```text
sig = wallet.signPersonalMessage(canonical_message)
seed = HKDF-SHA256(ikm = sig, salt = "whisper/v1/encryption-keypair", info = "x25519")[0..32]
encryption_priv = clamp(seed)
encryption_pub  = X25519.scalarMultBase(encryption_priv)
```

The user signs once per device; the derived keypair is cached in IndexedDB
for that origin.

## The One Property That Makes This Work

The whole construction depends on **the wallet producing the same signature
bytes for the same `(private_key, message)` every time**.

This is a property of the **signature scheme**, not of the wallet, the API,
or the message. The scheme matters more than the wallet.

| Scheme                        | Deterministic by spec? | Usable for derivation? |
|-------------------------------|------------------------|------------------------|
| Ed25519 (RFC 8032)            | Yes                    | Yes                    |
| Schnorr (BIP-340)             | Yes                    | Yes                    |
| BLS                           | Yes                    | Yes                    |
| ECDSA secp256k1 / secp256r1   | No (RFC 6979 optional) | Only if RFC 6979       |
| WebAuthn / passkey signatures | Implementation-defined | Generally no           |

Sui supports Ed25519 (default), secp256k1, and secp256r1. **Whisper's
on-ramp must gate to Ed25519** at registration time. Refuse other schemes
with a clear error and a link to this document. Sui's default wallet
generates Ed25519 keys, so in practice this excludes few users.

A "trust-and-verify" alternative — sign the message twice and reject the
wallet if the signatures differ — is rejected as primary path: the UX cost
of a double prompt is high, and a wallet that's deterministic today can
become non-deterministic after a firmware update without warning.

## Canonical Message Format

The message is the security boundary. Its construction is non-negotiable.

```text
whisper-protocol
version: 1
purpose: encryption-keypair
address: 0x<lowercased sui address with 0x prefix>
scope: root
```

Rules:

- **UTF-8, LF line endings, no trailing newline.** Wallets that normalize
  whitespace will silently produce a different signature; we lock the
  format byte-exactly.
- **Address is included.** Without it, two protocols that happen to use
  identical preambles can derive the same encryption key for the same user.
  With it, a phisher must target a specific victim.
- **Version is the integer after `version:`.** Bumping it is the only
  supported way to derive a new encryption keypair from the same wallet.
- **Scope** allows future per-conversation or per-context subkeys (e.g.
  `scope: dm:0xabc…`). For the PoC, only `scope: root` is defined.

The wallet wraps the message bytes in Sui's `PersonalMessage` intent
prefix before signing; verification on every Sui wallet uses the same
wrapping, so cross-wallet portability holds *as long as every signer goes
through the standard `signPersonalMessage` API*. A custom signer that
signs raw bytes will silently produce a different signature — see
**Trade-offs** §9.

## Wallet Integration Paths

Two Wallet-Standard features can produce the deterministic signature
the derivation pipeline consumes. The dApp picks one at runtime based
on what the connected wallet exposes; the choice is invisible to
on-chain logic.

### Path A — `sui:signPersonalMessage`

The default. Any Sui wallet that signs personal messages with an
RFC-8032 Ed25519 key qualifies. The SDK runs the **Ed25519 scheme
gate** (see §"The One Property That Makes This Work") before invoking
the wallet, so non-Ed25519 wallets are refused at registration time
with a clear error.

This path covers Slush, the official Sui Wallet, hardware wallets, and
any browser-extension wallet that uses Wallet-Standard's
`sui:signPersonalMessage` feature.

### Path B — `misc:deriveSignature`

For wallets where `sui:signPersonalMessage` is *not* deterministic —
notably **zkLogin wallets**, where the user-signature component is
produced by a per-session ephemeral keypair — the wallet may instead
expose a Wallet-Standard custom feature with the identifier
`misc:deriveSignature`.

A wallet implementing this feature derives an Ed25519 sub-key
internally from the user's stable identity material (e.g.
`HKDF(salt || sub || aud, info = scope)`), wraps the dApp-supplied
message in a wallet-controlled canonical envelope, and signs with the
sub-key. The signature is byte-deterministic across sessions and
devices for any given `(identity, scope)`.

When the SDK takes this path:

- It **skips the Ed25519 scheme gate**. The wallet's outer signing
  scheme (zkLogin, multisig, etc.) is irrelevant; correctness depends
  on the wallet's *internal* sub-key derivation being byte-stable,
  which the feature contract requires.
- It passes scope `whisper-protocol/v1` by default (the
  `DERIVE_SIGNATURE_FEATURE_SCOPE` constant). Consumers can override
  this via the `scope` option to
  `deriveEncryptionKeypairFromWallet`, but doing so changes which
  wallet sub-key participates in derivation — a different scope will
  produce a different X25519 keypair, so an override is effectively a
  key rotation. All Whisper integrations using the default scope agree
  on the resulting key for a given user.
- It HKDFs the **signature bytes** the wallet returns. The wrapped
  `bytes` field and the wallet-returned `publicKey` are surfaced by
  the wallet feature but **not currently verified by the SDK**. A
  malicious wallet could in principle return a signature it produced
  over different bytes than the canonical envelope claims; today this
  reduces to "the wallet is malicious," which already loses against
  every signing path. See **Trade-offs** §11b.

For the wallet-side spec see
[evevault/docs/DERIVE_SIGNATURE.md](https://github.com/0xErgod/evevault/blob/main/docs/DERIVE_SIGNATURE.md)
in the Eve Vault fork; that's the reference implementation.

### Selection rule

```text
if wallet exposes "misc:deriveSignature":
    use Path B
else:
    require Ed25519 (refuse Secp256k1, MultiSig, ZkLogin, Passkey)
    use Path A
```

A wallet exposing both features in practice should not happen — the
two are mutually exclusive in their use cases — but if it does, B
wins. The `misc:deriveSignature` contract is stricter (mandates
deterministic sub-key derivation), so it's the safer default.

### Cross-path key incompatibility

The two paths produce different X25519 keypairs **for the same user**.
The derivation HKDF is identical, but the inputs are not: Path A
HKDFs the wallet's personal-message signature, Path B HKDFs the
wallet-internal sub-key signature. Different signatures, different
keys.

This means: a user who derives an encryption keypair via Path A on a
Slush wallet, then later switches to a zkLogin wallet using Path B,
will get a *different* key. The on-chain `KeyRegistry` carries one
current version per Sui address; switching paths is a key rotation
that requires re-registering and writing a new `key_version`. Old
envelopes encrypted to the old pubkey can still be decrypted by going
back to the old wallet (the math is deterministic), but new senders
will use the new pubkey.

Wallets in the wild today implement at most one of the two features,
so this is a forward concern rather than a daily-use issue.

## Derivation

```text
ikm  = signature_bytes
salt = utf8("whisper/v1/encryption-keypair")
info = utf8("x25519")
seed = HKDF-SHA256(ikm, salt, info, length = 32)

encryption_priv = clamp(seed)
encryption_pub  = X25519.scalarMultBase(encryption_priv)
```

`clamp` is the standard Curve25519 bit-clamping (`seed[0] &= 248;
seed[31] &= 127; seed[31] |= 64`). The same operation is performed by
`x25519.utils.randomPrivateKey` in `@noble/curves` and by
`StaticSecret::from` in `x25519-dalek`.

Once `encryption_priv` is in memory, zeroize the signature bytes and the
HKDF intermediate buffers. The signature is now a long-lived high-value
secret; treat it as such (see **Trade-offs** §3).

## On-Chain Registration

Unchanged from the current PoC. The user calls
`secret_sharing::register_encryption_key(&mut KeyRegistry, scheme,
pubkey, &Clock)` with their Sui wallet, posting `encryption_pub`. Other
users can verify the binding because the registration tx is signed by the
claimed Sui address.

The on-chain module does **not** need to know how the encryption key was
derived. The derivation is a client-side concern; the registry stores
opaque public keys.

## Caching

After first derivation, store the derived keypair in IndexedDB keyed by
`(sui_address, scope, version, message_hash)`. The cache key includes the
message hash so that any change to the canonical message format invalidates
old entries automatically.

```text
db: whisper-keystore
  store: derived-keys
    key:   sha256(address || scope || version || message_bytes)
    value: { encryption_priv, encryption_pub, derived_at_ms }
```

On every page load:
1. Look up the cache entry.
2. If hit, use it without prompting.
3. If miss, prompt for one signature, derive, store.

IndexedDB is origin-scoped but accessible to any script on the origin —
see **Trade-offs** §10. The cache exists for UX; it is not a security
boundary.

## Rotation

Rotation is **versioning, not revocation**. Bumping `version: 2` in the
canonical message produces a new, unrelated encryption keypair derivable
from the same wallet. The user calls `register_encryption_key` again,
which increments `key_version` in the registry. New senders use v2; old
envelopes remain decryptable because the wallet can still re-derive v1 on
demand.

What rotation does **not** do: it does not destroy the old key. The math
of "deterministic function of wallet + message" forbids that. As long as
the wallet exists, `version: 1` is rederivable. See **Trade-offs** §8.

## Trade-offs

These are the costs of choosing this design. They are documented here so
future versions can revisit each one explicitly.

### Intrinsic — accept by choosing the design

**1. No forward secrecy.**
The encryption private key is a pure function of `(wallet_seed, message)`.
A wallet compromise reveals every encryption key ever derived under any
version, which decrypts every past message ever sent to that account.
Signal-style ratcheting prevents this by mixing fresh ephemeral randomness
into every message and discarding old key state — incompatible with the
"any device, anytime, no local state" property we are buying. If users
assume Whisper has Signal's privacy guarantees, they will be wrong about
the threat model. **Document prominently.**

**2. No deniability / repudiation.**
The encryption keypair is wallet-attributable by construction. A subpoena
to the user can compel re-derivation; "I lost the key" is not credible
because the wallet provably re-derives it. Acceptable for most users;
unsuitable for adversarial settings.

**3. Long-lived high-value secret.**
The signature bytes returned by the wallet are encryption key material,
not just authentication. Any code path that touches them — extension
memory, JS heap snapshots, debugger sessions, logs — is a potential leak
vector. This is structurally riskier than what wallets are designed for.
Mitigations: HKDF immediately after receipt, zeroize buffers, never
serialize the raw signature, never log it, never send it to any server.

**4. Cross-protocol entanglement.**
Two protocols with similar canonical messages can derive identical
encryption keys for the same user. The domain separator does real
security work, not hygiene. A bug in message construction (forgot the
address; bumped version but didn't change the bytes; wallet whitespace
normalization) doesn't fail loudly — it silently produces the wrong key,
or worse, the *same* key as some other dapp. Mitigation: lock the message
format byte-exactly, include address, include version, snapshot-test the
exact bytes the client sends.

**5. UX cost on first use.**
Every new device, cleared cache, browser profile, or incognito session
requires a wallet prompt. Wallets show "Sign Message" dialogs that look
indistinguishable from phishing. Some users will bounce at this step.
Cheaper than "import private key," more expensive than "just connect."

### Engineering — mitigatable, but real

**6. Wallet-scheme gating.**
Sui supports three signature schemes; only Ed25519 is deterministic by
spec. Implementation: read `keypair.getKeyScheme()` at registration,
refuse anything other than Ed25519, surface a clear error.

**7. Phishing surface.**
The MetaMask `eth_getEncryptionPublicKey` cautionary tale: a malicious
dapp asks the user to "sign in" with a string that matches Whisper's
canonical message. User signs, attacker derives victim's encryption key.
Mitigations (address in message, multi-line preview, version tag) reduce
but do not eliminate the attack — they require the phisher to be more
targeted. Wallet-side mitigations (visible message preview, origin
binding) are out of our control.

**8. Rotation is versioning, not revocation.**
Bumping the `version:` field gets you a new key going forward; it does
not retire the old one. Anyone who later compromises the wallet
re-derives every past version. Practical effect: rotation lets users
*move forward* cleanly but does not *destroy* old keys. Real revocation
requires either (a) a Signal-style ratchet, or (b) an independent
encryption keypair held outside the wallet.

**9. Wallet behavior drift.**
Sui's `signPersonalMessage` wraps bytes with a `PersonalMessage` intent
prefix. Different wallets, SDK versions, hardware wallets, and any future
signer must wrap byte-for-byte identically. Today this is solid. Future
hardware wallet that signs "raw bytes for compatibility" will silently
produce a different signature; users will be unable to decrypt their own
messages. Mitigation: snapshot-test the wrapped bytes against a known-good
fixture in CI; document that custom signers must replicate the intent
wrapping exactly.

**10. Caching tension.**
IndexedDB cache is required for tolerable UX. IndexedDB is accessible to
any script on the origin: an XSS in the dapp = encryption key theft.
Strict alternatives (re-derive every session; require passphrase to
unwrap cached key) trade UX for safety. The PoC ships with plain IndexedDB
caching and a documented XSS threat. Future work: passkey-wrapped cache,
or the keypair lives in a wallet-side feature (Phase 4 of
[wallet-bound-private-messaging.md](./wallet-bound-private-messaging.md)).

**11a. Path B inherits a second deterministic-signing dependency.**
When a wallet implements `misc:deriveSignature`, Whisper's correctness
depends on **two** byte-stable derivations — its own HKDF pipeline
and the wallet's internal identity-to-sub-key derivation. The wallet
spec mandates RFC-8032-compliant Ed25519 signing of a wallet-controlled
canonical envelope, so a spec-compliant wallet behaves identically
across machines. But a buggy or malicious implementation can silently
produce drift — different bytes on different devices — that would
look exactly like a wallet-signature-drift bug under Path A. Mitigation:
the wallet-side spec must include byte-stable test vectors (the Eve
Vault reference does); we should run those vectors as part of CI when
testing against a specific wallet build.

**11b. SDK does not currently verify Path B's wrapped envelope.**
`misc:deriveSignature` returns `{ bytes, signature, publicKey }`,
where `bytes` is the wallet's canonical envelope wrapping the dApp's
input plus scope and address. A spec-compliant wallet signs `bytes`
with the sub-key whose pubkey is `publicKey`. The SDK today HKDFs
only `signature` and ignores both `bytes` and `publicKey`. A malicious
wallet could return a signature it produced over a different envelope
than `bytes` claims — but this only matters if we plan to use `bytes`
as a security boundary (e.g. binding a derived key to an attested
scope). For the current "HKDF the signature into an X25519 seed" use
case, the trust boundary is "the wallet is honest about
deterministically signing for this user under this scope," which is
the same trust boundary every other path requires. A future hardening
step is to parse `bytes`, verify it embeds the dApp-supplied message,
scope, and address verbatim, and verify `signature` against `publicKey`
over `bytes` before HKDFing — at which point `publicKey` becomes
load-bearing and a malicious wallet has nowhere to hide. We have not
done this yet. See Future Work §8.

**11c. No runtime drift detection across calls.**
Whisper assumes the wallet returns byte-identical signatures every
time for the same `(identity, message)` (Path A) or `(identity, scope)`
(Path B). The SDK does not double-sign and compare; doing so would
double the wallet-prompt UX cost. If a wallet quietly becomes
non-deterministic — firmware update, plugin swap, an internal bug —
the user's encryption keypair silently rotates and past envelopes
become undecryptable until the regression is fixed and the user
re-signs. Mitigation today is the IndexedDB cache: the first
derivation is locked in as long as the cache survives. A future
hardening step would be opt-in periodic re-derivation against the
cache (re-sign once, compare, surface a warning on mismatch).

**11. Migrations are hard.**
Changing the derivation (post-quantum scheme, fixing a domain-separator
bug, swapping HKDF parameters) requires running both schemes in parallel
during a transition. Old envelopes decrypt with old derivation; new ones
use the new path. The registry tracks which is which via `key_version`
plus a `derivation_id` we will need to add. Doable; protocol overhead.

### What does **not** become a problem

For symmetry, common worries that are not real concerns:

- **Signature replay.** Determinism is the goal. Same `(sk, m)` always
  produces the same signature; this is required, not exploitable.
- **Key recovery from public messages.** Ciphertext + sender + recipient +
  derived public key leak no more about the private key than vanilla
  X25519 does.
- **Wallet "memory" of past signatures.** Wallets are stateless signers;
  the user can produce the same signature any number of times.

## Threat Model Summary

| Adversary                                  | Reads plaintext? |
|--------------------------------------------|------------------|
| Public chain observer                      | No               |
| Indexer                                    | No               |
| Other Whisper users                        | No               |
| Compromised wallet (now or later)          | **Yes — all past and future messages** |
| Phisher who tricks user into signing the canonical message | **Yes — all past and future messages** |
| XSS on the Whisper origin (cache scraped)  | All cached versions |
| Subpoena to the user                       | All versions, by compulsion |

The first three rows are the value Whisper delivers. The last four are
the cost of the design and must be visible in user-facing docs.

## Future Work

In rough order of payoff:

1. ~~**Snapshot test the canonical message.** Lock the byte sequence
   in a test fixture so accidental changes (whitespace, version bump
   without key bump) fail CI loudly.~~ **Done.** See
   `packages/wallet-derived-keys/src/__tests__/crossDevice.golden.test.ts`.
   The test pins golden X25519 public keys for both Path A and Path B
   against fixed identity + canonical message inputs, and re-derives
   the pipeline by hand to catch drift between spec and implementation.
2. **Passkey-wrapped IndexedDB cache.** Eliminates §10 in exchange for a
   passkey prompt on cold start.
3. **Optional ratchet layer.** A Signal-style double ratchet on top of
   the existing envelope, opt-in per conversation. Provides forward
   secrecy at the cost of state synchronization.
4. **Per-scope subkeys.** Use `scope: dm:0x…` to derive distinct
   encryption keys per conversation, so a single-conversation compromise
   doesn't leak everything.
5. **Wallet-standard feature for derivation.** Move derivation into the
   wallet itself (Phase 3/4 of the parent spec) so the dapp never sees
   the signature bytes.
6. **Cross-chain derivation.** Document per-chain rules (Ed25519 on Sui
   and Solana, Schnorr on Bitcoin, RFC-6979 ECDSA on Ethereum) for a
   future multi-chain Whisper.
7. **Post-quantum migration plan.** Define the `derivation_id` field and
   the parallel-decryption rules now, before we have envelopes that need
   migrating.
8. **Verify the Path B wrapped envelope.** Today the SDK trusts the
   wallet's signature without inspecting `bytes` or verifying
   `publicKey`. Hardening: parse `bytes`, assert it embeds the
   dApp-supplied message + scope + address verbatim, verify
   `signature` against `publicKey` over `bytes`, only then HKDF. Closes
   trade-off §11b.
9. **Opt-in drift detection across sessions.** Periodically re-sign
   the canonical message against the cached keypair and surface a
   warning on mismatch, so a wallet that became non-deterministic
   after an update is caught before users lose access. Closes
   trade-off §11c.

## Migration from the Current PoC

The earlier X25519/ChaCha PoC derived X25519 directly from Ed25519
seeds in a `web/src/crypto/identities.ts` module and a now-removed
`crates/secret-sharing-cli` Rust binary (deleted as the workspace
moved to the Baby Jubjub + Groth16 stack). The migration shape
documented here applies the same way to any future caller that
still does direct Ed25519→X25519 derivation:

1. Add a `deriveKeypairViaWalletSignature(suiAddress)` helper that builds
   the canonical message, calls `signPersonalMessage`, runs HKDF, and
   returns `{ encryption_priv, encryption_pub }`.
2. Replace the demo-key bootstrap with a one-time "derive my key" flow on
   first page load per address.
3. Remove the `.env` Ed25519-private path from the web client. The Rust
   CLI keeps the demo-key path for scripted testing, but is documented as
   not the production trust boundary.
4. Bump the `key_version` on the next registration so the new keypairs
   are unambiguously v2-or-higher; mark v1 entries as legacy demo-mode in
   the indexer.

The on-chain Move module and HKDF info string `sui-secret-sharing-poc-v1`
do **not** change — only the source of the X25519 seed. Existing
envelopes remain decryptable by anyone who can replay the old derivation
(i.e., still has the demo Ed25519 seed).
