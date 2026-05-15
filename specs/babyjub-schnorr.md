# Baby Jubjub Schnorr Signatures (`babyjub-schnorr-v1`)

This document specifies the Schnorr-style signature scheme used by the
protocol. Sign-a-field-element, deterministic nonce, Poseidon-based
challenge with `PK`-prefixing. Cross-language compatibility contract
between the Rust `crypto` crate, the WASM binding, and the TypeScript
SDK. Built on [`babyjub-curve.md`](./babyjub-curve.md),
[`babyjub-keypair.md`](./babyjub-keypair.md), and the protocol's shared
Poseidon parameters.

> **NOTE(name):** scheme tag `babyjub-schnorr-v1` and crate name
> `crypto` are working names. No product name baked in.

**Any implementation that does not reproduce the exact signature values
in [§ Worked Example](#worked-example) is incompatible with this scheme
and will not interoperate.**

## What this signs

A single field element `m ∈ F_p`. Not arbitrary bytes — that
composition (`bytes → m` via hashing) lives at the caller. The
canonical use cases inside the protocol all naturally produce a field
element to be signed: a Pedersen commitment value, an envelope handle,
a Poseidon hash of an opening, a stored on-chain object id reduced to
the field. Any byte-message signing layer must pick its own
byte-to-field encoding with its own domain tag.

## What this does NOT define

- **Sign-arbitrary-bytes.** Future composition. The caller's
  byte→field hashing has its own design surface (chunking, length,
  domain) that doesn't belong in the signature primitive.
- **Batch verification.** A few-percent speedup at most for this
  small-arity curve; not worth the API complication.
- **Multi-signature / threshold variants.** Separate primitives. The
  single-signer Schnorr construction here is the base case both build
  on, but neither is implemented.

## Construction

Given:

- `sk ∈ F_l` — signer's secret scalar (from
  [`babyjub-keypair.md`](./babyjub-keypair.md))
- `PK ∈ G` — signer's public key, `PK = sk · Base8`
- `m ∈ F_p` — message field element

### Sign

```text
sk_as_fq  = lift sk from F_l into F_p     (lossless: l < p)
k_fq      = Poseidon6(nonce_domain, sk_as_fq, m, 0, 0, 0)
k         = k_fq reduced into F_l         (mod-l reduction)
R         = k · Base8                                          // commitment point
c_fq      = Poseidon6(challenge_domain, R.x, R.y, PK.x, PK.y, m)
c         = c_fq reduced into F_l         (mod-l reduction)
s         = k + c · sk    mod l                                // response scalar
signature = (R, s)
```

### Verify

```text
c_fq = Poseidon6(challenge_domain, R.x, R.y, PK.x, PK.y, m)
c    = c_fq reduced into F_l
accept iff   s · Base8  ==  R + c · PK
```

## Design decisions, pinned

### Deterministic nonce (RFC 6979 style, with Poseidon)

The nonce `k` is derived from `(sk, m)` via Poseidon with its own
domain tag. No randomness enters signing. **This is a non-negotiable
security choice for Schnorr**: two signatures `(R, s₁)` and `(R, s₂)`
on different messages with the same `k` reveal `sk` instantly. Modern
practice (Ed25519, BIP-340, etc.) is to derandomise. The cost is
roughly one extra Poseidon call; the safety win is total elimination
of an entire failure class.

Padding to arity-6 with zeros is intentional: `poseidon6` is the only
arity this scheme uses (the challenge also needs 6 inputs), so reusing
it keeps the binary surface small. The domain tag distinguishes the
nonce hash from the challenge hash; a collision in padding positions
across the two uses is impossible by domain separation.

### Sign-one-field-element

Schnorr signs `m ∈ F_p`. The choice avoids baking a byte-message
encoding into the signature primitive. Real composition uses
field-element-shaped objects (commitment values, hashes, ids); the
primitive matches that shape directly.

### Domain-separated challenge

`c = Poseidon6(challenge_domain, R.x, R.y, PK.x, PK.y, m)`. The
domain tag prevents the same six field elements from collapsing to the
same hash across schemes — a hash used as both a signature challenge
and a commitment input, even with shared sub-inputs, would be a
cross-protocol oracle. The tag is the one bit of separation that costs
nothing and rules out an entire attack class.

### `PK` in the challenge (key prefixing)

Including `PK.x, PK.y` in the challenge hash prevents related-key
attacks where an adversary tries to repurpose a signature under a
different public key. Standard Schnorr-with-key-prefixing; BIP-340 does
this for the same reason.

### Field reductions

Two `F_p → F_l` reductions happen: one for `k` (after the nonce hash)
and one for `c` (after the challenge hash). Both go through
serialize-to-bytes + reduce-mod-`l`. The bias from `p` (~254 bits) to
`l` (~251 bits) on Poseidon-uniform input is ~2⁻²⁵¹, well below
cryptographic relevance. Same trick the keypair derivation uses; see
[`babyjub-keypair.md`](./babyjub-keypair.md).

## Domain tags

```text
nonce_domain     = "babyjub-schnorr-nonce-v1"
challenge_domain = "babyjub-schnorr-challenge-v1"
```

As reduced field elements:

```text
domain_tag("babyjub-schnorr-nonce-v1")     = 21729794174239755470552386574297440972213761608631578816820312365506580392985
domain_tag("babyjub-schnorr-challenge-v1") = 20573619326964626862733302371592070954063093901187322038069098498158339541676
```

The `-v1` suffixes reserve space for future tweaks (a different challenge
arity, a different padding rule, key compression in the challenge inputs)
without silently reusing the same scheme name.

## Wire form

A signature is `(R, s)` where `R` is an affine curve point and `s` is
an `F_l` scalar. The boundary representation matches the rest of the
protocol's conventions:

- `R.x` and `R.y` as base-10 decimal strings (the wire form pinned in
  [`babyjub-curve.md`](./babyjub-curve.md))
- `s` as a base-10 decimal string

Three strings per signature. A decoder accepting `(R, s)` from an
external source MUST validate `R` via `point_from_strings` (on-curve +
prime-subgroup) before verification — same hygiene rule every external
point gets.

## Worked Example

A conformant implementation reproduces every value below exactly.

### Signer keypair

Seed `0x07` followed by 63 × `0x00`. This is the same seed the unit
tests use, so the fixture and the unit tests cross-anchor.

```text
PK.x = 11164399029837664407055359313997844806901732622806579156125419783739925007983
PK.y = 14592084695496273113419456967406390983505872435887630137749651140392618556302
```

### Vector 1 — `m = 1`

```text
R.x = 11632351294401981618034412607960018633759132523604891111145083805962634408526
R.y = 16437810892664933023884131539764605025844133936197983566486350081488662891513
s   = 1812749329934557351717178747835822339686472044802696027660553171848252014907
```

### Vector 2 — `m = 123456789`

```text
R.x = 6375882820815417677096742276733849921405984769193898132545252656057555844260
R.y = 3047706727927232926540757222837094987678920983781058568722301670558932589075
s   = 1672146590325984867501175997505308325917192911330920320014368257217536359444
```

### Vector 3 — `m = 2^240 = 1766847064778384329583297500742918515827483896875618958121606201292619776`

```text
R.x = 1395873755850300180104726848613996444071352053794302031425716596821856303738
R.y = 20526401082777560701041724606565419033104885953699580911324980591395500280786
s   = 2581033176336945103238693484339366247360111711785418479474279938072861984860
```

A conformant implementation MUST also accept each `(R, s)` above as a
valid signature on its message, and MUST reject any single-component
tampering — change `m`, `R`, `s`, or the verifying `PK` and verify
fails.

## Validity contracts

A conformant implementation MUST:

- **Reject signatures whose `R` is not in the prime-order subgroup.**
  An off-subgroup `R` is the wire-decoded entry point for
  subgroup-confinement attacks. The Rust crate enforces this by
  requiring `R` to arrive via `point_from_strings` at the boundary.
- **Not transmit `sk` or the derived nonce `k` across language
  boundaries.** Both are sensitive. The WASM `sign()` entry point
  takes the signer's 64-byte seed and re-derives `sk` and `k`
  internally; neither is exposed.
- **Treat the signature `(R, s)` as fully public.** No part of the
  signature value is sensitive — only the secret key that produced it.

## References

- [`babyjub-curve.md`](./babyjub-curve.md) — the curve everything
  lives on.
- [`babyjub-keypair.md`](./babyjub-keypair.md) — how `sk` and `PK` are
  derived from a seed.
- [`poseidon-commitment-format.md`](./poseidon-commitment-format.md) —
  same Poseidon parameter set, same `bytes_to_field_be(Blake2b256(domain))`
  domain-tag construction.
- BIP-340 (Schnorr Signatures for secp256k1) — for the
  key-prefixing-in-challenge and the deterministic-nonce rationale.
  This scheme is the same idea over Baby Jubjub with Poseidon
  challenges and a `F_p` message.
