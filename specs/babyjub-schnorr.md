# Baby Jubjub Schnorr Signatures (`babyjub-schnorr`)

This document specifies the Schnorr-style signature scheme used by
the protocol: a deterministic Schnorr over Baby Jubjub that signs a
**stream of field elements** as its message. Cross-language
compatibility contract between the Rust `crypto` crate, the WASM
binding, and the TypeScript SDK. Built on
[`babyjub-curve.md`](./babyjub-curve.md),
[`babyjub-keypair.md`](./babyjub-keypair.md),
[`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md).

> **NOTE(name):** scheme tag `babyjub-schnorr` and crate name
> `crypto` are working names. No product name baked in.

**Any implementation that does not reproduce the exact signature
values in [§ Worked Example](#worked-example) is incompatible with
this scheme and will not interoperate.**

## What this signs

A **stream** of field elements `message ∈ F_p^n` with `0 ≤ n ≤
MAX_MESSAGE_LEN`. The protocol's stream-shaped encodings (see
[`encodings/README.md`](./encodings/README.md)) produce exactly this
shape: a `text-utf8-v1` encoded payload is 9 field elements, well
under the cap. Signing the encoding's output directly preserves the
structure into the signature without an intermediate
hash-and-then-sign step.

```text
MAX_MESSAGE_LEN = 11
```

The cap comes from the fixed-arity Poseidon ceiling: the message
hash is one `Poseidon-(1+n)` call, and `light-poseidon`'s shipped
circomlib parameters cap at total arity 12 (= 1 domain + 11
payload). Beyond that, a future variant would either chunk-and-
chain the message hash or use the sponge — both are different
schemes and mint their own spec. Keeping this one ceiling-bound
means the in-circuit message hash is one permutation, no branching.
Same ZK-friendliness discipline as
[`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md).

## What this does NOT define

- **Sign-arbitrary-bytes.** The caller hashes bytes to a field-element
  stream via an encoding from `crates/encodings/*`, then signs the
  stream.
- **Long messages** (length > 11). A future `babyjub-schnorr-long` or
  similar would mint a new spec and use a different message-hash
  construction (sponge, or chunked fixed-arity).
- **Batch verification.** A few-percent speedup at most for this
  small-arity curve; not worth the API complication.
- **Threshold / multi-signature variants.** Separate primitives.

## Construction

Given:

- `sk ∈ F_l` — signer's secret scalar (from
  [`babyjub-keypair.md`](./babyjub-keypair.md))
- `PK ∈ G` — signer's public key, `PK = sk · Base8`
- `message ∈ F_p^n` — message stream of length `n ≤ MAX_MESSAGE_LEN`

### Sign

```text
m_hash      = Poseidon-hash-fixed(message_domain, message)
sk_as_fq    = lift sk from F_l into F_p     (lossless: l < p)
k_fq        = Poseidon-hash-fixed(nonce_domain, [sk_as_fq, m_hash])
k           = k_fq reduced into F_l         (mod-l reduction)
R           = k · Base8                                                  // commitment point
c_fq        = Poseidon-hash-fixed(challenge_domain, [R.x, R.y, PK.x, PK.y, m_hash])
c           = c_fq reduced into F_l         (mod-l reduction)
s           = k + c · sk    mod l                                        // response scalar
signature   = (R, s)
```

### Verify

```text
m_hash = Poseidon-hash-fixed(message_domain, message)
c_fq   = Poseidon-hash-fixed(challenge_domain, [R.x, R.y, PK.x, PK.y, m_hash])
c      = c_fq reduced into F_l
accept iff   s · Base8  ==  R + c · PK
```

A conformant implementation MUST reject messages of length > 11
with a typed length error from both `sign` and `verify`. (See the
[`poseidon-hash-fixed`](./poseidon-hash-fixed.md) error contract —
the message hash's `ArityOutOfRange` propagates as `MessageTooLong`
here.)

## Design decisions, pinned

### Hash-then-include

The message stream is collapsed to a single field element via
`Poseidon-hash-fixed(message_domain, message)` before it enters the
nonce and challenge hashes. The challenge hash itself stays at fixed
arity 6 (1 domain + 5 inputs: `R.x, R.y, PK.x, PK.y, m_hash`)
regardless of message length. This means:

- A 9-field message and a 33-field message would sign through the
  **same circuit shape** (once the long-message variant exists) —
  only the message-hash witness differs.
- The verifier's circuit is parametric in message length without
  any constraint-count branching.
- Two cheap Poseidon calls instead of one big one: negligible
  signing cost, big in-circuit-uniformity win.

### Deterministic nonce (RFC 6979 / BIP-340 style)

The nonce `k` is derived from `(sk, m_hash)` via Poseidon with its
own domain tag. No randomness enters signing. This is the
**non-negotiable** security choice for Schnorr: two signatures
sharing a nonce reveal `sk` instantly. Modern practice (Ed25519,
BIP-340) is to derandomise; the cost is one Poseidon call and the
safety win is the elimination of an entire failure class.

### Three distinct domain tags

`message_domain`, `nonce_domain`, `challenge_domain` — so the three
internal hashes are syntactically and semantically distinct.
Cross-protocol oracle risk goes to zero: even with colliding
payload inputs, the hashes can't be misused as one another.

### `PK` in the challenge (key prefixing)

The challenge includes `PK.x` and `PK.y`. Standard
Schnorr-with-key-prefixing — prevents related-key attacks where an
adversary tries to repurpose a signature under a different public
key. BIP-340 does this; same reasoning here.

### Field reductions

Two `F_p → F_l` reductions happen: one for `k` (after the nonce
hash) and one for `c` (after the challenge hash). Both via
serialize-to-bytes + reduce-mod-`l`. The bias from `p` (254 bits) to
`l` (251 bits) on Poseidon-uniform input is `~2⁻²⁵¹`, far below
cryptographic relevance.

## Domain tags

```text
message_domain   = "babyjub-schnorr-message"
nonce_domain     = "babyjub-schnorr-nonce"
challenge_domain = "babyjub-schnorr-challenge"
```

As `Fq` field elements (via `bytes_to_field_be(Blake2b-256(string))`,
the same construction every protocol spec uses):

```text
message_domain   = 4959039381246480768649712740131367318031820083426683321809849078165270134540
nonce_domain     = 13553819876672115371529980418111891239725968071633845505629858202683350719118
challenge_domain = 15418927958364043498621237258658947106658773105201138129987459449759031421787
```

## Wire form

A signature is `(R, s)` where `R` is an affine curve point and `s`
is an `F_l` scalar. Boundary representation:

- `R.x` and `R.y` as base-10 decimal strings
- `s` as a base-10 decimal string

Three strings. A decoder accepting `(R, s)` from an external source
MUST validate `R` via `point_from_strings` (on-curve +
prime-subgroup) before verification.

## Worked Example

A conformant implementation reproduces every value below exactly.

### Signer keypair

Seed `0x07` followed by 63 × `0x00`. Same seed the keypair fixture
uses (and the previous Schnorr fixture used), so the keypair value
is unchanged across the migration:

```text
PK.x = 11164399029837664407055359313997844806901732622806579156125419783739925007983
PK.y = 14592084695496273113419456967406390983505872435887630137749651140392618556302
```

### Vector 1 — empty message

```text
message = []
R.x = 19672181936203324131656225559501475555772993461869651448031019731729494125516
R.y = 13566859200123542336948177722573650541027744755873253525080581171534205128273
s   = 585729486597474274390090641694341699325329864890452131536921756383744534588
```

The empty message hashes to a per-domain constant
(`Poseidon-1(message_domain)`), so this vector pins the "no
content" baseline.

### Vector 2 — single-element message

```text
message = [42]
R.x = 14463837123490585712352081519964757127730117503535410223157071561987752976040
R.y = 14835801757202602810496014359609043970705906585033731611275274330266563989628
s   = 1470727944428070892525141747972223984368576545003202506760627628426109537509
```

The single-element case demonstrates that signing `[42]` is **not**
equivalent to signing the bare field element `42` in the previous
(scalar) construction — `m_hash` is `Poseidon-2(message_domain,
42)`, not `42`. Migration is a breaking change; existing signatures
from the prior scheme do not verify under this one.

### Vector 3 — three-element message

```text
message = [1, 2, 3]
R.x = 4421583882441814884919433367012339810780463461595955860104800629341428551515
R.y = 685556324815791047742857456106268926562746442722529319403820029970894328632
s   = 2480202173437343318607319337411596044484259619894416475763013773164119271331
```

### Vector 4 — `text-utf8-v1`-shaped message (9 elements)

```text
message = [0, 1, 2, 3, 4, 5, 6, 7, 8]
R.x = 9907919187759728836420608685439673743018415908584274981339045984432314418876
R.y = 14320670493132427095800905404319123040028993772245066136630070019717299866336
s   = 690166825546950374194223969053258468670318750960230750355004980014353065874
```

This vector represents the canonical protocol use: a `text-utf8-v1`
encoded payload (9 field elements) signed directly without external
collapse. The signing circuit shape is the same for this vector and
the 11-element vector below; only the message-hash witness differs.

### Vector 5 — maximum-length message (11 elements)

```text
message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
R.x = 19963310545348971650786133235255750555652125687870187620843360496751874600702
R.y = 1299550255739614117019408363067734689527566129196823495220357367769924437828
s   = 531332205057006653850069745815249283082797922145794081647360253109887423674
```

The cap. A 12-element message produces `MessageTooLong { len: 12,
max: 11 }` from both `sign` and `verify`. A conformant
implementation MUST surface this as a typed error, not silently
truncate.

## Validity contracts

A conformant implementation MUST:

- **Reject messages of length > 11** with a typed length error, in
  both `sign` and `verify`. The empty message is valid.
- **Reject signatures whose `R` is not in the prime-order subgroup.**
  Wire decoders MUST enforce this before `R` reaches `verify`.
- **Reject signatures whose `R` is not on the curve.** Same wire
  decoder.
- **Treat the signature `(R, s)` as fully public.** No part of the
  signature value is sensitive — only the secret key.
- **Not transmit `sk` or the derived nonce `k` across language
  boundaries.** The WASM `sign` entry point takes the signer's
  64-byte seed and re-derives `sk` and `k` internally; neither is
  exposed.

## References

- [`babyjub-curve.md`](./babyjub-curve.md) — the curve.
- [`babyjub-keypair.md`](./babyjub-keypair.md) — keypair derivation.
- [`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md) — the
  underlying hash, including the arity-12 cap that determines
  `MAX_MESSAGE_LEN`.
- BIP-340 (Schnorr Signatures for secp256k1) — for the key-prefixing
  and deterministic-nonce rationale. This scheme is the same idea
  over Baby Jubjub with Poseidon hashes and a field-element stream as
  the message.
