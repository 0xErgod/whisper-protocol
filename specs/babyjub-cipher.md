# Baby Jubjub Stream Cipher (`babyjub-cipher`)

This document specifies the symmetric stream cipher used by the
protocol to encrypt field-element streams under a key derived from
ECDH+KDF. Cross-language compatibility contract between the Rust
`crypto` crate, the WASM binding, and the TypeScript SDK. Built on
[`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md) and consumes
keys produced by [`babyjub-kdf.md`](./babyjub-kdf.md).

> **NOTE(name):** scheme tag `babyjub-cipher` and crate name `crypto`
> are working names. No product name baked in.

**Any implementation that does not reproduce the exact field-element
values in [§ Worked Example](#worked-example) is incompatible with
this scheme.**

## What this is

A pair of functions:

```text
encrypt(key: Fq, plaintext: Fq*) -> Fq*
decrypt(key: Fq, ciphertext: Fq*) -> Fq*
```

operating on streams of base-field elements. The cipher is a
keystream construction: for each position `i`, derive a keystream
element from `(key, i)` via one fixed-arity Poseidon call, and
combine with the plaintext element by field addition.

```text
keystream_i = Poseidon-hash-fixed(cipher_domain, [key, i])
ciphertext_i = plaintext_i + keystream_i   (mod p)
plaintext_i  = ciphertext_i - keystream_i  (mod p)
```

Same shape in and out: `|ciphertext| == |plaintext|`. No length cap
on the stream — each Poseidon call is independent.

## What this is FOR

Encrypting the field-element output of the encoding layer
(`text-utf8-v1`, future structured encodings) under a key derived
from an ECDH+KDF handshake. Pairs with `babyjub-mac` to form an
authenticated envelope: encrypt-then-MAC.

The construction is deliberately ZK-native:

- **One constraint per element**, not one per bit. Field addition
  costs a single R1CS constraint; an XOR-style cipher costs roughly
  one constraint per bit of the field element.
- **Per-position addressable keystream.** `keystream_i` depends
  only on `(key, i)`. A future ZK predicate proving "the i-th
  plaintext element equals X given the i-th ciphertext element"
  reads exactly one keystream slot — no chain to follow.
- **Fixed-arity Poseidon per call site.** Arity is always 3 (domain
  + key + counter), independent of stream length.

## What this is NOT

- **Authenticated.** A stream cipher provides confidentiality, not
  integrity. An attacker who knows or guesses `plaintext_i` can
  tamper with `ciphertext_i` to flip the plaintext arbitrarily.
  Pair with `babyjub-mac` (encrypt-then-MAC) for any application
  where integrity matters — which is essentially all of them.
- **Nonced.** The cipher does NOT carry a per-message nonce of its
  own. Key-uniqueness per message is the **caller's responsibility**
  and the canonical way to enforce it is via the KDF: derive a
  fresh key per envelope by including an envelope identifier in
  the KDF context. See [`babyjub-kdf.md`](./babyjub-kdf.md).
- **Bit-confidential.** The cipher hides field-element *values*,
  not bit patterns *within* values. For our use case (encrypted
  encoded streams) this is the right granularity; byte-oriented
  XOR ciphers are at a different abstraction level.

## Construction

```text
cipher_domain = bytes_to_field_be(Blake2b-256("babyjub-stream-cipher"))

keystream_at(key, i) = poseidon_hash_fixed(
    cipher_domain,
    [key, Fq::from(i as u64)],
)

encrypt(key, [p_0, ..., p_{n-1}]) = [p_i + keystream_at(key, i)]_{i=0..n}
decrypt(key, [c_0, ..., c_{n-1}]) = [c_i - keystream_at(key, i)]_{i=0..n}
```

The counter `i` is encoded as `Fq::from(i as u64)` — a small
non-negative integer in the base field. The full Poseidon call is
arity 3 (domain + key + counter).

## Length

- **No cap.** The cipher iterates per element; each Poseidon call
  is fixed-arity 3.
- **`|ciphertext| == |plaintext|`.** Length-preserving. The empty
  plaintext encrypts to the empty ciphertext.

## Domain tag

```text
domain_string = "babyjub-stream-cipher"
domain_tag    = bytes_to_field_be(Blake2b-256("babyjub-stream-cipher"))
```

## Worked Example

A conformant implementation reproduces every value below exactly.

### Key

Reuses the cipher key from
[`babyjub-kdf.md`](./babyjub-kdf.md) Vector 2 — derived from the
Alice/Bob ECDH shared point under the `envelope-cipher-key` role
with envelope id 42:

```text
key = 9799522521534548758133939899702695884003167902663631833387651174524282263857
```

### Vector 1 — empty stream

```text
plaintext  = []
ciphertext = []
```

The empty edge case. Length-preserving.

### Vector 2 — single zero element

Exposes `keystream_0` directly: `ciphertext_0 = 0 + keystream_0 = keystream_0`.

```text
plaintext  = [0]
ciphertext = [10787321779190226554676337514347691875659477298610453494316095697639731105524]
```

This value is exactly `keystream_at(key, 0)` — useful as an audit
probe.

### Vector 3 — small structured stream

```text
plaintext  = [1, 2, 3, 4]
ciphertext = [
  10787321779190226554676337514347691875659477298610453494316095697639731105525,
  11005131623232030623906867189653141067415173065234117331769608574160093139922,
  11791314040563090199526129580738560103220176213914809365331933459954108858858,
  7865039964291077852173468667319105421171640084683400461629880408575490986497,
]
```

Note `ciphertext[0]` is exactly `vector_2_ciphertext[0] + 1` —
shared keystream at position 0.

### Vector 4 — 9-element stream

The canonical encoded-text size from `text-utf8-v1`. No structural
significance to the length 9 here; the cipher has no length cap.

```text
plaintext  = [1, 2, 3, 4, 5, 6, 7, 8, 9]
ciphertext = [
  10787321779190226554676337514347691875659477298610453494316095697639731105525,
  11005131623232030623906867189653141067415173065234117331769608574160093139922,
  11791314040563090199526129580738560103220176213914809365331933459954108858858,
  7865039964291077852173468667319105421171640084683400461629880408575490986497,
  2229138201795589665836767366228584476563000856384984963522822284776068932630,
  11702069139758725090303111831331195321446015655716158873298318997122786844126,
  21827964982986497021603458608987397530066910094307594093465521210581113049125,
  5740201568618975964672094667205897157857936348884108865070928080450242112246,
  6187684344249448887322373286095556400810738367783748855733293931088165175507,
]
```

The first four elements match Vector 3's ciphertext exactly —
position-dependent keystream, position-only dependence.

### Vector 5 — same plaintext, different key

Same plaintext as Vector 3, but encrypted under the MAC-role key
for envelope 42 (KDF Vector 3):

```text
key        = 5302105009719633730025155498822445041452574923386899996802294480945238328306
plaintext  = [1, 2, 3, 4]
ciphertext = [
  16506928987906569383944781504684601770814262391889970105684093521341732525754,
  7731186885346303069632096810963599601471099092800449051344926221212941321164,
  16960104434118179033056841776385404401539280326058795617003206515921385327816,
  9750714252119089106587215089218327748956786451850137551892779329943517333788,
]
```

**MUST differ from Vector 3 element-for-element** — different keys
produce different keystreams. (In practice you would never use the
MAC-role key as a cipher key; this vector exists only to pin the
key-dependence property.)

## Validity contracts

A conformant implementation MUST:

- **Preserve length.** `|encrypt(k, p)| == |p|`. The empty stream
  is valid and produces the empty ciphertext.
- **Round-trip.** `decrypt(k, encrypt(k, p)) == p` for every key
  and every plaintext.
- **Use field addition mod `p`**, NOT bitwise XOR or any byte-level
  operation.
- **Use `Fq::from(i as u64)` as the counter.** Not little-endian
  bytes, not a field-encoded big-int — the direct field-element
  embedding of the `usize` index.
- **Never silently truncate.** There is no length cap, so this
  doesn't come up — but the contract is "iterate the full input."
- **Treat the key as sensitive.** Same hygiene as the secret-key
  path.
- **Match every pinned vector byte-for-byte.**

## References

- [`babyjub-kdf.md`](./babyjub-kdf.md) — produces the key.
- [`poseidon-hash-fixed.md`](./poseidon-hash-fixed.md) — the
  underlying keystream hash.
- [`babyjub-mac.md`](./babyjub-mac.md) — the integrity primitive
  this cipher pairs with in an authenticated envelope. (To be
  specified next.)
- ChaCha20 (RFC 8439) — the canonical Western-stack counter-mode
  stream cipher; this scheme is the same idea (per-position
  keystream from a PRF on `(key, counter)`) over the protocol's
  circuit-friendly primitives, with field addition replacing XOR.
