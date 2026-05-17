# Baby Jubjub MAC (`babyjub-mac`)

This document specifies the message authentication code used by the
protocol to bind integrity to field-element streams under a key
derived from ECDH+KDF. Cross-language compatibility contract between
the Rust `crypto` crate, the WASM binding, and the TypeScript SDK.
Built on [`poseidon-hash-sponge.md`](./poseidon-hash-sponge.md) and
consumes keys produced by [`babyjub-kdf.md`](./babyjub-kdf.md).

> **NOTE(name):** scheme tag `babyjub-mac` and crate name `crypto`
> are working names. No product name baked in.

**Any implementation that does not reproduce the exact field-element
values in [§ Worked Example](#worked-example) is incompatible with
this scheme.**

## What this is

A pair of functions:

```text
mac(key: Fq, message: Fq*) -> Fq
verify(key: Fq, message: Fq*, tag: Fq) -> bool
```

operating on streams of base-field elements. The MAC is a keyed
sponge: absorb the key as the first input, then the message, then
squeeze one field element as the tag.

```text
tag = Poseidon-hash-sponge(mac_domain, [key, m_0, m_1, ..., m_{n-1}])
```

One `Fq` tag regardless of message length. No length cap.

## What this is FOR

Authenticating the ciphertext output of `babyjub-cipher` under a key
derived from an ECDH+KDF handshake. Pairs with `babyjub-cipher` to
form an authenticated envelope: **encrypt-then-MAC**.

```text
key_enc  = babyjub-kdf(shared, [ENC_ROLE_TAG, envelope_id])
key_mac  = babyjub-kdf(shared, [MAC_ROLE_TAG, envelope_id])
ct       = babyjub-cipher.encrypt(key_enc, plaintext)
tag      = babyjub-mac.mac(key_mac, ct)
envelope = (ct, tag)
```

A recipient who knows `shared` (the ECDH peer) can re-derive both
keys, verify the tag, and on success decrypt. A tag-verification
failure means "do not decrypt" — the recipient learns that the
ciphertext was tampered with or was never genuine without revealing
*what* the plaintext would have been.

The construction is deliberately ZK-native:

- **Sponge over Poseidon-3.** Variable-length input absorbed with
  rate `r=2` capacity `c=1`. No fixed-arity ceiling on the message;
  ciphertexts of any length authenticate.
- **One tag field element.** ZK predicates that prove "the envelope
  was authenticated by the holder of `key_mac`" check one field
  equality, not a hash chain.

## What this is NOT

- **Confidential.** A MAC authenticates; it does not encrypt. The
  message is absorbed in plaintext into the sponge. Pair with
  `babyjub-cipher` (encrypt-then-MAC) for any application where
  message contents must remain private.
- **A signature.** Anyone with `key` can produce *or* verify a tag.
  A MAC binds integrity within a pair that shares a key; it does
  not prove "this came from a specific identity" the way a Schnorr
  signature does.
- **Replay-protected on its own.** A `(message, tag)` pair stays
  valid forever under its key. Replay protection comes from
  binding per-message material (envelope id, counter) into the
  *key* via the KDF context — so a tag for envelope 42 cannot
  replay against envelope 43 because the keys differ.

## Construction

```text
mac_domain = bytes_to_field_be(Blake2b-256("babyjub-mac"))

mac(key, [m_0, ..., m_{n-1}]) = poseidon_hash_sponge(
    mac_domain,
    [key, m_0, m_1, ..., m_{n-1}],
)

verify(key, message, tag) = (mac(key, message) == tag)
```

The key is the **first** rate-slot input. The sponge state is
initialized with `mac_domain` folded into the capacity row at
position 0, then absorption proceeds: `key` lands at rate position
0 in the first absorbed block, the message follows.

## Length

- **No cap.** The sponge absorbs arbitrary-length input; each
  absorption block is one Poseidon-3 permutation.
- **Tag is always one `Fq` element.**
- **Empty message is valid** and produces a per-key constant tag
  (`poseidon_hash_sponge(mac_domain, [key])`).

## Domain tag

```text
domain_string = "babyjub-mac"
domain_tag    = bytes_to_field_be(Blake2b-256("babyjub-mac"))
```

Distinct from `babyjub-stream-cipher`, so a `(key, stream)` MAC'd
in this role cannot collide with the same `(key, stream)` keystream
in the cipher role.

## Worked Example

A conformant implementation reproduces every value below exactly.

### Key

Reuses the MAC key from
[`babyjub-kdf.md`](./babyjub-kdf.md) Vector 3 — derived from the
Alice/Bob ECDH shared point under the `envelope-mac-key` role with
envelope id 42:

```text
key = 5302105009719633730025155498822445041452574923386899996802294480945238328306
```

### Vector 1 — empty message

```text
message = []
tag     = 13976129352745355852952122427372408395772002964442343488572190579262395794749
```

The empty edge case. Sponge absorbs only the key, then squeezes.

### Vector 2 — single zero element

```text
message = [0]
tag     = 83483476632619605001810600041749983961166824905670904509823254115267351440
```

### Vector 3 — small structured message

```text
message = [1, 2, 3, 4]
tag     = 19959040651903833489024164256692762142561345502386131858898218371248838287538
```

### Vector 4 — 9-element message

A 9-element message, matching the canonical encoded-text size from
`text-utf8-v1`. No structural significance — the MAC has no length
cap.

```text
message = [1, 2, 3, 4, 5, 6, 7, 8, 9]
tag     = 21372504646644668171584038078143205540789048079810990041830821947945838102294
```

### Vector 5 — MAC over a canonical ciphertext

The encrypt-then-MAC envelope use case. The message here is the
ciphertext from
[`babyjub-cipher.md`](./babyjub-cipher.md) Vector 3 (plaintext
`[1, 2, 3, 4]` encrypted under the cipher-role key for envelope
42):

```text
message = [
  10787321779190226554676337514347691875659477298610453494316095697639731105525,
  11005131623232030623906867189653141067415173065234117331769608574160093139922,
  11791314040563090199526129580738560103220176213914809365331933459954108858858,
  7865039964291077852173468667319105421171640084683400461629880408575490986497,
]
tag     = 16162720997808794646235033165738484245710842752524771795771394985271256269398
```

This is the value a recipient checks to authorize decrypting that
ciphertext under the cipher-role key for envelope 42.

### Vector 6 — same message, cipher-role key

The cross-construction differentiator. Same message as Vector 3,
but tagged under the **cipher-role** key for envelope 42 (KDF
Vector 2):

```text
key     = 9799522521534548758133939899702695884003167902663631833387651174524282263857
message = [1, 2, 3, 4]
tag     = 4052831540585470231953709742711952097170537538075536978551751398089530481570
```

**MUST differ from Vector 3** — different keys produce different
tags. (In practice the cipher-role key would never be used as a
MAC key; this vector exists to pin the key-dependence property.)

## Validity contracts

A conformant implementation MUST:

- **Always emit one `Fq` tag**, regardless of message length. The
  empty message is valid.
- **Absorb the key as the first input**, immediately after the
  domain tag is folded into capacity. Any other key placement
  produces a different MAC scheme.
- **Use `poseidon_hash_sponge`** with the domain tag fixed by this
  spec. The fixed-arity variant is a different hash function and
  would mint a different MAC.
- **Verify by recomputation and field equality.** No partial
  computation, no early exit on per-byte mismatch.
- **Treat the key as sensitive.** Same hygiene as the secret-key
  path; same level of secrecy as the cipher key.
- **Treat tag-verification failure as fatal for downstream
  consumers.** A recipient that decrypts a ciphertext whose MAC
  failed has voluntarily exposed itself to forgery. The MAC's
  contract is "do not proceed."
- **Match every pinned vector byte-for-byte.**

## References

- [`babyjub-kdf.md`](./babyjub-kdf.md) — produces the key.
- [`babyjub-cipher.md`](./babyjub-cipher.md) — the confidentiality
  primitive this MAC pairs with in an authenticated envelope.
- [`poseidon-hash-sponge.md`](./poseidon-hash-sponge.md) — the
  underlying variable-length hash.
- HMAC (RFC 2104) — the canonical Western-stack MAC; this scheme
  is the keyed-sponge analogue (key absorbed as the first input,
  one squeeze emitted) over circuit-friendly Poseidon.
- KMAC (NIST SP 800-185) — the Keccak-sponge MAC; the construction
  here is the same shape over a Poseidon sponge.
