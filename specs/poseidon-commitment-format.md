# Poseidon-BN254 Commitment Format (`poseidon-bn254-circomlib-v1`)

This document specifies the ZK-friendly commitment hash scheme used by Whisper Protocol commitments tagged with `hash_scheme = "poseidon-bn254-circomlib-v1"`. It is the cross-language compatibility contract between the TypeScript SDK and any future Rust prover/verifier built on `arkworks-rs`.

**Any implementation that does not produce the exact hash byte values listed in [§ Worked Example](#worked-example) is incompatible with this scheme.**

## Why this exists

Whisper's default commitment hash is Blake2b-256 (scheme: `blake2b-256`). Blake2 is fast on CPUs but expensive inside ZK circuits: a single Blake2b hash inside a Groth16 circuit is ~100,000+ R1CS constraints. The first ZK predicate Whisper plans to support is *"I know an opening for this commitment"*, which is fundamentally `H(domain, secret, salt) == commitment` checked inside a circuit. Blake2-flavored versions of that proof are usable but expensive.

Poseidon is a hash function designed for prime-field arithmetic. Inside a BN254 Groth16 circuit, Poseidon costs ~200–300 R1CS constraints — about 500× cheaper than Blake2b for the same purpose. The trade-off is brutal in the opposite direction: Poseidon is materially slower than Blake2b in software (rough order of magnitude). For commitments where the prover later wants to write an "I know the opening" proof, Poseidon is the right primitive. For commitments that will only ever be opened publicly, Blake2b is faster.

Whisper supports both. This document specifies the Poseidon variant.

## Parameter set

We use **Poseidon over the BN254 scalar field with circomlib parameters**.

- **Field**: BN254 scalar field, prime `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`. Same field as the BN254 curve used by Sui's `sui::groth16::verify_groth16_proof` precompile.
- **Parameter set**: circomlib (`circomlibjs`'s `poseidon`). Specifically, the parameters used by [`poseidon-lite`](https://www.npmjs.com/package/poseidon-lite), which mirrors circomlib bit-for-bit.
- **Permutation arity**: `t = 13`. The TS implementation calls `poseidon12(inputs)` (12 inputs, 1 output, total state size 13). All implementations must use these exact round constants and MDS matrix.

### Why circomlib over arkworks-default

`ark-crypto-primitives::sponge::poseidon` does not, by default, match circomlib. Round constants and MDS matrices were generated differently. The Rust prover must instantiate `PoseidonSponge` with circomlib's constants explicitly — references like [`light-poseidon`](https://crates.io/crates/light-poseidon) provide drop-in circomlib parameter tables.

We picked circomlib because it's the de facto standard in the JS/EVM ZK ecosystem (Semaphore, RLN, Tornado Cash, zkLogin proofs that wallets emit) and because it has been examined by far more cryptographers than arkworks-defaults have.

## Commitment hash construction

Inputs to the commitment scheme:

- `encoded_secret`: variable-length UTF-8 byte string with line endings normalized to `\n`. Maximum length: **256 bytes**.
- `salt`: exactly 32 random bytes.

The hash is `poseidon12([f0, f1, f2, c0, c1, c2, c3, c4, c5, c6, c7, c8])` where the 12 inputs are field elements derived as follows:

### `f0` — domain field

A constant derived once:

```
f0 = bytes_to_field_be( Blake2b256("sui-secret-commitment-v1") )
```

The Blake2b digest is interpreted as a 32-byte big-endian unsigned integer and reduced modulo `p`. The "sui-secret-commitment-v1" string is the same domain tag the Blake2b-256 commitment scheme uses, ensuring the same domain semantics across hash schemes.

**`f0` value (constant)**: `0x15acf9be01a30fd2b8298af5cab2f90c84e8fb388ae253ebb8911cf98f421306`

### `f1` — secret length field

The byte length of `encoded_secret` as a field element:

```
f1 = BigInt(encoded_secret.length)
```

Always less than `MAX_POSEIDON_SECRET_BYTES = 256`, so always less than `p`. Including the length distinguishes `"foo"` from `"foo\0\0\0..."` — essential since the chunking pads with zeros.

### `f2` — salt field

```
f2 = bytes_to_field_be(salt) mod p
```

The 32-byte salt is interpreted as a big-endian 256-bit integer and reduced modulo `p`. Since `p` is ~254 bits, the top 2 bits of the 256-bit salt are masked away by reduction. Acceptable because the salt is uniform random — the effective entropy is still ≥ 254 bits.

### `c0` … `c8` — secret chunks

`encoded_secret` is split into 9 chunks of 31 bytes each. Each chunk is interpreted as a 31-byte big-endian unsigned integer (always fits in BN254 since 31 × 8 = 248 < 254).

```
for i in 0..9:
    chunk_bytes = encoded_secret[31i .. 31(i+1)]   # zero-pad on the right
                                                    # if encoded_secret runs out
    c_i = bytes_to_field_be(chunk_bytes)
```

If `encoded_secret` is shorter than `31 * 9 = 279` bytes (which it always is, since we cap at 256), the missing bytes in the last partial chunk and any unused later chunks are zero-padded.

### Output serialization

`poseidon12` returns a single field element. Serialize it as 32 big-endian bytes:

```
commitment_bytes = field_to_bytes_be(poseidon12_output)
```

The output is always exactly 32 bytes. This matches Blake2b-256's output width, so the same on-chain `commitment: vector<u8>` field accepts both schemes interchangeably.

## Reference TypeScript implementation

`packages/sdk/src/hash-poseidon.ts` contains the canonical reference. Key code paths:

- `bytesToFieldBe(bytes)` — big-endian byte string to `bigint`, reduced mod `BN254_FIELD_MODULUS`.
- `fieldToBytesBe(value)` — `bigint` to 32 big-endian bytes.
- `packSecretChunks(encodedSecret)` — produces the 9 chunk fields with right-zero-padding.
- `poseidonCommitmentHash(encodedSecret, salt)` — orchestrates the above and calls `poseidon12` from `poseidon-lite`.

## Worked example

These are exact byte values that any compatible implementation must reproduce. They are also encoded as test fixtures in [`packages/sdk/src/__tests__/commitments.test.ts`](../packages/sdk/src/__tests__/commitments.test.ts).

**Inputs:**

- `encoded_secret = utf8("attack=north")` — 12 bytes: `0x61 0x74 0x74 0x61 0x63 0x6b 0x3d 0x6e 0x6f 0x72 0x74 0x68`
- `salt = [0xff; 32]` — 32 bytes, all `0xff`

**Intermediate values:**

- Domain field (constant for this scheme): `0x15acf9be01a30fd2b8298af5cab2f90c84e8fb388ae253ebb8911cf98f421306`

**Output:**

- `commitment = 0x05f259557771fff79607b4e879588ab25c357c2da69acac697da93d9af2d1eb7`

If your implementation produces any other commitment for these inputs, it is using different parameters or a different packing — both incompatible with this scheme.

## Recommended Rust mirror

When the Rust verifier ships, it should:

1. Depend on `ark-bn254` for the field, and a circomlib-compatible Poseidon implementation (e.g., `light-poseidon` with circomlib constants, or hand-port the round constants from circomlibjs).
2. Mirror the four primitive helpers (`bytes_to_field_be`, `field_to_bytes_be`, `pack_secret_chunks`, `poseidon_commitment_hash`) as native `arkworks-rs` operations over `ark_bn254::Fr`.
3. Run the worked example as the first integration test before doing anything else. If the test passes, the cross-language compatibility holds.

## Future considerations

- **Larger secrets**: if a use case ever needs more than 256 bytes of `encoded_secret`, the right answer is a new scheme identifier (`poseidon-bn254-circomlib-v2` or similar) using a sponge construction over `poseidon2`. Bumping the parameters of an existing scheme is a compatibility-breaking change and not allowed under invariant #16.
- **Different parameter sets**: if a future verifier tooling change requires arkworks-default parameters (or Poseidon2), introduce them as new scheme identifiers. Never silently change what `poseidon-bn254-circomlib-v1` means.
- **On-chain hash verification**: this spec defines a *commitment*, not an on-chain check. The contract stores `hash_scheme` as opaque bytes and never computes the hash itself. If on-chain verification ever becomes desirable, that's a Move-side feature implementing `verify_opening_groth16` against a precompiled verifying key — separate from this scheme.
