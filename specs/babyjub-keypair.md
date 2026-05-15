# Baby Jubjub Keypair From Seed (`babyjub-keypair-v1`)

This document specifies the deterministic Baby Jubjub keypair derivation
used by the protocol. It is the cross-language compatibility contract
between the Rust `crypto` crate (native + future in-circuit), the WASM
binding, and the TypeScript SDK. Built on [`babyjub-curve.md`](./babyjub-curve.md).

> **NOTE(name):** scheme tag `babyjub-keypair-v1` and crate name `crypto` are
> working names. The protocol's public name is undecided — no product name is
> baked into either. A rename does not touch this derivation.

**Any implementation that does not reproduce the exact secret and public-key
values in [§ Worked Example](#worked-example) is incompatible with this
scheme and will not interoperate.**

## Why "from seed"

Randomness is contextual. A CSPRNG, a Blake2b digest of a wallet signature,
and a fixed test vector all produce 64 bytes; the keypair primitive should
not care which. Outsourcing randomness to the caller makes the primitive
deterministic and trivially testable: the same input runs through unit
tests, headless-browser boundary tests, and production-derived wallet keys
unchanged.

Where seeds come from in practice:

| Context | Seed source |
|---|---|
| Native tests | fixed bytes or `ark_std::test_rng()` |
| Headless-browser fixture | fixed bytes (this spec's worked example) |
| Production (wallet-bound) | `Blake2b-512(wallet_signature_over("babyjub-keypair-v1"))` — pinned in a separate spec when `wallet-derived-keys` extends to Baby Jubjub |

## Why 64 bytes (and not 32)

The secret key `sk` lives in `F_l`, the Baby Jubjub scalar field (a
251-bit prime, see [`babyjub-curve.md`](./babyjub-curve.md)). Reducing a
32-byte seed (256 bits) into a 251-bit field is biased — the top 5 bits
under-represent in `sk`. That bias is small (~2⁻³) but avoidable, and the
fix is one extra hash call at seed time. Reducing 64 bytes (512 bits)
yields a distribution indistinguishable from uniform on `F_l`
(bias ~ 2⁻²⁵⁶). This is what `ed25519-dalek` does internally and what
RFC 9380 recommends for hash-to-field constructions.

## Derivation

Given a 64-byte seed:

```text
domain_tag = bytes_to_field_be( Blake2b-256("babyjub-keypair-v1") )
chunk_0    = bytes_to_field_be( seed[ 0 ..  32] )
chunk_1    = bytes_to_field_be( seed[32 ..  64] )
sk_fq      = Poseidon-BN254-circomlib( domain_tag, chunk_0, chunk_1 )    // in F_p
sk         = sk_fq reinterpreted in F_l                                  // mod-l reduction
PK         = sk · Base8
```

Where:

- **`bytes_to_field_be(b)`** interprets `b` as a big-endian unsigned
  integer and reduces it modulo the target field's prime. For 32-byte
  inputs into `F_p` this is a 256-bit-into-254-bit reduction; the
  resulting bias on uniform input is ~2⁻²⁵⁰ and is fixed (the domain tag
  is constant, the chunks come from a uniform seed).
- **`Poseidon-BN254-circomlib`** is the Poseidon permutation over
  `F_p` with circomlib's parameters (arity 3, state size 4). Same
  parameter set as [`specs/poseidon-commitment-format.md`](./poseidon-commitment-format.md);
  same parameter set as the TypeScript `poseidon-lite` and circomlib's
  `poseidon([_, _, _])`. The Rust implementation uses
  [`light-poseidon`](https://crates.io/crates/light-poseidon), audited by
  Veridise.
- **The `F_p` → `F_l` reduction** is performed by serializing the `F_p`
  element to bytes and re-parsing into `F_l` (i.e. literal `sk_fq mod l`).
  The bias is determined by the gap between the two prime moduli (254 vs
  251 bits) on Poseidon-uniform input, ~2⁻²⁵¹ — far below cryptographic
  relevance for a private key.
- **`Base8`** is the prime-order-subgroup generator pinned in
  [`babyjub-curve.md`](./babyjub-curve.md). `PK = sk · Base8` is in the
  prime-order subgroup by construction.

## Domain tag

```text
domain_string = "babyjub-keypair-v1"
domain_tag    = 19761263853693738108338270330884798184054063717590838868550696276495870701270
```

The `-v1` suffix reserves space for a future derivation tweak — a different
chunk count, a different hash, an additional binding context — without
silently reusing the same scheme name. A scheme change MUST mint a new
domain string and increment the version.

## Worked Example

These vectors are the compatibility fixture. Any Rust, WASM, or TypeScript
implementation is conformant iff it reproduces every value below exactly.

### Seed: 64 bytes of `0x00`

```text
seed = 0x00 × 64
sk   = 2680668902465992673778802688582297466674589947419533446784951070170521507216
PK.x = 9052145210158052161818611168469442415783119048928084171117132839267951576749
PK.y = 15138733388225546515036950290042250293266309799081989529651843475752774394912
```

### Seed: 64 bytes of `0x42`

```text
seed = 0x42 × 64
sk   = 840856665571143697078937402224105503145452462402279532427996026995141498285
PK.x = 10242056643687748052026914853801031667608768151841054399444813507230536137636
PK.y = 17209935276727295699825960001966777169457960631433628415363271904988532178005
```

### Seed: `0x01, 0x02, …, 0x40`

```text
seed = 0x01 0x02 0x03 … 0x3F 0x40   // 64 bytes, increasing
sk   = 1484991602482751723892107159329215742754162297312481754483523557948882437954
PK.x = 20850129809617136780643076514291815738908181923486074779130442852041357820493
PK.y = 6638083023153244747644631095237619826300111037602892009430291132442244811183
```

## Validity

A conformant implementation MUST also satisfy:

- **`PK` is in the prime-order subgroup.** This follows mathematically
  from `PK = sk · Base8`, but any decoder accepting a `PK` from outside
  the process (a JS caller, a wire-decoded envelope, an on-chain value)
  MUST re-check on-curve and prime-subgroup membership — the Rust
  [`point_from_strings`](../crates/crypto/src/babyjub/wire.rs) decoder
  performs both checks.

## Scope intentionally NOT in this version

- **Secret-key wire format.** No on-wire `SecretKey` encoding. The
  production caller (`wallet-derived-keys` for Baby Jubjub, when written)
  re-derives rather than stores. Adding `SecretKey` byte serialization
  later is non-breaking.
- **`Zeroize` on drop.** Tracked as a follow-up brick. The production
  caller does not retain secrets so this is not urgent; the test vectors
  in this spec keep their bytes by design.

## References

- [`babyjub-curve.md`](./babyjub-curve.md) — the curve this keypair lives on.
- [`poseidon-commitment-format.md`](./poseidon-commitment-format.md) —
  same Poseidon parameter set, same `bytes_to_field_be(Blake2b256(domain))`
  domain-tag construction.
- [RFC 9380](https://datatracker.ietf.org/doc/rfc9380/) — hash-to-field
  rationale for using more than 32 bytes when reducing into a ≤256-bit
  field.
- [light-poseidon](https://github.com/Lightprotocol/light-poseidon) — Rust
  Poseidon implementation, circomlib-compatible.
