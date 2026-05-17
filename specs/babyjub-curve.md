# Baby Jubjub Curve (`babyjub-erc2494-v1`)

This document pins the exact Baby Jubjub curve parameters used by the protocol's
cryptographic primitives — keypairs, key agreement, Pedersen commitments, and
Schnorr-style signatures all live on this curve. It is the cross-language
compatibility contract between the Rust `crypto` crate (native + future
in-circuit), the future WASM binding, and the TypeScript SDK.

> **NOTE(name):** the scheme tag `babyjub-erc2494-v1` and the crate name
> `crypto` are working names. The protocol's public name is undecided — no
> product name is baked into either. A rename should not touch this curve
> definition.

**Any implementation that does not reproduce the exact point coordinates in
[§ Worked Example](#worked-example) is incompatible with this scheme and will
not interoperate.**

## Why this exists

Baby Jubjub is a twisted Edwards curve whose base field is the BN254 scalar
field. That is the whole point of choosing it: curve operations are *native
field arithmetic* inside a BN254 Groth16 circuit, so public keys, ECDH shared
secrets, commitments, and signature relations become cheap constraints rather
than prohibitively expensive foreign-field simulation.

But "Baby Jubjub" alone does not pin down a byte-level implementation. The 2018
WhiteHat–Baylina–Bellés paper fixes the field, the subgroup order, the cofactor,
and the Montgomery coefficient — and then **leaves the Edwards coordinate
convention and the generator point to the implementer.** Two good-faith
conventions exist in the wild:

- **arkworks default (`ark-ed-on-bn254`):** the paper's literal `a = 1` Edwards
  form, with arkworks' own chosen generator.
- **ERC-2494 / circomlib / iden3:** the twisted `a = 168700` Edwards form, with
  `Base8` as the generator.

These are the *same curve* — same field, same order, same cofactor — expressed
in different coordinates with different chosen generators. But a keypair, a
commitment, or a shared secret serializes to **different bytes** under each
convention. They do not interoperate.

The entire circom ecosystem — circomlib, snarkjs, iden3, every existing Baby
Jubjub circuit and published test vector — speaks the **ERC-2494 dialect**. The
protocol's design goal is public, interoperable encodings that arbitrary
developers can write circuits against. That goal is only achievable in the
dialect the ecosystem already speaks. **This spec therefore pins the ERC-2494
dialect.** The Rust crate implements it by defining a custom arkworks
`TECurveConfig` rather than adopting `ark-ed-on-bn254`'s defaults.

## Parameter set

All constants below are transcribed from [ERC-2494][erc2494] and independently
cross-checked against [`iden3/circomlibjs`][circomlibjs] `src/babyjub.js`. The
two sources agree digit-for-digit.

### Field

- **Base field** `F_p` — Baby Jubjub point coordinates and the curve
  coefficients `a`, `d` live here. This is the **BN254 scalar field**:

  ```
  p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  ```

  It is the same field Sui's `sui::groth16::verify_groth16_proof` precompile
  proves over, and the same field the Poseidon scheme
  (`poseidon-bn254-circomlib-v1`) hashes in.

- **Scalar field** `F_l` — private keys and scalars used in scalar
  multiplication live here. Its modulus is the **prime-order subgroup order**:

  ```
  l = 2736030358979909402780800718157159386076813972158567259200215660948447373041
  ```

### Curve

Baby Jubjub has two equivalent forms. The protocol works in the **twisted
Edwards** form; the Montgomery form is listed only because arkworks uses it
internally for the birational map.

- **Twisted Edwards form:** `a · x² + y² = 1 + d · x² · y²` over `F_p`, with

  ```
  a = 168700
  d = 168696
  ```

- **Montgomery form:** `B · v² = u³ + A · u² + u` over `F_p`, with

  ```
  A = 168698   (the coefficient from the Baby Jubjub paper)
  B = 1
  ```

- **Cofactor** `h = 8`. The full curve has order `h · l = 8 · l`. The
  conventional generator `Base8` lies in the prime-order subgroup, so scalar
  multiplication by an `F_l` element stays inside that subgroup.

### Generator

The conventional generator is circomlib's **`Base8`** — *not* the paper-style
generator `G`. `Base8 = 8 · G` lands in the prime-order subgroup, which is why
circomlib, snarkjs, and iden3 all use it as *the* generator. Every public key
in this protocol is a scalar multiple of `Base8`.

```
Base8.x = 5299619240641551281634865583518297030282874472190772894086521144482721001553
Base8.y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
```

For completeness, the paper-style (cofactored) generator `G`, which this
protocol does **not** use as the generator:

```
G.x = 995203441582195749578291179787384436505546430278305826713579947235728471134
G.y = 5472060717959818805561601436314318772137091100104008585924551046643952123905
```

### Group identity

The twisted Edwards neutral element is `O = (0, 1)`. Adding it to any point
returns that point unchanged. The inverse of `(x, y)` is `(-x, y)`.

## Point validity

An externally-supplied point (a wire-decoded public key, for example) must pass
**both** checks before any cryptographic use:

1. **On-curve:** `(x, y)` satisfies `a · x² + y² = 1 + d · x² · y²`.
2. **In the prime-order subgroup:** `l · (x, y) = O`.

On-curve alone is insufficient. The full curve has order `8 · l`; a point in a
small-order component is on-curve but enables subgroup-confinement attacks. Both
checks are required.

## Worked Example

These vectors are the compatibility fixture. An implementation is conformant iff
it reproduces every coordinate below exactly.

### Anchor 1 — circomlib reference vectors (external cross-check)

These are published in [`iden3/circomlib`][circomlib] `test/babyjub.js` and
[`iden3/circomlibjs`][circomlibjs] `test/babyjub.js`. They are independent of
this codebase: reproducing them proves the curve config matches circomlib's
curve, not merely that it is internally self-consistent.

Let `P = (17777552123799933955779906779655732241715742912184938656739573121738514868268,
2626589144620713026669568689430873010625803728049924121243784502389097019475)`.

**Point doubling — `P + P`:**

```
x = 6890855772600357754907169075114257697580319025794532037257385534741338397365
y = 4338620300185947561074059802482547481416142213883829469920100239455078257889
```

**Point addition — `P + Q`** where
`Q = (16540640123574156134436876038791482806971768689494387082833631921987005038935,
20819045374670962167435360035096875258406992893633759881276124905556507972311)`:

```
x = 7916061937171219682591368294088513039687205273691143098332585753343424131937
y = 14035240266687799601661095864649209771790948434046947201833777492504781204499
```

**Scalar multiplication — `3 · P`:**

```
x = 19372461775513343691590086534037741906533799473648040012278229434133483800898
y = 9458658722007214007257525444427903161243386465067105737478306991484593958249
```

### Anchor 2 — `Base8` scalar-mul vectors (generator-anchored contract)

These are `k · Base8` for selected scalars `k`, computed by the `crypto` crate.
Anchor 1 proves the *curve* is correct; Anchor 2 pins outputs to *this
protocol's generator* specifically, and is the contract the future Rust circuit
and TypeScript SDK must reproduce. They are regenerable: any conformant
ERC-2494 implementation produces exactly these.

| `k` | `(k · Base8).x` / `(k · Base8).y` |
|---|---|
| `1` | `5299619240641551281634865583518297030282874472190772894086521144482721001553` |
|     | `16950150798460657717958625567821834550301663161624707787222815936182638968203` |
| `2` | `10031262171927540148667355526369034398030886437092045105752248699557385197826` |
|     | `633281375905621697187330766174974863687049529291089048651929454608812697683` |
| `3` | `2763488322167937039616325905516046217694264098671987087929565332380420898366` |
|     | `15305195750036305661220525648961313310481046260814497672243197092298550508693` |
| `8` | `7582035475627193640797276505418002166691739036475590846121162698650004832581` |
|     | `7801528930831391612913542953849263092120765287178679640990215688947513841260` |
| `1000` | `20366147795936572600700348767835863189204735700033902769792878907543918679364` |
|        | `17979751125406099319734770781608767238997398840154679652223692501113096137972` |
| `4242424242` | `8197680051882628970410681376493202672655988696749960149267822370593492838760` |
|              | `12894077115825233362045965817688273159131941840146661890364266485669764812312` |
| `2^200` | `5724625655608868645689535268422070084543995927732212059724113152068754891373` |
|         | `10308923700401579816603597606813811960552754413890927913080984195249222032507` |

## References

- [ERC-2494: Baby Jubjub Elliptic Curve][erc2494] — the dialect this spec pins.
- [Baby Jubjub paper][paper] — WhiteHat, Baylina, Bellés, 2018. Fixes the field,
  order, cofactor, and Montgomery `A`; leaves the Edwards convention and
  generator open.
- [`iden3/circomlib`][circomlib] / [`iden3/circomlibjs`][circomlibjs] — the
  reference implementations; source of the Anchor 1 vectors.

[erc2494]: https://eips.ethereum.org/EIPS/eip-2494
[paper]: https://eips.ethereum.org/assets/eip-2494/Baby-Jubjub.pdf
[circomlib]: https://github.com/iden3/circomlib
[circomlibjs]: https://github.com/iden3/circomlibjs
