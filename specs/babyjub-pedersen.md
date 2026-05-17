# Baby Jubjub Vector Pedersen Commitments (`babyjub-pedersen`)

This document specifies the **vector** Pedersen commitment scheme
used by the protocol: a commitment to a *stream* of field elements,
not a single scalar. It is the cross-language compatibility
contract between the Rust `crypto` crate, the WASM binding, and the
TypeScript SDK. Built on [`babyjub-curve.md`](./babyjub-curve.md).

> **NOTE(name):** scheme tag `babyjub-pedersen` and crate name
> `crypto` are working names. No product name is baked in.

**Any implementation that does not reproduce the exact point
coordinates in [§ Worked Example](#worked-example) is incompatible
with this scheme and will not interoperate.**

## What this defines

A commitment to a stream of base-field elements
`stream = (stream_0, stream_1, …, stream_{n-1}) ∈ F_p^n`, blinded
by a caller-supplied scalar `blinding ∈ F_l`:

```text
C = stream_0 · G_0 + stream_1 · G_1 + … + stream_{n-1} · G_{n-1} + blinding · H
```

where:

- `G_0, G_1, G_2, …` is an unbounded family of **value generators**,
  each derived deterministically from its index. Section [§
  Generators](#generators) pins the derivation.
- `H` is the **blinding generator**, derived from a separate fixed
  string by the same procedure.

The stream's elements live in `F_p` (base field — what every
encoding produces). The blinding lives in `F_l` (scalar field —
where scalar-multiplication scalars live). Each stream element is
reduced into `F_l` for the scalar mul; the bias from this 254-bit
→ 251-bit reduction is `~2⁻²⁵¹` on encoding-uniform input, far
below cryptographic relevance.

## Properties

- **Binding** — the committer cannot open `C` to a different
  stream without finding a non-trivial linear combination of the
  generators that equals zero. Honestly-derived generators
  (below) have no such relation known to anyone.
- **Hiding** — for `blinding` sampled uniformly from `F_l`, `C`
  reveals nothing about the stream.
- **Element-wise additive homomorphism** —
  `commit(a, r_a) + commit(b, r_b) == commit(a + b, r_a + r_b)`
  where `a + b` is the element-wise sum of streams. This holds
  per-position, not just on a hash of the stream.
- **Single-element addressability** — because each stream position
  is bound to a distinct generator, a future ZK predicate can
  prove "the i-th element of the committed stream is X" by
  isolating `stream_i · G_i` without revealing the other elements.

## What this does NOT define

- **Length-hiding commitments.** The commitment leaks the stream
  length to anyone who knows which generator set was used (the
  encoding's tag exposes it anyway in normal protocol use). For a
  future use case where length itself is secret, the construction
  would zero-pad the stream to a fixed `MAX_LEN` first.
- **Pedersen-hash** (commit-to-bit-vector without blinding). A
  different primitive; circomlib has one.
- **Verification function.** Verification is `commit(stream,
  blinding) == C` — re-run and compare. No separate `verify`
  exists by design.
- **Zero-knowledge proofs of opening.** Future bricks.

## Caller responsibilities

- **Randomness for `blinding`**: this spec does not specify a
  source. A production caller MUST sample `blinding` from a
  cryptographically secure source. Reusing `blinding` across
  commitments to different streams is a hiding-failure footgun.
- **Stream length**: any non-negative length, including zero.
  `commit([], blinding)` produces `blinding · H` — a "no content"
  commitment, useful as a placeholder.
- **Stream element range**: any element of `F_p`. The protocol's
  application layer is responsible for narrower constraints; the
  primitive itself accepts the full base field.

## Generators

### Derivation procedure (shared)

Every generator (`H`, `G_0`, `G_1`, …) is derived by the same
try-and-increment hash-to-curve procedure, parameterized by an
input seed:

```text
derive_generator(seed: bytes) -> EdwardsAffine:
    for counter in 0, 1, 2, ...:
        bytes  = seed || counter_as_big_endian_4_bytes
        digest = Blake2b-256(bytes)
        y      = bytes_to_field_be(digest) mod p          # candidate y-coordinate
        want_odd_x = digest[0] >> 7                       # top bit picks the x sign
        if x² := (1 - y²) / (a - d·y²) has a square root in F_p:
            x = chosen_sqrt
            if (x is odd) != want_odd_x: x = -x           # disambiguate the two roots
            if (x, y) is on the curve:
                P = (x, y)
                G = 8 · P                                 # cofactor-clear into the subgroup
                if G is not identity and l · G == identity:
                    return G
```

Same procedure pinned for `H` in the original commitment spec; it
just gets a fresh `seed` per generator now.

### `H` — blinding generator

```text
H_seed = Blake2b-256("babyjub-pedersen-h-v1")
H      = derive_generator(H_seed)
```

```text
H.x = 841592716755229802932648006577806087532565884664794707633999447952449024030
H.y = 21165608275098473985804540174915770236470038226241417420449949757110115410790
```

(Identical to the previous version of this spec — `H`'s identity
does not change.)

### `G_i` — value generators

```text
G_seed_i = Blake2b-256("babyjub-pedersen-G" || i_as_big_endian_4_bytes)
G_i      = derive_generator(G_seed_i)
```

The 4-byte big-endian counter caps the family at `2³² ≈ 4 × 10⁹`
generators — vastly more than any conceivable encoding length.
`G_i` does not depend on stream length; the same `G_0` is used by
any commitment whose stream has at least one element, regardless of
whether that stream has 1 or 1000 elements total.

A conformant implementation MUST reproduce the following coordinates
for `G_0` through `G_8`. (These are the indices any commitment to a
`text-utf8-v1` encoded payload — 9 fields — will need. Longer
encodings derive additional `G_i` by the same rule.)

```text
G_0.x = 21825913315207187562682941426389735603195557456908788185325554283133704969469
G_0.y = 13858835039840996693419673582381761260939607442217267755302767527818398641731

G_1.x = 20575965760164337262334774054378795618088523386778010995471136590187796529701
G_1.y = 11472718758928886131229343204249654494039108425038885225582864325793984113683

G_2.x = 19629444098512607486964143211932544072019384249182351321391247980828086963181
G_2.y = 14676386063549364987353415367080290114747127276135091611357592180751577407216

G_3.x = 4191123957088666987917744952774410638283201499374880855397978634321446378746
G_3.y = 5563868606574005692855439626454045831229812366456773367012537503515753711491

G_4.x = 13906250278609103013693965804928758909088584430521764093212153348033627984392
G_4.y = 12181978227468336557233115140244123563457685652645865608273337316976963078835

G_5.x = 16785645457649661107253518324490257230918828410474949611283289767397026109801
G_5.y = 11876897120948612820992029687954458547916175818021718205885701570622240592878

G_6.x = 7558247459771661250659309781149422418626500996716368678807322689757894225296
G_6.y = 16642285874621993431346944680104703757912566044478696417322347576188548774770

G_7.x = 9875071539881219242689911895463477601134300318323430306073081116421254878463
G_7.y = 9121186125160826469157651053942138620676480120915017749641308921065902798489

G_8.x = 7464720615947172612874151335915560519424575078796952400920267107051066945193
G_8.y = 6892475268534480380904659053333425458191144723810987894174457601007330478314
```

## Worked Example

A conformant implementation reproduces every value below exactly.

### Vector 1 — small stream

```text
stream   = [1, 2, 3]
blinding = 7
C.x      = 13038198386731673912560721016555247709029515585051432629517992977316576071934
C.y      = 9212446836796220420114805122843851887604206441937641721882028388154348874834
```

### Vector 2 — same stream, different blinding (hiding demo)

```text
stream   = [1, 2, 3]
blinding = 13
C.x      = 9736694471584014539103174266977502394328576418207416620718200307732692986586
C.y      = 3837989773818515678372306562761863874052663211214567054924083133818431027478
```

### Vector 3 — 9-element stream (matches `text-utf8-v1` shape)

```text
stream   = [0, 1, 2, 3, 4, 5, 6, 7, 8]
blinding = 42
C.x      = 1816745010582515843223529375604165335664011795439985242868613130573867132011
C.y      = 1118057154514564837088862449882370788049673922232213149895810435579743690349
```

### Vector 4 — empty stream

The "no content with hiding" case: `C = blinding · H`.

```text
stream   = []
blinding = 123
C.x      = 13828148247158678812499162641315699180347697370202244738700865095716896041487
C.y      = 15186219207262690188902497053707372380315160076221164591981113425196456829665
```

### Vector 5 — element-wise homomorphism anchor

`[10, 20, 30] + [5, 15, 25] = [15, 35, 55]` element-wise. Blindings
`100 + 200 = 300`. A conformant implementation produces the same
`C_sum` both as `commit([15, 35, 55], 300)` (the right-hand side)
and as `commit([10, 20, 30], 100) + commit([5, 15, 25], 200)` (the
left-hand side, computed in the group).

```text
stream_a    = [10, 20, 30]
blinding_a  = 100
C_a.x       = 20165783177805050685274039323930990409514798580108732990166809078322919387758
C_a.y       = 20105427299541812631581133674178585240009494580824437651896536730345287064526

stream_b    = [5, 15, 25]
blinding_b  = 200
C_b.x       = 17596125414069067324687810281063731630965449169266662977490787474901973411621
C_b.y       = 330214796688329854541806467049644026825127578648076530845715008630967672190

stream_sum  = [15, 35, 55]
blinding_sum = 300
C_sum.x     = 7197332655677449090088671372714432917743021897248424654297871978491214754206
C_sum.y     = 3491146607410882481913448536648113321671999435511322181830072546126502831366
```

## Validity contracts

A conformant implementation MUST:

- **Produce commitments in the prime-order subgroup.** Follows
  mathematically from `H` and every `G_i` being subgroup
  generators. A decoder accepting an external commitment value
  MUST validate via `point_from_strings` (which enforces on-curve
  + prime-subgroup) before downstream use.

- **Reject configurations where `G_i == G_j` for `i ≠ j`** during
  generator validation. The try-and-increment procedure makes a
  collision astronomically unlikely, but the assertion is cheap
  and forecloses an entire failure class.

- **Treat the blinding scalar as sensitive.** If `blinding` leaks,
  the commitment becomes a deterministic function of the stream,
  which is brute-forceable for small stream spaces.

- **Match every pinned generator and worked-example vector
  byte-for-byte.**

## References

- [`babyjub-curve.md`](./babyjub-curve.md) — the curve all
  generators live on.
- [`babyjub-keypair.md`](./babyjub-keypair.md) — same `Fq → Fr`
  reduction trick for scalar mul.
- Pedersen, T. P. (1991). *Non-interactive and
  information-theoretic secure verifiable secret sharing.*
  CRYPTO '91. The original (scalar) construction; the vector
  extension is a straightforward generalization.
