/**
 * Canonical fixture values for each circuit, pinned against the
 * spec docs. The values here MUST match the integration tests
 * and the spec's worked examples — any drift surfaces as the
 * prove/verify cycle failing in-page.
 *
 * Pedersen fixture decimals come from
 * `specs/zk/circuit-pedersen-opens-to.md § Worked Example`.
 *
 * Envelope fixture decimals come from
 * `specs/zk/circuit-envelope-open-at-0.md` chained through
 * `protocol::envelope::seal` for the canonical Alice/Bob/id=42
 * envelope with the 9-element plaintext `[1..=9]`. The same
 * values are produced by `crates/prover-wasm/build.rs` and
 * checked in the wasm boundary tests.
 *
 * Hardcoding the values keeps the page simple: no need to
 * re-derive the envelope in-browser via `crypto-wasm`
 * primitives just to demonstrate the prove/verify flow. A
 * future "type your own message" variant would compute these
 * dynamically.
 */

/** Wire-form inputs for the pedersen_opens_to /prove call. */
export interface PedersenOpensToInputs {
  commitment_x: string;
  commitment_y: string;
  encoding_id: string;
  claimed_first_value: string;
  stream: [string, string, string, string, string, string, string, string, string];
  blinding: string;
}

/** Public-input-only subset for /verify and tampered-verify. */
export interface PedersenOpensToPublicInputs {
  commitment_x: string;
  commitment_y: string;
  encoding_id: string;
  claimed_first_value: string;
}

/**
 * Canonical pedersen_opens_to fixture (stream [10..90], blinding
 * 12345, text-utf8-v1 encoding id). The commitment is over the
 * augmented [encoding_id, ...stream], matching protocol::commitment.
 */
export const PEDERSEN_FIXTURE: PedersenOpensToInputs = {
  commitment_x:
    "14178428728361130724833880240122318573449800233918657877722353700842024882875",
  commitment_y:
    "19246693951740292838985087626008218915644570097536058114244575946261704440826",
  encoding_id:
    "10251905648233427808659162032937842155138269080868533503078341140126603942221",
  claimed_first_value: "10",
  stream: ["10", "20", "30", "40", "50", "60", "70", "80", "90"],
  blinding: "12345",
};

/** Wire-form inputs for the envelope_open_at_0 /prove call. */
export interface EnvelopeOpenAt0Inputs {
  signal: string;
  claimed_value: string;
  recipient_sk: string;
  sender_pk_x: string;
  sender_pk_y: string;
  recipient_pk_x: string;
  recipient_pk_y: string;
  envelope_id: string;
  encoding_id: string;
  ciphertext: [string, string, string, string, string, string, string, string, string];
  mac_tag: string;
}

/** Public-input-only subset. */
export interface EnvelopeOpenAt0PublicInputs {
  signal: string;
  claimed_value: string;
}

/**
 * Canonical envelope_open_at_0 fixture. Alice (seed 0x01...) seals
 * the 9-element plaintext [1..=9] to Bob (seed 0x02...) under
 * envelope id 42; Bob proves plaintext[0] == 1.
 *
 * Values reproduced from `prover-wasm`'s build.rs output and
 * cross-checked by the wasm boundary test.
 */
export const ENVELOPE_FIXTURE: EnvelopeOpenAt0Inputs = {
  signal:
    "6217333408759767397651363326396230716363569755863458852918341719635726940429",
  claimed_value: "1",
  recipient_sk:
    "2731702875519064002290362656202589349494796443482268838874720774092641752720",
  sender_pk_x:
    "5973620972294513314673339121277153508734624544832413721485350068184114274974",
  sender_pk_y:
    "17578450795250715997356049057547570616306557704415636814477109373899234445795",
  recipient_pk_x:
    "10663274534402736726963618346545626675833419329443596343571402089744699622013",
  recipient_pk_y:
    "17118641971790752267450378861266165944315881057953088539621212593641527445102",
  envelope_id: "42",
  encoding_id:
    "10251905648233427808659162032937842155138269080868533503078341140126603942221",
  ciphertext: [
    "10787321779190226554676337514347691875659477298610453494316095697639731105525",
    "11005131623232030623906867189653141067415173065234117331769608574160093139922",
    "11791314040563090199526129580738560103220176213914809365331933459954108858858",
    "7865039964291077852173468667319105421171640084683400461629880408575490986497",
    "2229138201795589665836767366228584476563000856384984963522822284776068932630",
    "11702069139758725090303111831331195321446015655716158873298318997122786844126",
    "21827964982986497021603458608987397530066910094307594093465521210581113049125",
    "5740201568618975964672094667205897157857936348884108865070928080450242112246",
    "6187684344249448887322373286095556400810738367783748855733293931088165175507",
  ],
  mac_tag:
    "7398943834207946599435298367371708282541003530546881690116239308373972876185",
};

/** Project the public-input subset from a full Inputs struct. */
export function pedersenPublic(i: PedersenOpensToInputs): PedersenOpensToPublicInputs {
  return {
    commitment_x: i.commitment_x,
    commitment_y: i.commitment_y,
    encoding_id: i.encoding_id,
    claimed_first_value: i.claimed_first_value,
  };
}

export function envelopePublic(i: EnvelopeOpenAt0Inputs): EnvelopeOpenAt0PublicInputs {
  return {
    signal: i.signal,
    claimed_value: i.claimed_value,
  };
}
