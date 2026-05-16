//! Cross-language compatibility fixture for `babyjub-pedersen`.
//!
//! Executable form of `specs/babyjub-pedersen.md § Worked Example`.
//! If `H`, any `G_i`, or the commitment construction drifts, these
//! tests fail. Integration tests (in `tests/`) by design — they
//! exercise the public surface as a third-party crate would.

use ark_ec::CurveGroup;
use ark_ec::twisted_edwards::Projective;

use crypto::babyjub::{
    commit, g_generator, h_generator, point_to_strings, Fq, Fr,
};

// --- generators -------------------------------------------------------

/// `H` keeps its identity from the previous (scalar) version of this
/// spec — same domain string, same coordinates.
#[test]
fn h_matches_spec() {
    let h = point_to_strings(&h_generator());
    assert_eq!(
        h.x,
        "841592716755229802932648006577806087532565884664794707633999447952449024030",
    );
    assert_eq!(
        h.y,
        "21165608275098473985804540174915770236470038226241417420449949757110115410790",
    );
}

/// All nine `G_i` (the indices needed for `text-utf8-v1`) match the
/// pinned spec coordinates. If the derivation procedure drifts —
/// wrong domain string, wrong index encoding, wrong sign-bit
/// convention, wrong cofactor-clearing — these change and the test
/// fails.
#[test]
fn g_generators_0_through_8_match_spec() {
    let expected: [(usize, &str, &str); 9] = [
        (0,
         "21825913315207187562682941426389735603195557456908788185325554283133704969469",
         "13858835039840996693419673582381761260939607442217267755302767527818398641731"),
        (1,
         "20575965760164337262334774054378795618088523386778010995471136590187796529701",
         "11472718758928886131229343204249654494039108425038885225582864325793984113683"),
        (2,
         "19629444098512607486964143211932544072019384249182351321391247980828086963181",
         "14676386063549364987353415367080290114747127276135091611357592180751577407216"),
        (3,
         "4191123957088666987917744952774410638283201499374880855397978634321446378746",
         "5563868606574005692855439626454045831229812366456773367012537503515753711491"),
        (4,
         "13906250278609103013693965804928758909088584430521764093212153348033627984392",
         "12181978227468336557233115140244123563457685652645865608273337316976963078835"),
        (5,
         "16785645457649661107253518324490257230918828410474949611283289767397026109801",
         "11876897120948612820992029687954458547916175818021718205885701570622240592878"),
        (6,
         "7558247459771661250659309781149422418626500996716368678807322689757894225296",
         "16642285874621993431346944680104703757912566044478696417322347576188548774770"),
        (7,
         "9875071539881219242689911895463477601134300318323430306073081116421254878463",
         "9121186125160826469157651053942138620676480120915017749641308921065902798489"),
        (8,
         "7464720615947172612874151335915560519424575078796952400920267107051066945193",
         "6892475268534480380904659053333425458191144723810987894174457601007330478314"),
    ];
    for (i, want_x, want_y) in expected {
        let g = point_to_strings(&g_generator(i));
        assert_eq!(g.x, want_x, "G_{i}.x drift");
        assert_eq!(g.y, want_y, "G_{i}.y drift");
    }
}

// --- commitment vectors ----------------------------------------------

/// Vector 1: small 3-element stream.
#[test]
fn fixture_vector_1_small_stream() {
    let stream = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
    let c = point_to_strings(&commit(&stream, Fr::from(7u64)));
    assert_eq!(
        c.x,
        "13038198386731673912560721016555247709029515585051432629517992977316576071934",
    );
    assert_eq!(
        c.y,
        "9212446836796220420114805122843851887604206441937641721882028388154348874834",
    );
}

/// Vector 2: same stream, different blinding (hiding demo).
#[test]
fn fixture_vector_2_same_stream_different_blinding() {
    let stream = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
    let c = point_to_strings(&commit(&stream, Fr::from(13u64)));
    assert_eq!(
        c.x,
        "9736694471584014539103174266977502394328576418207416620718200307732692986586",
    );
    assert_eq!(
        c.y,
        "3837989773818515678372306562761863874052663211214567054924083133818431027478",
    );
}

/// Vector 3: 9-element stream matching `text-utf8-v1`'s shape. The
/// "real" use case for the commitment in production.
#[test]
fn fixture_vector_3_text_utf8_v1_shape() {
    let stream: Vec<Fq> = (0u64..9).map(Fq::from).collect();
    let c = point_to_strings(&commit(&stream, Fr::from(42u64)));
    assert_eq!(
        c.x,
        "1816745010582515843223529375604165335664011795439985242868613130573867132011",
    );
    assert_eq!(
        c.y,
        "1118057154514564837088862449882370788049673922232213149895810435579743690349",
    );
}

/// Vector 4: empty stream. `C = blinding · H`. Pins the edge case.
#[test]
fn fixture_vector_4_empty_stream() {
    let c = point_to_strings(&commit(&[], Fr::from(123u64)));
    assert_eq!(
        c.x,
        "13828148247158678812499162641315699180347697370202244738700865095716896041487",
    );
    assert_eq!(
        c.y,
        "15186219207262690188902497053707372380315160076221164591981113425196456829665",
    );
}

/// Vector 5a: first addend for the homomorphism anchor.
#[test]
fn fixture_vector_5a() {
    let stream = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
    let c = point_to_strings(&commit(&stream, Fr::from(100u64)));
    assert_eq!(
        c.x,
        "20165783177805050685274039323930990409514798580108732990166809078322919387758",
    );
    assert_eq!(
        c.y,
        "20105427299541812631581133674178585240009494580824437651896536730345287064526",
    );
}

/// Vector 5b: second addend for the homomorphism anchor.
#[test]
fn fixture_vector_5b() {
    let stream = [Fq::from(5u64), Fq::from(15u64), Fq::from(25u64)];
    let c = point_to_strings(&commit(&stream, Fr::from(200u64)));
    assert_eq!(
        c.x,
        "17596125414069067324687810281063731630965449169266662977490787474901973411621",
    );
    assert_eq!(
        c.y,
        "330214796688329854541806467049644026825127578648076530845715008630967672190",
    );
}

/// Vector 5sum: element-wise homomorphism. The spec's worked-example
/// proof of `commit(a, r_a) + commit(b, r_b) == commit(a+b, r_a+r_b)`
/// at the byte level. A conformant implementation produces the same
/// point both via `commit([15, 35, 55], 300)` (explicit) and as the
/// group sum of 5a + 5b (homomorphism).
#[test]
fn fixture_vector_5_homomorphism_via_explicit() {
    let stream = [Fq::from(15u64), Fq::from(35u64), Fq::from(55u64)];
    let c = point_to_strings(&commit(&stream, Fr::from(300u64)));
    assert_eq!(
        c.x,
        "7197332655677449090088671372714432917743021897248424654297871978491214754206",
    );
    assert_eq!(
        c.y,
        "3491146607410882481913448536648113321671999435511322181830072546126502831366",
    );
}

#[test]
fn fixture_vector_5_homomorphism_via_group_sum() {
    let stream_a = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
    let stream_b = [Fq::from(5u64), Fq::from(15u64), Fq::from(25u64)];
    let stream_sum = [Fq::from(15u64), Fq::from(35u64), Fq::from(55u64)];

    let c_a = commit(&stream_a, Fr::from(100u64));
    let c_b = commit(&stream_b, Fr::from(200u64));
    let group_sum = (Projective::from(c_a) + Projective::from(c_b)).into_affine();
    let c_sum_explicit = commit(&stream_sum, Fr::from(300u64));

    assert_eq!(
        group_sum, c_sum_explicit,
        "element-wise homomorphism: commit(a) + commit(b) MUST equal commit(a+b)",
    );
}
