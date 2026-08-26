// `secrets rotate-plan`in DIFFERENTIAL'DA OLCULEMEYEN yuzeyi.
//
// Bir sey burada, differential'da degil, cunku Go'nun RET CUMLESI
// ayristiricinin ic durumunu anlatiyor ve bes ayri bicimi var: `cannot parse
// "1-02..." as "01"`, `month out of range`, `day out of range`, `hour out of
// range`, `extra text: "Z"`. O cumleleri elle uretmek SAHTE bir sadakat olurdu
// — bir sonraki bozuk girdide kirilacak bir yalan (bkz. cases.py'deki
// human_rotate_plan_bad_since gerekcesi).
//
// AMA KARAR AYRIDIR VE OLCULEBILIR: hangi dizelerin KABUL, hangilerinin RET
// edildigi. Asagidaki tablo tahmin edilmedi — Go'da
// `time.Parse(time.RFC3339, in)` kosturularak URETILDI. Uc satiri sasirtici ve
// ucu de elle yazilmis bir dogrulayicinin kacirmasi en muhtemel yerler.
use wapps::rotateplan::{query_escape, query_string, rfc3339_valid, render_text};
use wapps::store::{RotatePlanItem, RotatePlanResult};

// GO'DAN OLCULEN KABUL KUMESI.
const ACCEPTED: &[&str] = &[
    "2026-01-02T03:04:05Z",
    "2026-01-02T03:04:05.123Z",
    "2026-01-02T03:04:05.000000001Z",
    // Kesirli saniye UZUNLUGU sinirli DEGIL.
    "2026-01-02T03:04:05.1234567890123Z",
    "2026-01-02T03:04:05+03:00",
    "2026-01-02T03:04:05-11:30",
    "2026-01-02T03:04:05+00:00",
    "2026-01-02T03:04:05-00:00",
    "2026-01-02T03:04:05.5+05:45",
    // ARTIK YIL GERCEKTEN hesaplaniyor.
    "2024-02-29T03:04:05Z",
    // SASIRTICI: offset'in DAKIKASI aralik kontrolune GIRMIYOR. Go yalnizca
    // offset SAATINI kontrol ediyor, o yuzden `:60` gecerli sayiliyor.
    "2026-01-02T03:04:05+03:60",
    "0000-01-01T00:00:00Z",
    "9999-12-31T23:59:59Z",
];

// GO'DAN OLCULEN RET KUMESI.
const REJECTED: &[&str] = &[
    // Kucuk harf `t`/`z` KABUL EDILMIYOR — RFC3339'un kendisi izin verse de
    // Go'nun layout'u vermiyor, ve sozlesme Go'nun davranisi.
    "2026-01-02t03:04:05z",
    "2026-01-02T03:04:05z",
    "2026-01-02 03:04:05Z",
    // Sifir dolgusu ZORUNLU.
    "2026-1-02T03:04:05Z",
    "2026-01-2T03:04:05Z",
    "26-01-02T03:04:05Z",
    "+2026-01-02T03:04:05Z",
    // Aralik ihlalleri.
    "2026-13-02T03:04:05Z",
    "2026-00-02T03:04:05Z",
    "2026-01-32T03:04:05Z",
    "2026-01-00T03:04:05Z",
    "2026-02-30T03:04:05Z",
    "2026-02-29T03:04:05Z",
    "2026-01-02T25:04:05Z",
    // SASIRTICI: 24:00:00 de RET. "Gun sonu" gosterimi kabul edilmiyor.
    "2026-01-02T24:00:00Z",
    "2026-01-02T03:60:05Z",
    // SASIRTICI: ARTIK SANIYE YOK. `:60` her zaman ret.
    "2026-01-02T03:04:60Z",
    "2026-06-30T23:59:60Z",
    "2026-01-02T03:04:61Z",
    // Bolge SAAT'i aralik kontrolunden GECIYOR (dakikasinin aksine).
    "2026-01-02T03:04:05+99:00",
    // Eksik / fazla metin.
    "2026-01-02T03:04:05ZZ",
    "2026-01-02T03:04:05Z ",
    " 2026-01-02T03:04:05Z",
    "2026-01-02T03:04:05",
    "2026-01-02",
    "",
    // Nokta VARSA en az bir rakam gerekiyor.
    "2026-01-02T03:04:05.Z",
    // Offset iki basamakli ve iki parcali OLMALI.
    "2026-01-02T03:04:05+3:00",
    "2026-01-02T03:04:05+03",
];

#[test]
fn rfc3339_accepts_exactly_what_go_accepts() {
    for s in ACCEPTED {
        assert!(rfc3339_valid(s), "Go bunu KABUL ediyor, biz reddettik: {s:?}");
    }
}

#[test]
fn rfc3339_rejects_exactly_what_go_rejects() {
    for s in REJECTED {
        assert!(!rfc3339_valid(s), "Go bunu REDDEDIYOR, biz kabul ettik: {s:?}");
    }
}

// query_escape: kacilmamis bir `&` sorgu dizesini IKIYE BOLER ve gate bambaska
// bir `identity` gorur. Bu, tel'e cikan degerin sessizce kirpilabilecegi tek yer.
#[test]
fn query_escape_encodes_the_characters_that_would_split_a_query() {
    assert_eq!(query_escape("human:a@b.co"), "human%3Aa%40b.co");
    assert_eq!(query_escape("human:<a>&b"), "human%3A%3Ca%3E%26b");
    // Go'nun QueryEscape'i boslugu `+` yapar, `%20` DEGIL.
    assert_eq!(query_escape("a b"), "a+b");
    // Kacilmayan kume: harf, rakam ve -_.~
    assert_eq!(query_escape("Az09-_.~"), "Az09-_.~");
    // Yuzdelikler BUYUK harf.
    assert_eq!(query_escape("\u{7f}"), "%7F");
}

#[test]
fn query_string_sorts_by_key_like_go_url_values() {
    let q = query_string(&[
        ("identity", "x".to_string()),
        ("since", "y".to_string()),
        ("assume_policy", "1".to_string()),
    ]);
    assert_eq!(q, "assume_policy=1&identity=x&since=y");
}

fn item(project: &str, key: &str, last_read: &str, reads: u64) -> RotatePlanItem {
    RotatePlanItem {
        project: project.to_string(),
        key: key.to_string(),
        last_read: last_read.to_string(),
        reads,
    }
}

// BOS PLAN: tablo BASILMAZ. Bos bir baslik satiri basmak, operatore
// "sutunlar var ama satir yok" derdi; Go tek bir cumle basip donuyor.
#[test]
fn an_empty_plan_prints_a_sentence_and_no_table() {
    let out = render_text(&RotatePlanResult {
        identity: "human:nobody@example.invalid".to_string(),
        generated_at: "2026-08-26T00:00:00Z".to_string(),
        items: vec![],
    });
    assert!(out.contains("0 item(s)"), "{out}");
    assert!(out.contains("nothing to rotate"), "{out}");
    assert!(!out.contains("PROJECT"), "bos planda baslik satiri BASILMAMALI:\n{out}");
    assert!(!out.contains("Next:"), "bos planda kapanis satiri da yok:\n{out}");
}

// BOS `last_read` "(assume-policy)" olmali: satirin audit'ten degil policy
// kurallarindan turedigini soyleyen TEK isaret bu. Bos dize basmak "hic
// okunmamis" ile "audit kaydi yok"u AYNI gosterirdi.
#[test]
fn a_row_without_a_last_read_is_labelled_assume_policy() {
    let out = render_text(&RotatePlanResult {
        identity: "human:a@b.co".to_string(),
        generated_at: "g".to_string(),
        items: vec![item("lumira", "API_TOKEN", "", 0)],
    });
    assert!(out.contains("(assume-policy)"), "{out}");
}

// rotate-plan DEGER DONDURMEZ ve dondurmedigi yapisal olmali: sonuc tipinde
// bir deger alani YOKTUR, yani bir sir bu yuzeye ancak ADIYLA girebilir.
// Alanlarin serilestirmesi `--json` sozlesmesi oldugu icin burada da pinli.
#[test]
fn the_json_shape_carries_names_and_counters_but_no_value_field() {
    let res = RotatePlanResult {
        identity: "human:a@b.co".to_string(),
        generated_at: "g".to_string(),
        items: vec![item("vaulter", "DB_PASSWORD", "2026-01-02T03:04:05Z", 12)],
    };
    let json = serde_json::to_string(&res).expect("serilestirilemedi");
    assert_eq!(
        json,
        r#"{"identity":"human:a@b.co","generated_at":"g","items":[{"project":"vaulter","key":"DB_PASSWORD","last_read":"2026-01-02T03:04:05Z","reads":12}]}"#
    );
    assert!(!json.contains("\"value\""), "sonuc semasinda deger alani OLMAMALI: {json}");
}
