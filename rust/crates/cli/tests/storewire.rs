// GATE'IN TEL BICIMI: alan ADLARI Go'nun struct etiketlerinden gelir, Rust'in
// alan adlarindan DEGIL.
//
// NEDEN AYRI BIR TEST: bu ayrisma differential'da GORUNMUYORDU. Sahte gate
// `key_name` yayiyordu (Rust'in alan adi) ve `POST /read` COKLU anahtar
// isteklerini tek bir `__ALL__` senaryosuna cevirdigi icin, Go BOS adlar
// okuyup `["","",""]` gonderse bile ayni degerleri geri aliyordu. Yani iki
// ikili ayni ciktiyi uretiyordu ve karsilastirma HICBIR SEY olcmuyordu.
//
// Gercek gate `keyName` yayiyor: internal/store/store.go:54 (`json:"keyName"`),
// worker/test/admin-policy.test.ts (`k.keyName`), cmd/deploy/deploy_test.go.
use wapps::store::KeysResult;

#[test]
fn keys_response_is_parsed_from_the_camel_case_wire_field() {
    // Gate'in GERCEKTEN yaydigi govde (Go fixture'lariyla ayni sekil).
    let body = r#"{"project":"p","epoch":7,
                   "keys":[{"keyName":"ALPHA","keyVersion":1},
                           {"keyName":"BETA","keyVersion":2}]}"#;
    let got: KeysResult = serde_json::from_str(body).expect("gate govdesi cozulmeli");
    let names: Vec<&str> = got.keys.iter().map(|k| k.key_name.as_str()).collect();
    assert_eq!(names, ["ALPHA", "BETA"], "anahtar ADLARI `keyName` alanindan okunmali");
    assert_eq!(got.epoch, 7);
}

// Rust'in KENDI alan adi (`key_name`) tel bicimde YOKTUR. Bu vaka, yanlis
// alani okuyan bir cozucunun sessizce BOS ad uretmesini yakalar: bos adlar
// `read_all`da gate'e `["",""]` olarak gider ve okuma sessizce coker.
#[test]
fn the_snake_case_field_is_not_the_wire_name() {
    let body = r#"{"epoch":1,"keys":[{"key_name":"ALPHA"}]}"#;
    let got: KeysResult = serde_json::from_str(body).expect("cozulmeli");
    assert_eq!(
        got.keys[0].key_name, "",
        "`key_name` tel adi DEGIL; okunmus olmasi yanlis alanin baglandigini gosterir"
    );
}

// --- POST /import: TOPLU yazimin govdesi ------------------------------------
//
// Bu, `keyName` sinifinin YAZIM tarafidir. Okuma tarafinda yanlis bir alan adi
// BOS anahtar adlari uretip okumayi sessizce cokertiyordu; yazim tarafinda
// yanlis bir zarf adi (`secrets:`, `keys:`, duz harita) gate'e ANLAMSIZ bir
// govde gonderir. Sahte gate bu govdeyi artik DOGRULUYOR (eksik/bos `values`
// → 400), yani bir ayrisma differential'da da gorunur; buradaki test onu
// AG'A CIKMADAN yakalar.
//
// Oracle: internal/store/worker.go:358 —
//   json.Marshal(map[string]any{"values": values})
use std::collections::BTreeMap;

#[test]
fn the_import_body_wraps_the_values_in_a_values_envelope() {
    let mut v = BTreeMap::new();
    v.insert("BETA".to_string(), "second-test-string".to_string());
    v.insert("ALPHA".to_string(), "first-test-string".to_string());
    assert_eq!(
        wapps::store::import_body(&v),
        r#"{"values":{"ALPHA":"first-test-string","BETA":"second-test-string"}}"#
    );
}

#[test]
fn an_import_body_never_carries_a_bare_key_map() {
    let mut v = BTreeMap::new();
    v.insert("A".to_string(), "x".to_string());
    let body = wapps::store::import_body(&v);
    assert!(body.starts_with(r#"{"values":"#), "zarf `values` olmali: {body}");
}

// --- COMMIT YANITININ EPOCH'U: yazim tarafinin pin girdisi ------------------
//
// Bu blok, "bir yazim sunulan bir epoch OKUMUYOR" iddiasini CURUTUR. Tel onu
// tasiyor: worker/src/writer-do.ts commit yanitini
// `{project, epoch, manifestSha256, keyVersions}` olarak donduruyor ve
// index.ts'teki dispatchWrite DO yanitini istemciye AYNEN geciriyor. Yani
// `set` epoch'u yanitta ALIYORDU; JSON sinirinda ATIYORDU.
//
// Karar PUR bir fonksiyonda duruyor, cunku store::set ag I/O yapiyor ve
// testten ERISILEMEYEN bir guvenlik kapisi kimsenin savunamayacagi bir kapidir.

#[test]
fn a_commit_response_carries_the_new_epoch() {
    let body = r#"{"project":"vaulter","epoch":12,"manifestSha256":"ab","keyVersions":{"A":3}}"#;
    assert_eq!(
        wapps::store::committed_epoch(body, "set A").expect("epoch okunmali"),
        12
    );
}

// epoch 0 GECERLI BIR COMMIT DEGIL (writer-do: epoch = prevEpoch+1 >= 1), yani
// 0 "alan yoktu" demektir. Onu pin kontroluna vermek operatore
// "served epoch 0 < pinned N — possible rollback attack" dedirtir ve onu
// GEREKSIZ bir DR seremonisine yollar. Kapi yine KAPALI ama suclama DOGRU
// sinifta: protokol ihlali.
#[test]
fn a_commit_response_without_an_epoch_is_a_protocol_error_not_a_rollback_accusation() {
    let body = r#"{"project":"vaulter","manifestSha256":"ab"}"#;
    let err = wapps::store::committed_epoch(body, "set A").expect_err("epoch'suz 200 gecmemeli");
    assert_eq!(
        err.code,
        wapps::clierr::Code::Internal,
        "eksik epoch bir protokol ihlali; rollback SUCLAMASI degil: {err}"
    );
    assert_ne!(err.code, wapps::clierr::Code::EpochDowngrade);
}

// --- `safeCode`: gate'ten gelen KOD dizesinin transcript'e girmeden once
//     gectigi budama -------------------------------------------------------
//
// NEDEN AYRI BIR TEST VE NEDEN SIMDI: bu port bir sure Go'nunkinden BASKA bir
// budama tasidi (satirsonlarini bosluga cevir + trim + 64 karaktere kirp) ve
// AYRISMA GORUNMUYORDU, cunku korpustaki her hata govdesi zaten temiz bir
// `SCREAMING_SNAKE` kodu tasiyordu. `whoami`nin 403 dali ile `token
// exchange`in 400 dali BOS bir kod gorebiliyor, ve orada iki taraf ayri
// seyler basiyor: Go "unknown", eski port bos dize.
//
// ORACLE: internal/store/worker.go safeCode. Uc kural var ve ucu de
// asagida ayri ayri geziliyor.
use wapps::store::map_http_error;
use wapps::clierr::Code;

#[test]
fn an_empty_gate_code_is_named_unknown_not_left_blank() {
    // 403 + BOS govde: hem `error` hem `dimension` bos -> IKI parantez de
    // "unknown". Bos dize basan bir port "whoami:  (dimension )" uretirdi.
    let e = map_http_error(403, "{}", 60, "whoami");
    assert_eq!(e.code, Code::GrantDenied);
    assert_eq!(e.message, "whoami: unknown (dimension unknown)");
}

#[test]
fn characters_outside_the_safe_class_are_dropped_not_escaped() {
    // `<`, `>`, `/`, bosluk ve satirsonu ATILIR — yerlerine hicbir sey
    // konmaz, yani parcalar BITISIR. Bir port onlari bosluga cevirseydi
    // (ya da kacisla yazsaydi) metin ayrisirdi.
    let e = map_http_error(400, r#"{"error":"BAD <b>code</b>\nsecond line"}"#, 60, "token exchange");
    assert_eq!(e.message, "token exchange: bad request (BADbcodebsecondline)");
}

#[test]
fn a_code_that_is_all_unsafe_characters_falls_back_to_unknown() {
    // Budamadan geriye HICBIR SEY kalmiyorsa sonuc yine "unknown" — Go'da
    // bu IKINCI bir kontrol (bos girdiden AYRI) ve atlanmasi kolay.
    let e = map_http_error(409, r#"{"error":"<<< >>>"}"#, 60, "set K");
    assert_eq!(e.message, "set K: unknown");
}

#[test]
fn a_long_code_is_truncated_to_forty_eight_bytes_before_cleaning() {
    // KIRPMA TEMIZLIKTEN ONCE: Go once 48 bayta kesiyor, sonra siniftan
    // olmayanlari atiyor. Sirayi ters ceviren bir port daha UZUN bir dize
    // basardi (kirpilan kisimda atilacak karakter varsa).
    let raw = format!("{}!!!!{}", "A".repeat(44), "B".repeat(40));
    let body = serde_json::json!({ "error": raw }).to_string();
    let e = map_http_error(409, &body, 60, "ctx");
    assert_eq!(e.message, format!("ctx: {}", "A".repeat(44)));
}
