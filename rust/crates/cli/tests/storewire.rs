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
