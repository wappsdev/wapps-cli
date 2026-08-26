// `StoreValues`in sozlesmesi — ve DIFFERENTIAL'DA OLCULEMEDIGI icin burada.
//
// Bu, portun tek "verb olmayan" parcasi: `cmd/secrets/archive_values.go` bir
// komut degil, `wapps deploy`in credential fallback'i icin bir kutuphane
// fonksiyonu. `wapps deploy` bu dilimde PORTLANMADI, yani hicbir pty vakasi
// buraya ulasmiyor ve differential bu kodun VAR OLDUGUNU bile gormuyor.
//
// Vakalar cmd/secrets/archive_values_test.go'nun dortlusunun karsiligidir ve
// ayni dort seyi soruyor. Ucu bir GUVENLIK ozelligi:
//
//   * config yok → (None), HATA DEGIL: store kullanmayan bir projede deploy
//     kirilmasin;
//   * ad duzlemi kesisimi ONCE: bulk read all-or-nothing, yani var olmayan tek
//     bir aday TUM okumayi NOT_FOUND ile dusururdu;
//   * bos kesisim → gate'e HIC gidilmez: audit ledger'ina olmamis bir okuma
//     satiri dusmez, ve `rotate-plan` tam olarak o ledger'i oracle sayiyor;
//   * gercek okuma hatasi AYNEN yuzer (grant reddi yutulmaz).
//
// GERCEK SIR YOK: asagidaki degerler uydurma test dizeleridir.
use std::cell::RefCell;
use std::collections::BTreeMap;
use wapps::clierr::{Code, Error};
use wapps::storevalues::{store_values, wanted_subset};

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

// Sahte store: Go'daki installFakeStore'un karsiligi. CAGRILARI SAYIYOR,
// cunku olculen seylerden biri "kac cagri yapildigi" (bos kesisimde SIFIR
// okuma).
#[derive(Default)]
struct FakeStore {
    values: BTreeMap<String, String>,
    keys_calls: RefCell<usize>,
    read_calls: RefCell<Vec<(String, Vec<String>)>>,
    read_err: Option<Code>,
}

impl FakeStore {
    fn keys(&self, project: &str) -> Result<Vec<String>, Error> {
        let _ = project;
        *self.keys_calls.borrow_mut() += 1;
        Ok(self.values.keys().cloned().collect())
    }
    fn read(&self, project: &str, keys: &[String]) -> Result<BTreeMap<String, String>, Error> {
        self.read_calls.borrow_mut().push((project.to_string(), keys.to_vec()));
        if let Some(code) = self.read_err {
            return Err(Error::new(code, "denied on key"));
        }
        Ok(keys
            .iter()
            .filter_map(|k| self.values.get(k).map(|v| (k.clone(), v.clone())))
            .collect())
    }
}

fn fake(pairs: &[(&str, &str)]) -> FakeStore {
    FakeStore {
        values: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        ..Default::default()
    }
}

// Istenen adaylardan yalnizca store'da VAR olanlar okunur: bulk read'e eksik
// bir ad SIZMAZ (all-or-nothing NOT_FOUND tuzagi), ve donen harita yalnizca
// mevcut degerleri tasir — "yok" ile "bos" AYNI SEY DEGIL.
#[test]
fn only_the_keys_that_exist_are_read() {
    let f = fake(&[
        ("DEPLOY_PROXY_TOKEN_VAULTER", "tok-store"),
        ("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "id-store"),
    ]);
    let got = store_values(
        Some("testproj"),
        &s(&[
            "DEPLOY_PROXY_TOKEN_VAULTER",
            "DEPLOY_PROXY_TOKEN",
            "PROXY_TOKEN",
            "DEPLOY_PROXY_CF_ACCESS_CLIENT_ID",
        ]),
        &|p| f.keys(p),
        &|p, k| f.read(p, k),
    )
    .expect("store_values")
    .expect("config var sayiliyor");

    assert_eq!(got.get("DEPLOY_PROXY_TOKEN_VAULTER").map(String::as_str), Some("tok-store"));
    assert_eq!(got.get("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID").map(String::as_str), Some("id-store"));
    assert!(
        !got.contains_key("PROXY_TOKEN"),
        "eksik anahtarlar sonucta YOK olmali, present-empty DEGIL"
    );
    assert_eq!(*f.keys_calls.borrow(), 1, "ad duzlemi TAM BIR KEZ sorulmali");
    let calls = f.read_calls.borrow();
    assert_eq!(calls.len(), 1, "tam bir bulk okuma beklenir");
    assert_eq!(calls[0].0, "testproj");
    let mut got_keys = calls[0].1.clone();
    got_keys.sort();
    assert_eq!(
        got_keys,
        s(&["DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "DEPLOY_PROXY_TOKEN_VAULTER"]),
        "okuma YALNIZCA mevcut anahtarlari istemeli"
    );
}

// Hicbir aday store'da yoksa gate'e HIC gidilmez. Bu bir performans notu
// degil bir AUDIT ozelligi: olmamis bir okuma ledger'a dusmemeli, ve
// `rotate-plan` o ledger'i rotate-set oracle'i sayiyor.
#[test]
fn an_empty_intersection_performs_no_read_at_all() {
    let f = fake(&[("UNRELATED_KEY", "x")]);
    let got = store_values(
        Some("testproj"),
        &s(&["DEPLOY_PROXY_TOKEN_VAULTER", "PROXY_TOKEN"]),
        &|p| f.keys(p),
        &|p, k| f.read(p, k),
    )
    .expect("store_values")
    .expect("config var");
    assert!(got.is_empty(), "bos harita beklenir, alindi: {got:?}");
    assert!(
        f.read_calls.borrow().is_empty(),
        "bos kesisimde HICBIR value.read yapilmamali"
    );
}

// Config yok → (None), hata DEGIL, ve store'a HIC dokunulmaz. Cagiran
// (deploy) hatasiz env-only cozumlemeye duser.
#[test]
fn without_a_config_it_returns_none_and_never_touches_the_store() {
    let f = fake(&[("DEPLOY_PROXY_TOKEN_VAULTER", "tok")]);
    let got = store_values(None, &s(&["DEPLOY_PROXY_TOKEN_VAULTER"]), &|p| f.keys(p), &|p, k| {
        f.read(p, k)
    })
    .expect("config yoklugu bir hata DEGIL");
    assert!(got.is_none(), "config yokken None beklenir");
    assert_eq!(*f.keys_calls.borrow(), 0);
    assert!(f.read_calls.borrow().is_empty(), "backend:store config'i olmadan store'a dokunulmamali");
}

// GERCEK bir okuma hatasi (ornegin grant reddi) AYNEN yuzer. Yutulsaydi
// deploy sessizce env'e duser ve operator bir YETKI reddini bir "anahtar yok"
// sanirdi — bu portun kapatmaya calistigi sinifin ta kendisi.
#[test]
fn a_real_read_error_propagates_instead_of_being_swallowed() {
    let mut f = fake(&[("DEPLOY_PROXY_TOKEN_VAULTER", "tok")]);
    f.read_err = Some(Code::GrantDenied);
    let err = store_values(
        Some("testproj"),
        &s(&["DEPLOY_PROXY_TOKEN_VAULTER"]),
        &|p| f.keys(p),
        &|p, k| f.read(p, k),
    )
    .expect_err("GRANT_DENIED yuzmeli");
    assert_eq!(err.code, Code::GrantDenied);
}

// Ayni aday iki kez istenirse bulk istege iki kez GIRMEZ (Go'daki
// `present[k] = false` hilesinin karsiligi), ve sira ISTENEN sira olarak
// korunur — alfabetik DEGIL.
#[test]
fn a_repeated_candidate_is_requested_once_and_order_is_preserved() {
    let present = s(&["A", "B", "C"]);
    assert_eq!(wanted_subset(&present, &s(&["C", "A", "C", "B", "A"])), s(&["C", "A", "B"]));
    assert_eq!(wanted_subset(&present, &s(&["Z"])), Vec::<String>::new());
}
