// listverb, `wapps secrets list` — projenin anahtar ADLARI, DEGER asla.
//
// METADATA duzlemi (§7.1): adlar GET /keys'ten geliyor, Store.Read
// CAGRILMIYOR, yani audit'e `value.read` DUSMEZ. Liste Worker'da principal'in
// read grant'ina filtreleniyor (§4.3.3) — istemci kendi kendine eleme YAPMAZ.
//
// Ajan modunda SERBEST: basilan sey yalnizca adlar, `get`in reddedilme sebebi
// (duz metin deger) burada yok.
//
// ORACLE: cmd/secrets/list.go, cmd/secrets/store_backend.go (runListStore).

/// render, adlari SIRALAYIP satir basina bir tane basar.
///
/// Siralama ISTEMCIDE (Go: sort.Strings) ve BAYT duzeyinde — locale-duyarli
/// bir siralama Go ile ayrisirdi. `projects list` bunun tersi: orada sunucu
/// sirasi AYNEN korunuyor.
pub fn render(names: &[String]) -> String {
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort();
    let mut out = String::new();
    for n in sorted {
        out.push_str(n);
        out.push('\n');
    }
    out
}
