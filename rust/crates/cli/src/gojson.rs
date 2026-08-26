// gojson, serde_json'i Go'nun `encoding/json`'i gibi kacis yapmaya zorlar.
//
// NEDEN: sahada kurulu `wapps` ikilileri zarfi Go ile uretiyor ve Go varsayilan
// olarak `<`, `>`, `&` (HTML guvenligi) ile U+2028/U+2029'u (JSONP guvenligi)
// \uXXXX yaziyor. serde_json bunlarin HICBIRINI yazmiyor. Ayrisma OLCULDU ve tam
// olarak bu bes karakter; alan sirasi, bosluk ve `retryable` zaten birebir ayni.
//
// Karar: GOLDENLAR degil SERIALIZER degisti. Gerekce, bu dilimde tek yonlu:
// goldenlari degistirmek sahadaki bir tuketici icin davranis degisikligi olurdu,
// serializer'i hizalamak ise hicbir seyi degistirmiyor — ayni baytlari uretiyor.
use serde_json::ser::Formatter;
use std::io;

pub struct GoEscape;

impl Formatter for GoEscape {
    // serde_json, kacis GEREKTIRMEYEN parcalari buradan geciriyor (tirnak, ters
    // bolu ve kontrol karakterleri zaten ayri ele aliniyor). Go'nun fazladan
    // kacirdigi bes karakteri burada yakaliyoruz.
    fn write_string_fragment<W>(&mut self, w: &mut W, frag: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut last = 0usize;
        for (i, c) in frag.char_indices() {
            let esc = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            w.write_all(frag[last..i].as_bytes())?;
            w.write_all(esc.as_bytes())?;
            last = i + c.len_utf8();
        }
        w.write_all(frag[last..].as_bytes())
    }
}

/// to_string, Go-uyumlu kacisla tek satir JSON uretir.
pub fn to_string<T: serde::Serialize>(v: &T) -> serde_json::Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscape);
    v.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json her zaman gecerli UTF-8 uretir"))
}
