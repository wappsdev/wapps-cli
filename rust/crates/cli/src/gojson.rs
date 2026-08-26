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
            w.write_all(&frag.as_bytes()[last..i])?;
            w.write_all(esc.as_bytes())?;
            last = i + c.len_utf8();
        }
        w.write_all(&frag.as_bytes()[last..])
    }
}

/// to_string, Go-uyumlu kacisla tek satir JSON uretir.
pub fn to_string<T: serde::Serialize>(v: &T) -> serde_json::Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscape);
    v.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json her zaman gecerli UTF-8 uretir"))
}

/// GoEscapePretty, `json.MarshalIndent(v, "", "  ")` ile AYNI baytlari uretir:
/// serde_json'in girintili duzeni + Go'nun fazladan kacirdigi bes karakter.
///
/// Neden gerekli: epoch pin dosyasi Go ikilisiyle PAYLASILAN bir dosya. Iki
/// ikili ayni pin'i farkli baytlarla yazarsa, dosyayi karsilastiran her olcum
/// (differential dahil) sahte bir fark gorur — ve daha kotusu, iki ikili
/// arasinda gidip gelen bir kullanicida dosya her seferinde yeniden yazilir.
pub struct GoEscapePretty<'a> {
    inner: serde_json::ser::PrettyFormatter<'a>,
}

impl Default for GoEscapePretty<'_> {
    fn default() -> Self {
        GoEscapePretty { inner: serde_json::ser::PrettyFormatter::with_indent(b"  ") }
    }
}

impl Formatter for GoEscapePretty<'_> {
    fn write_string_fragment<W>(&mut self, w: &mut W, frag: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        GoEscape.write_string_fragment(w, frag)
    }

    fn begin_array<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_array(w)
    }
    fn end_array<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_array(w)
    }
    fn begin_array_value<W>(&mut self, w: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_array_value(w, first)
    }
    fn end_array_value<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_array_value(w)
    }
    fn begin_object<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_object(w)
    }
    fn end_object<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_object(w)
    }
    fn begin_object_key<W>(&mut self, w: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_object_key(w, first)
    }
    fn begin_object_value<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_object_value(w)
    }
    fn end_object_value<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_object_value(w)
    }
}

/// to_string_indent, Go-uyumlu kacisla 2-bosluk girintili JSON uretir
/// (`json.MarshalIndent(v, "", "  ")`). Sonda newline YOKTUR — Go da koymuyor.
pub fn to_string_indent<T: serde::Serialize>(v: &T) -> serde_json::Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscapePretty::default());
    v.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json her zaman gecerli UTF-8 uretir"))
}

/// quote, Go'nun `%q`'sunu taklit eder.
///
/// SINIR: Rust'in `{:?}`'si ile Go'nun strconv.Quote'u yazdirilamayan
/// karakterlerde ayrisir (`\u{7}` vs `\a`). Bu yolun tasidigi degerler proje ve
/// anahtar ADLARI — o kumede iki bicim ayni. Ayrisan bir ad gorulurse burasi
/// elle yazilmalidir; sessizce dogru saymak icin degil, bilerek kabul edildi.
pub fn quote(s: &str) -> String {
    format!("{s:?}")
}
