// envwrite, zarf JSON'unu `export KEY='VALUE'` satirlarina cevirir.
//
// ORACLE: cmd/secrets/env.go (envName, writeTofuOutputsAsEnv). `apply`in
// yazdigi tuketim hedefleri bu bicimde.
use std::collections::BTreeMap;
use std::io::Write;

/// env_name, kaynak onekini bir anahtara IDEMPOTENT uygular: onekle ZATEN
/// baslayan bir anahtar aynen cikar, asla cift-oneklenmez.
///
/// Karisik bir anahtar kumesi dogru kalsin diye: Tofu ciktilari ciplak
/// saklaniyor (coolify_uuid → TF_VAR_coolify_uuid) ama dosya kaynakli sirlar
/// zaten onekli geliyor (TF_VAR_gemini_api_key) ve gidip gelirken
/// TF_VAR_TF_VAR_gemini_api_key olmamalilar.
pub fn env_name(prefix: &str, key: &str) -> String {
    if prefix.is_empty() || key.starts_with(prefix) {
        return key.to_string();
    }
    format!("{prefix}{key}")
}

// Envelope, {"KEY":{"value":...}} zarfinin tek girdisi.
//
// RawValue (Go'nun json.RawMessage'i) SART: exec'in env kurucusu string-olmayan
// bir degeri HAM haliyle tasiyor. serde_json::Value'ya cozmek bosluklari
// KAYBEDER ve `[1, 2]`yi `[1,2]` yapardi — Go'yla olculmus bir ayrisma.
#[derive(serde::Deserialize)]
struct Envelope {
    // deserialize_with SART: serde'nin duz `Option`u JSON `null`i None'a
    // cevirir ve boylece "alan YOK" ile "alan acikca null" AYNI seye duserdi.
    // Go bunlari AYIRIYOR (RawMessage nil vs []byte("null")) ve fark
    // gozlemlenebilir: null → 'null', eksik → ''.
    #[serde(default, deserialize_with = "de_raw_opt")]
    value: Option<Box<serde_json::value::RawValue>>,
}

// de_raw_opt, alan MEVCUT oldugunda — degeri `null` olsa bile — ham metni
// yakalar. Alan hic yoksa serde `default`a duser ve None kalir.
fn de_raw_opt<'de, D>(d: D) -> Result<Option<Box<serde_json::value::RawValue>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(d).map(Some)
}

// parse_archive, zarf haritasini SIRALI olarak cozer. BTreeMap, Go'nun
// keys+sort.Strings adimiyla ayni sirayi verir — determinizm testler ve git
// diff kararliligi icin sart.
pub(crate) fn parse_archive(
    json_input: &[u8],
    ctx: &str,
) -> Result<BTreeMap<String, Option<Box<serde_json::value::RawValue>>>, String> {
    let raw: BTreeMap<String, Envelope> =
        serde_json::from_slice(json_input).map_err(|e| format!("{ctx}: {e}"))?;
    Ok(raw.into_iter().map(|(k, v)| (k, v.value)).collect())
}

/// write_tofu_outputs_as_env, zarf JSON'unu `export <onek><anahtar>='<deger>'`
/// satirlarina cevirir.
///
/// Deger tipi dagitimi:
///   - string      → tek tirnak KACISIYLA duz kabuk degeri
///   - null        → literal 'null' (aksi halde sinyal sessizce kaybolurdu)
///   - liste/harita/bool/sayi → tek tirnak icinde SIKISTIRILMIS JSON. Tofu
///     TF_VAR_<ad>'i JSON olarak yeniden ayristiriyor, yani string-olmayan
///     tipler kayipsiz gidip geliyor.
pub fn write_tofu_outputs_as_env<W: Write>(
    json_input: &[u8],
    prefix: &str,
    w: &mut W,
) -> Result<(), String> {
    let outputs = parse_archive(json_input, "env: parse values")?;
    for (k, v) in &outputs {
        let name = env_name(prefix, k);
        let body = raw_to_env_body(v);
        // '\'' — tek tirnakli kabuk dizesinden cikip tirnak koyup geri girmek.
        // Bu kacis olmadan uretilen dosya `source` edilince kabugu bozar.
        let escaped = body.replace('\'', "'\\''");
        writeln!(w, "export {name}='{escaped}'").map_err(|e| format!("env: write: {e}"))?;
    }
    Ok(())
}

// raw_to_env_body, env DOSYASI icin bir zarf degerini govdeye cevirir.
//
// Sira Go ile ayni: once ham baytlar "null" mi diye bakilir, sonra string
// denenir, en son SIKISTIRILMIS JSON'a dusulur.
fn raw_to_env_body(v: &Option<Box<serde_json::value::RawValue>>) -> String {
    // Alan hic yoksa Go string(nil)=="" uretir; "null" DEGIL.
    let Some(raw) = v else { return String::new() };
    let text = raw.get().trim();
    if text == "null" {
        return "null".to_string();
    }
    if let Ok(s) = serde_json::from_str::<String>(text) {
        return s;
    }
    // String-olmayan: json.Compact'in karsiligi — bosluk artifakti kalmasin,
    // cunku Tofu bu degeri JSON olarak YENIDEN ayristiriyor.
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(val) => val.to_string(),
        // Gecerli JSON degilse Go da TrimSpace edip AYNEN basiyor.
        Err(_) => text.to_string(),
    }
}
