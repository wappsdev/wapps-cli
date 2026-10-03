// policyverb, `wapps secrets policy` ailesinin OKUNABILIR yuzeyidir:
// dosya okuma, kural render'i, diff ve rapor satirlari.
//
// ORACLE: cmd/secrets/policy.go.
//
// KURAL RENDER'I NEDEN KRITIK: `policy set`in bastigi diff, bir admin'in
// "neyi degistiriyorum" sorusuna verdigi TEK cevap. Diff, kural METNI uzerinden
// KUME farki aliyor (kurallar sira-bagimsizdir §4.3), yani render'daki bir
// ayrisma diff'i sessizce YANLIS gosterir: silinmemis bir kural silinmis
// gorunur ve admin onu geri koymaya calisir.
use crate::clierr::{Code, Error};
use crate::policy::{self, PolicyDoc, Rule};
use std::collections::BTreeSet;
use std::path::Path;

/// POLICY_TOPOLOGY, PRIMARY/FALLBACK secimi — Worker'daki TOPOLOGY sabitiyle
/// hizali. PRIMARY'de aud selector'leri istemci lint'inde de reddedilir.
pub const POLICY_TOPOLOGY: &str = "primary";

/// render_rule, bir kurali TEK satir insan-okunur basar. DEGER ICERMEZ.
pub fn render_rule(r: &Rule) -> String {
    // Go'daki SIRA: once group, service EZER, aud ONU EZER. Dogrulamadan gecmis
    // bir dokuman tek selector tasir; ama `show` gate'in dondugu dokumani
    // dogrulamadan basiyor, yani sira gozlemlenebilir.
    let mut sel = format!("group={}", r.group);
    if !r.service.is_empty() {
        sel = format!("service={}", r.service);
    }
    if !r.aud.is_empty() {
        sel = format!("aud={}", r.aud);
    }
    format!(
        "{sel} projects=[{}] keys=[{}] verbs=[{}]",
        r.projects.join(","),
        r.keys.join(","),
        r.verbs.join(",")
    )
}

/// rule_diff, kural listelerinin farkini basar: RENDER EDILMIS metin uzerinden
/// basit kume farki, cunku policy kurallari SIRA-BAGIMSIZDIR.
pub fn rule_diff(old_rules: &[Rule], new_rules: &[Rule]) -> String {
    let old_set: BTreeSet<String> = old_rules.iter().map(render_rule).collect();
    let new_set: BTreeSet<String> = new_rules.iter().map(render_rule).collect();

    let mut out = String::from("rule diff:\n");
    let mut changed = false;
    // Sira: once SILINENLER (girdi sirasinda), sonra EKLENENLER — Go ile ayni.
    for r in old_rules {
        let t = render_rule(r);
        if !new_set.contains(&t) {
            out.push_str(&format!("  - {t}\n"));
            changed = true;
        }
    }
    for r in new_rules {
        let t = render_rule(r);
        if !old_set.contains(&t) {
            out.push_str(&format!("  + {t}\n"));
            changed = true;
        }
    }
    if !changed {
        out.push_str("  (no rule changes)\n");
    }
    out
}

/// short12, uzun bir sha'yi goruntu icin kisaltir.
pub fn short12(s: &str) -> String {
    if s.len() <= 12 {
        return s.to_string();
    }
    // Go BAYT dilimliyor; sha hex oldugu icin ASCII, yine de karakter
    // sinirinda kalmak icin yuvarlaniyor.
    let mut i = 12;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    format!("{}…", &s[..i])
}

/// render_show, `policy show`un insan-okunur raporudur.
pub fn render_show(version: u64, sha256: &str, doc: &PolicyDoc) -> String {
    let mut out = format!(
        "version: {version}\nsha256:  {sha256}\nrules:   {}\n",
        doc.rules.len()
    );
    for (i, r) in doc.rules.iter().enumerate() {
        out.push_str(&format!("  [{i}] {}\n", render_rule(r)));
    }
    out
}

/// read_policy_file, bir policy dosyasini okur + SEMA dogrular.
///
/// UC AYRI HATA SINIFI, ve ayrimlari gozlemlenebilir:
///   - okunamadi  → INTERNAL (dosya sistemi sorunu, policy'nin sucu degil)
///   - JSON degil → POLICY_INVALID
///   - sema ihlali→ POLICY_INVALID
///
/// `version` alani YOKSA 1 kabul edilir; `set` yolu sunucudan gelen
/// current+1 ile UZERINE yazar.
pub fn read_policy_file(path: &Path) -> Result<PolicyDoc, Error> {
    let p = path.to_string_lossy().to_string();
    let raw = std::fs::read(path).map_err(|e| {
        Error::new(
            Code::Internal,
            format!("read policy file {p}: {}", crate::goerr::open_error(&p, &e)),
        )
    })?;
    let mut doc: PolicyDoc = serde_json::from_slice(&raw).map_err(|e| {
        Error::new(
            Code::PolicyInvalid,
            format!("policy file {p} not valid JSON: {}", go_json_error(&e)),
        )
    })?;
    if doc.version == 0 {
        doc.version = 1;
    }
    policy::validate(&doc, POLICY_TOPOLOGY)
        .map_err(|e| Error::new(Code::PolicyInvalid, format!("policy file {p} invalid: {e}")))?;
    Ok(doc)
}

// go_json_error, serde'nin ayristirma hatasini Go'nun encoding/json cumlesine
// cevirir — YALNIZCA cevrilebildigi yerde.
//
// TEK KAPALI VAKA: DisallowUnknownFields'in karsiligi. Go bunu
// `json: unknown field "x"` diye basiyor (OLCULDU) ve bu sabit, kucuk, tam bir
// esleme. Bir policy dosyasindaki yazim hatasi bu daldan geciyor, yani en sik
// okunan cumle bu.
//
// GERISI CEVRILMIYOR ve bu bilincli: Go'nun SOZDIZIMI hatalari ayristiricinin
// ic durumunu tasiyor ("invalid character 't' looking for beginning of object
// key string") ve serde'ninki bambaska. Elde taklit etmek SAHTE bir sadakat
// olurdu — bir sonraki bozuk dosyada kirilacak bir yalan. O dal differential'da
// ACIKCA disarida birakiliyor (cases.py EXCLUDED).
fn go_json_error(e: &serde_json::Error) -> String {
    let msg = e.to_string();
    if let Some(rest) = msg.strip_prefix("unknown field `") {
        if let Some(end) = rest.find('`') {
            return format!("json: unknown field {}", crate::gojson::quote(&rest[..end]));
        }
    }
    msg
}
