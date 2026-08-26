// policy, policy.json'un ISTEMCI-TARAFI dogrulamasi + lint'idir.
//
// ORACLE: internal/policy/policy.go.
//
// BU BIR YETKILENDIRME KAYNAGI DEGIL. Authz kaynagi SUNUCUDUR; Worker ayni
// semayi PUT'ta ZORLUYOR. Buradaki kopya yalnizca `policy lint`/`policy set`in
// hizli, cevrimdisi on-kontroludur — ve degeri "dogru karar vermek"ten cok
// "GO ILE AYNI karari AYNI CUMLEYLE vermek"tir: bu metinleri bir insan okuyor
// ve reddedilen bir policy dosyasinda elindeki tek ipucu o cumle.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// SCHEMA_POLICY, sema tanimlayicisi (§4.2).
pub const SCHEMA_POLICY: &str = "wapps-secrets/policy/v1";

// POLICY_VERBS, KAPALI verb kumesi. `delete` write'tan AYRIDIR ve hicbir verb
// tarafindan IMA EDILMEZ — worker/src/policy.ts ile birebir ayni kume.
const POLICY_VERBS: &[&str] = &["read", "write", "rotate", "delete", "admin"];

const GLOB_MAX_LEN: usize = 256;

/// Rule, policy.json kural seklidir (§4.2).
///
/// ALAN SIRASI ve `skip_serializing_if` GO STRUCT ETIKETLERINDEN geliyor, bir
/// Rust tercihi degil: `policy set` bu dokumani gate'e AYNEN gonderiyor ve gate
/// aldigi BAYTLARIN sha256'sini geri veriyor. Sira ya da omitempty bir yerde
/// ayrisirsa basilan sha ayrisir — sahte gate'in PUT rotasi tam olarak bunu
/// olcuyor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub aud: String,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub verbs: Vec<String>,
}

/// PolicyDoc, policy.json dokuman seklidir (§4.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

// --- Glob (pinli sozdizimi, §4.2) --------------------------------------------
//
// `*` = herhangi bir dizi (bos dahil), `?` = tek karakter, gerisi literal,
// case-sensitive, TAM-string eslesme.

/// glob_match, pinli glob semantigiyle TAM-string eslesme yapar
/// (§4.2 case-SENSITIVE).
pub fn glob_match(glob: &str, s: &str) -> bool {
    // Klasik geri-izlemeli glob esleyici (yalnizca * ve ?). Go BAYT uzerinden
    // yuruyor; burada da bayt dilimleri kullaniliyor ki cok-baytli bir
    // karakterde `?` sayimi ayrismasin.
    let (g, s) = (glob.as_bytes(), s.as_bytes());
    let (mut gi, mut si) = (0usize, 0usize);
    let (mut star, mut star_si): (Option<usize>, usize) = (None, 0);
    while si < s.len() {
        if gi < g.len() && (g[gi] == b'?' || g[gi] == s[si]) {
            gi += 1;
            si += 1;
        } else if gi < g.len() && g[gi] == b'*' {
            star = Some(gi);
            star_si = si;
            gi += 1;
        } else if let Some(st) = star {
            gi = st + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
    while gi < g.len() && g[gi] == b'*' {
        gi += 1;
    }
    gi == g.len()
}

// key_glob_match, anahtar-ADI eslesmesidir: glob_match'i CASE-INSENSITIVE
// uygular. Anahtar adlari POSIX env-var (karisik harf) olabildiginden
// case-insensitive KIMLIKtir — Worker enforcement ile ayni semantik.
// glob_match'in KENDISI §4.2 pinli case-sensitive kalir.
fn key_glob_match(glob: &str, key: &str) -> bool {
    glob_match(&glob.to_lowercase(), &key.to_lowercase())
}

/// expand_verbs, rule.verbs'i efektif kumeye acar: "*" = besi; rotate ⊃ write
/// (§4.2). `delete` IMA EDILMEZ — acikca yazilmali ya da "*" ile gelmeli.
pub fn expand_verbs(verbs: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for v in verbs {
        if v == "*" {
            for pv in POLICY_VERBS {
                out.insert((*pv).to_string());
            }
            continue;
        }
        if POLICY_VERBS.contains(&v.as_str()) {
            out.insert(v.clone());
        }
        if v == "rotate" {
            out.insert("write".to_string());
        }
    }
    out
}

// is_common_name, `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$` — ELDE, cunku bu tek
// desen icin bir regex bagimliligi eklemek `deny.toml`daki grafigi buyuturdu.
fn is_common_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 128 {
        return false;
    }
    if !b[0].is_ascii_alphanumeric() {
        return false;
    }
    b[1..].iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// validate, §4.4 dokuman-ici dogrulamasini uygular (Worker paritesi;
/// version-CAS kontrolu SUNUCUDADIR). `topology` "primary" iken aud
/// selector'lu kurallar reddedilir (dead rule). Hata mesaji kural index'ini
/// ADLANDIRIR — operatorun dosyada nereye bakacagini bilmesinin tek yolu.
pub fn validate(doc: &PolicyDoc, topology: &str) -> Result<(), String> {
    if doc.schema != SCHEMA_POLICY {
        return Err(format!("policy: schema must be {SCHEMA_POLICY}"));
    }
    if doc.version < 1 {
        return Err("policy: version must be a positive integer".to_string());
    }
    for (i, r) in doc.rules.iter().enumerate() {
        let selectors = [&r.group, &r.service, &r.aud].iter().filter(|s| !s.is_empty()).count();
        if selectors != 1 {
            return Err(format!("policy: rule[{i}]: exactly one of group/service/aud required"));
        }
        if !r.aud.is_empty() && topology == "primary" {
            return Err(format!(
                "policy: rule[{i}]: aud selectors are valid only in the FALLBACK topology; rejected in PRIMARY"
            ));
        }
        if !r.service.is_empty() && !is_common_name(&r.service) {
            return Err(format!("policy: rule[{i}].service not a valid common_name"));
        }
        if r.projects.is_empty() {
            return Err(format!("policy: rule[{i}].projects must be a non-empty array"));
        }
        for g in &r.projects {
            if g.is_empty() || g.len() > GLOB_MAX_LEN || g.starts_with('!') {
                return Err(format!(
                    "policy: rule[{i}].projects: invalid glob {}",
                    crate::gojson::quote(g)
                ));
            }
        }
        if r.keys.is_empty() {
            return Err(format!("policy: rule[{i}].keys must be a non-empty array"));
        }
        let mut positive = 0;
        for g in &r.keys {
            if g.is_empty() || g == "!" || g.len() > GLOB_MAX_LEN {
                return Err(format!(
                    "policy: rule[{i}].keys: invalid glob {}",
                    crate::gojson::quote(g)
                ));
            }
            if !g.starts_with('!') {
                positive += 1;
            }
        }
        if positive == 0 {
            return Err(format!("policy: rule[{i}].keys: at least one positive glob required"));
        }
        if r.verbs.is_empty() {
            return Err(format!("policy: rule[{i}].verbs must be a non-empty array"));
        }
        for v in &r.verbs {
            if v != "*" && !POLICY_VERBS.contains(&v.as_str()) {
                return Err(format!(
                    "policy: rule[{i}].verbs: unknown verb {}",
                    crate::gojson::quote(v)
                ));
            }
        }
    }
    Ok(())
}

// --- Lint (§7.3 kurallari a–e; UYARI uretir, BLOKLAMAZ) ----------------------

/// Warning, bir lint bulgusudur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// a|b|c|d|e
    pub rule: &'static str,
    /// ilgili kural index'i
    pub index: usize,
    pub message: String,
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lint({}) rule[{}]: {}", self.rule, self.index, self.message)
    }
}

// selector_of, bir kuralin principal selector anahtarini doner.
fn selector_of(r: &Rule) -> String {
    if !r.group.is_empty() {
        format!("group:{}", r.group)
    } else if !r.service.is_empty() {
        format!("service:{}", r.service)
    } else {
        format!("aud:{}", r.aud)
    }
}

// concretize, bir glob'un TEMSILI dizesini uretir: '*'→"" ve '?'→"x".
fn concretize(glob: &str) -> String {
    glob.replace('*', "").replace('?', "x")
}

// globs_intersect_heuristic, iki glob'un kesisebilecegini SEZGISEL tespit eder
// (tam glob-kesisimi kararsizliga yakin pahalidir; lint icin yeterli).
// Anahtar-glob'lari CASE-INSENSITIVE kesisir (enforcement ile tutarli).
fn globs_intersect_heuristic(a: &str, b: &str) -> bool {
    key_glob_match(a, &concretize(b))
        || key_glob_match(b, &concretize(a))
        || a.eq_ignore_ascii_case(b)
}

// can_match_prod, glob'un *_PROD_* desenli bir anahtari eslesip
// esleyemeyecegini yoklar. Case-insensitive: `*_prod_*` KACMASIN.
fn can_match_prod(key_glob: &str) -> bool {
    if key_glob.to_lowercase().contains("_prod_") {
        return true;
    }
    let probe = key_glob.replace('*', "_PROD_").replace('?', "x");
    key_glob_match(key_glob, &probe) && key_glob_match("*_prod_*", &probe)
}

// denied_by_rule, key'in kuralin deny glob'larindan birine takildigini doner.
// Deny CASE-INSENSITIVE eslesir: kucuk-harf bir ad varyanti bir deny glob'unu
// atlatmasin.
fn denied_by_rule(r: &Rule, key: &str) -> bool {
    r.keys.iter().any(|g| g.starts_with('!') && key_glob_match(&g[1..], key))
}

/// lint, §7.3 kurallarini uygular:
///
///   (a) bir kuralda deny'lanan anahtar deseni, ORTUSEN bir principal kumesine
///       baska bir kuralla allow ediliyor (deny kural-KAPSAMLIDIR);
///   (b) *_PROD_* esleyebilen anahtarlara admin-disi GRUP kurallariyla
///       write/rotate/delete VEYA plaintext read grant'i (read, server-decrypt
///       modelde DAHA tehlikeli verb);
///   (c) erisilemez (tamamen golgelenmis / yinelenen) kurallar;
///   (d) verbs ["*"] tasiyan service satirlari;
///   (e) admin granting kurallarda proje/anahtar kapsamasi (admin op'lari
///       GLOBAL — kapsam OLUdur ve yaniltir).
///
/// SIRA SOZLESMENIN PARCASI: (d),(e),(b),(a) kural basina ana donguden;
/// (c) AYRI bir dongude, yani DAIMA en sonda. Uyarilar bu sirayla basiliyor.
pub fn lint(doc: &PolicyDoc) -> Vec<Warning> {
    let mut out = Vec::new();
    let rules = &doc.rules;

    for (i, r) in rules.iter().enumerate() {
        let verbs = expand_verbs(&r.verbs);

        // (d) service + ["*"].
        if !r.service.is_empty() {
            for v in &r.verbs {
                if v == "*" {
                    out.push(Warning {
                        rule: "d",
                        index: i,
                        message: format!(
                            "service row {} grants verbs [\"*\"] — scope service tokens to the narrowest verb set",
                            crate::gojson::quote(&r.service)
                        ),
                    });
                }
            }
        }

        // (e) admin + OLU proje/anahtar kapsamasi.
        if verbs.contains("admin") {
            let scoped = r.projects.iter().any(|p| p != "*") || r.keys.iter().any(|k| k != "*");
            if scoped {
                out.push(Warning {
                    rule: "e",
                    index: i,
                    message: "rule grants `admin` with project/key scoping — admin ops are GLOBAL (§4.2); the scoping is dead and misleads reviewers".to_string(),
                });
            }
        }

        // (b) *_PROD_* anahtarlarina admin-disi grup grant'i (read DAHIL).
        if !r.group.is_empty()
            && !verbs.contains("admin")
            && (verbs.contains("read")
                || verbs.contains("write")
                || verbs.contains("rotate")
                || verbs.contains("delete"))
        {
            for g in &r.keys {
                if g.starts_with('!') {
                    continue;
                }
                let probe = g.replace('*', "_PROD_").replace('?', "x");
                if can_match_prod(g) && !denied_by_rule(r, &probe) {
                    out.push(Warning {
                        rule: "b",
                        index: i,
                        message: format!(
                            "group {} can reach *_PROD_*-matching keys via {} — plaintext read is the MOST dangerous verb in a server-decrypt model; consider a \"!*_PROD_*\" deny glob",
                            crate::gojson::quote(&r.group),
                            crate::gojson::quote(g)
                        ),
                    });
                    break;
                }
            }
        }

        // (a) deny'lanan desen baska kuralda ORTUSEN principal'a allow.
        for g in &r.keys {
            if !g.starts_with('!') {
                continue;
            }
            let deny_pat = &g[1..];
            for (j, s) in rules.iter().enumerate() {
                if j == i || selector_of(s) != selector_of(r) {
                    continue;
                }
                for ag in &s.keys {
                    if ag.starts_with('!') {
                        continue;
                    }
                    if globs_intersect_heuristic(deny_pat, ag) {
                        out.push(Warning {
                            rule: "a",
                            index: i,
                            message: format!(
                                "deny glob {} is overridden for the same principal set by rule[{j}]'s allow {} (deny is rule-scoped, §4.3.2)",
                                crate::gojson::quote(g),
                                crate::gojson::quote(ag)
                            ),
                        });
                    }
                }
            }
        }
    }

    // (c) erisilemez/yinelenen kurallar (sezgisel alt-kume tespiti).
    for (i, r) in rules.iter().enumerate() {
        for (j, s) in rules.iter().enumerate() {
            if i == j || selector_of(r) != selector_of(s) {
                continue;
            }
            if rule_subsumes(s, r) && (j < i || !rule_subsumes(r, s)) {
                out.push(Warning {
                    rule: "c",
                    index: i,
                    message: format!(
                        "rule appears unreachable: rule[{j}] already grants a superset for the same selector"
                    ),
                });
                break;
            }
        }
    }
    out
}

// rule_subsumes, a'nin b'yi kapsadigini SEZGISEL doner.
//
// Kapsam CASE-SENSITIVE'dir (allow tarafiyla tutarli: anahtar adlari
// case-sensitive kimlik; yalniz DENY case-insensitive'dir, kapsam allow
// golgelemesidir).
fn rule_subsumes(a: &Rule, b: &Rule) -> bool {
    let (av, bv) = (expand_verbs(&a.verbs), expand_verbs(&b.verbs));
    if !bv.is_subset(&av) {
        return false;
    }
    if a.keys.iter().any(|g| g.starts_with('!')) {
        return false;
    }
    let covers = |a_globs: &[String], b_globs: &[String]| -> bool {
        b_globs.iter().filter(|bg| !bg.starts_with('!')).all(|bg| {
            a_globs
                .iter()
                .any(|ag| ag == "*" || ag == bg || glob_match(ag, &concretize(bg)))
        })
    };
    covers(&a.projects, &b.projects) && covers(&a.keys, &b.keys)
}
