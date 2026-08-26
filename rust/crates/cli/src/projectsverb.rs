// projectsverb, KOKTE mount'lu `wapps projects` ailesi: store'daki PROJELERI
// listeler ve (admin) bir projenin tamamini kaldirir.
//
// NEDEN KOKTE, `secrets` altinda DEGIL: bir proje sirlardan bagimsiz bir
// kavramdir (kokteki `--project` bayragi da oyle).
//
// KOK MOUNT'UN SONUCU — ve bu, portun kolayca kaciracagi yer: Go'da
// SecretsCmd.PersistentPreRunE (ajan-guard + depo pini) BU AILEDE CALISMAZ, o
// yuzden her yaprak KENDI guard'ini cagirir ve depo→proje BAGLAMA KONTROLU HIC
// YAPILMAZ. Ikisi de GLOBAL op'tur — bir repo→proje baglamasina bagli
// degildirler.
//
// Gozlemlenebilir sonucu OLCULDU: `--project testproj` ile ajan modunda
// `projects list` CALISIR, ama ayni bayrakla `secrets list` BINDING_UNPINNED
// ile duser. Iki fiil ayni sinifta ("yalnizca adlar") ama ayni kapinin
// arkasinda DEGILLER.
//
// YETKI MODELI iki verb icin KASITLI olarak farklidir:
//   - list → proje-metadata `read` (data-plane). Ajan serbest: yalnizca ADlar.
//   - rm   → global `admin` verb'i + write-AUD (control-plane), ajan REDDEDILIR.
//     Bir projeyi silmek, oradaki her anahtari silmenin toplamidir; per-key
//     `delete` grant'i buna YETMEZ.
//
// ORACLE: cmd/secrets/projects.go.

/// render, gorunur proje adlarini satir basina bir tane basar.
///
/// SUNUCU SIRASI AYNEN korunur (`secrets list`in aksine istemci sort'u YOK):
/// filtreleme sunucuda yapiliyor ve istemcide gizli bir siralama, sunucunun
/// sirasinin bir anlam tasidigi durumda onu sessizce yok ederdi.
pub fn render(projects: &[String]) -> String {
    let mut out = String::new();
    for p in projects {
        out.push_str(p);
        out.push('\n');
    }
    out
}

/// rm_prompt, proje silme onayidir — projeyi ADIYLA gosterir.
pub fn rm_prompt(project: &str) -> String {
    format!(
        "Remove project {project} and ALL of its keys? This cannot be undone. \
         Type 'yes' to confirm: "
    )
}

/// rm_success_line, silme sonucudur.
///
/// Pointer-event izi TUTULUYORSA bu ACIKCA soylenir: o iz, projenin var
/// oldugunun tamper-evident kaydi ve onu silmek temiz bir gecmis UYDURMAK
/// olurdu. Sessizce tutmak ile soyleyerek tutmak arasindaki fark, operatorun
/// DR kaydinin durdugunu bilmesidir.
pub fn rm_success_line(project: &str, deleted_objects: i64, pointer_events_kept: bool) -> String {
    let mut s = format!("✓ Removed project {project} ({deleted_objects} objects)\n");
    if pointer_events_kept {
        s.push_str("  pointer-event trail kept (append-only DR record)\n");
    }
    s
}
