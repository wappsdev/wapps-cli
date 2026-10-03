// initverb, `wapps secrets init` — bu dilimdeki TEK ureten fiil.
//
// Digerleri `.wapps.yaml`i OKUYOR; bu onu YAZIYOR. Sonucu kendi
// ayristiricimizin okuyabildigi tests/initverb.rs'te olculuyor, ve uretilen
// baytlar Go'nunkiyle BIREBIR karsilastiriliyor: bu dosya bir INSANIN
// duzenledigi bir sablon, yani yorum satirlari ve bosluklar sozlesmenin
// parcasi. "Ayni anlamda" yeterli degil.
//
// ORACLE: cmd/secrets/init.go (runInitStore, writeWappsYAMLStore).
//
// YEREL ARSIV YOK (SPEC §6.1): tek bir dosya yazilir, repoya sifreli hicbir
// sey konmaz — degerler gate'te yasar. Sonraki adimlar: login → trust-repo → set.
use std::path::Path;

/// WAPPS_YAML, olusturulan dosyanin adidir.
pub const WAPPS_YAML: &str = ".wapps.yaml";

/// render, v2 `backend:store` sablonunu uretir.
///
/// Sablonun KENDISI sozlesme: `targets:` blogu YORUMDA duruyor (yorum isaretini
/// dusuren bir degisiklik `apply`i sessizce farkli davrandirirdi) ve
/// `backend:` satiri HIC yazilmiyor (absent == store; yazmak eski ikilileri
/// gereksizce v2'ye zorlardi).
pub fn render(project: &str) -> String {
    let mut b = String::new();
    b.push_str("# wapps-cli configuration\n");
    b.push_str("# Docs: https://github.com/wappsdev/wapps-cli\n");
    b.push('\n');
    b.push_str("version: 2\n");
    b.push_str("# The project this repo reads from in the secrets gate.\n");
    b.push_str("project: ");
    b.push_str(project);
    b.push('\n');
    b.push('\n');
    b.push_str("# Optional consumption targets. 'wapps secrets apply' materializes these\n");
    b.push_str("# from the store — atomic, mode 0600, idempotent. Gitignore them.\n");
    b.push_str("# targets:\n");
    b.push_str("#   - path: .env.local\n");
    b.push_str("#     prefix: \"\"\n");
    b
}

/// run, iskeleti kurar ve BASILACAK metni doner.
///
/// `project` bossa depo kokunun DIZIN adina duser. Metni burada dondurup
/// cagirana bastirmak bilincli: Go tarafi `fmt.Println` ile dogrudan stdout'a
/// yaziyor ve test edilemez birakiyor; burada ayni baytlar test edilebilir.
pub fn run(repo_root: &str, project: &str, force: bool) -> Result<String, String> {
    let project = if project.is_empty() {
        // Go: filepath.Base(filepath.Abs(repoRoot)).
        let abs =
            abs_path(repo_root).map_err(|e| format!("secrets.init: resolve repo root: {e}"))?;
        Path::new(&abs)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| abs.clone())
    } else {
        project.to_string()
    };

    // Yol, Go'nun filepath.Join'i gibi TEMIZLENIYOR: repo koku "." iken mesaja
    // giren ad "./.wapps.yaml" degil ".wapps.yaml" olmali (olculdu).
    let yaml_path = go_join(repo_root, WAPPS_YAML);

    match std::fs::metadata(&yaml_path) {
        // Dosya VAR ve dizin degil → --force olmadan ASLA ezme.
        Ok(md) if !md.is_dir() && !force => {
            return Err(format!(
                "secrets.init: {yaml_path} already exists (use --force to overwrite)"
            ))
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("secrets.init: stat {yaml_path}: {e}")),
    }

    // Mod 0644 — Go ile AYNI. Bu dosya SIR TASIMIYOR (yalnizca proje adi) ve
    // repoya commit ediliyor; `apply`in 0600 hedefleriyle karistirilmamali.
    write_0644(Path::new(&yaml_path), render(&project).as_bytes())
        .map_err(|e| format!("secrets.init: write {yaml_path}: {e}"))?;

    let mut out = String::new();
    out.push_str("✓ wapps init complete (backend: store)\n");
    out.push_str("  + ");
    out.push_str(&yaml_path);
    out.push('\n');
    out.push_str("\nNext steps:\n");
    out.push_str("  1. wapps login                 # CF Access browser SSO\n");
    out.push_str("  2. wapps secrets trust-repo    # pin this repo to project ");
    out.push_str(&project);
    out.push('\n');
    out.push_str("  3. wapps secrets set <KEY>     # first set creates the manifest chain\n");
    out.push_str("     (an admin adds policy rows: wapps secrets policy set)\n");
    Ok(out)
}

fn write_0644(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // os.WriteFile ile AYNI semantik: varsa TRUNCATE, yoksa 0644 ile olustur.
    // Var olan bir dosyanin modu DEGISMEZ (Go da degistirmiyor) — --force ile
    // ezilen bir dosya kendi modunu korur.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    f.write_all(data)
}

fn abs_path(p: &str) -> std::io::Result<String> {
    let path = Path::new(p);
    if path.is_absolute() {
        return Ok(p.to_string());
    }
    Ok(std::env::current_dir()?
        .join(path)
        .to_string_lossy()
        .into_owned())
}

// go_join, Go'nun filepath.Join'i gibi birlestirir ve TEMIZLER.
//
// Neden elle: Rust'in Path::join'i temizlemiyor, yani `join(".", ".wapps.yaml")`
// "./.wapps.yaml" veriyor. O dize hata mesajina ve "  + <yol>" satirina
// giriyor, yani fark GOZLENEBILIR — differential'da init vakalari tam olarak
// bunu geziyor.
fn go_join(a: &str, b: &str) -> String {
    if a.is_empty() {
        return go_clean(b);
    }
    if b.is_empty() {
        return go_clean(a);
    }
    go_clean(&format!("{a}/{b}"))
}

// go_clean, path.Clean'in bu kullanim icin gereken yarisidir: tekrar eden
// ayiraclar, "." ogeleri ve cozulebilir ".." ogeleri atilir.
fn go_clean(p: &str) -> String {
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if let Some(last) = out.last() {
                    if *last != ".." {
                        out.pop();
                        continue;
                    }
                }
                if rooted {
                    continue; // kokun ustune cikilmaz
                }
                out.push("..");
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if rooted {
        return format!("/{joined}");
    }
    if joined.is_empty() {
        return ".".to_string();
    }
    joined
}
