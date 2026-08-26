// `wapps dr` — felaket kurtarma verb'leri (server-decrypt SPEC §8.4).
//
// PORTLANAN: verify, split, combine.
// PORTLANMAYAN, ve NEDEN — bu liste bir eksiklik itirafi degil bir SINIR:
//
//   restore              XChaCha20-Poly1305 (24 BAYTLIK nonce) istiyor. `ring`
//                        onu TASIMIYOR (olculdu: kaynakta `xchacha` sifir kez,
//                        NONCE_LEN=12). Yani bu alt komut bir CRATE KARARI
//                        olmadan portlanamaz ve o karar Cargo.toml'daki `ring`
//                        gerekcesine dogrudan carpiyor ("ikinci bir kripto
//                        denetim yuzeyi"). Yarim bir restore YAZILMADI: bir
//                        kurtarma toreninin yarisi, olmamasindan daha kotudur.
//   bootstrap            `internal/tofu` PreflightEnv + BootstrapEnvVars
//                        portunu gerektiriyor.
//   accept-epoch-reset   store'da `AuditHead` rotasi ve `X-Wapps-Intent:
//                        epoch-reset` basligi YOK.
//
// Bu uc verb Go ikilisinde CALISMAYA DEVAM EDIYOR; Rust ikilisi onlari
// TANIMIYOR. Ayrisma BILINCLI ve differential korpusunda ADLANDIRILMIS
// durumda (bkz. cases.py, DR_EXCLUDED).
//
// AJAN POLITIKASI — ve bu bir duzenleme ayrintisi degil: `dr` KOKTE mount'lu
// (Go'da rootCmd.AddCommand(secrets.DrCmd)), yani SecretsCmd.PersistentPreRunE
// bu agac icin HIC kosmuyor. Ne ajan kapisi, ne depo-proje baglama kapisi.
// Her yaprak kendi guard'ini ELDE cagiriyor ve `verify` BILEREK guard'siz
// (hicbir sir kullanmiyor, `doctor`/`status` ile ayni gerekce). Port bu sirayi
// AYNEN korumali — fazladan bir kapi eklemek de bir ayrisma olurdu.
use crate::clierr::{Code, Error};
use crate::cryptoid::{self};
use crate::goerr;
use serde::Deserialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// --- snapshot v2 sekilleri (worker/src/manifest.ts paritesi) ---------------------

const SCHEMA_CURRENT_POINTER: &str = "wapps-secrets/current/v1";
const SCHEMA_DATA_MANIFEST: &str = "wapps-secrets/data-manifest/v2";

#[derive(Debug, Deserialize)]
pub struct SnapshotPointer {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default, rename = "manifestSha256")]
    pub manifest_sha256: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotWrap {
    #[serde(default)]
    pub recipient: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub wrap: String,
}

#[derive(Debug, Deserialize)]
pub struct SnapshotEntry {
    #[serde(default, rename = "keyName")]
    pub key_name: String,
    #[serde(default, rename = "keyVersion")]
    pub key_version: u64,
    #[serde(default, rename = "blobHash")]
    pub blob_hash: String,
    #[serde(default)]
    pub wrap: SnapshotWrap,
}

#[derive(Debug, Deserialize)]
pub struct SnapshotManifest {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub entries: Vec<SnapshotEntry>,
}

/// load_snapshot_project, bir projenin current head'ini yukler ve ZINCIRI
/// dogrular: pointer → manifest hash → sema → proje/epoch eslesmesi.
///
/// Zincirin sirasi onemli: hash pointer'dan gelen degere karsi manifest'in HAM
/// baytlari uzerinde hesaplanir, AYRISTIRMADAN ONCE. Once ayristirip sonra
/// yeniden serilestirmek (JSON alan sirasi/bosluk) hash'i degistirirdi.
pub fn load_snapshot_project(
    dir: &Path,
    project: &str,
) -> Result<(SnapshotManifest, SnapshotPointer), Error> {
    let cur_path = dir.join("secrets").join(project).join("current");
    let cur_raw = std::fs::read(&cur_path).map_err(|e| {
        // Go'nun *os.PathError metni ("open <yol>: <errno>"). Rust'in kendi
        // dizesi ("No such file or directory (os error 2)") buyuk harfli ve
        // numarali — sahadaki ikiliyle AYRISIR. Bu differential'da OLCULDU.
        Error::new(
            Code::Internal,
            format!(
                "snapshot: read current pointer for {project}: {}",
                goerr::open_error(&cur_path.display().to_string(), &e)
            ),
        )
    })?;
    let ptr: SnapshotPointer = match serde_json::from_slice(&cur_raw) {
        Ok(p) => p,
        Err(_) => {
            return Err(Error::new(
                Code::Internal,
                format!("snapshot: current pointer for {project} malformed"),
            ))
        }
    };
    if ptr.schema != SCHEMA_CURRENT_POINTER {
        return Err(Error::new(
            Code::Internal,
            format!("snapshot: current pointer for {project} malformed"),
        ));
    }
    let man_path = dir
        .join("secrets")
        .join(project)
        .join("manifests")
        .join(format!("{}.json", ptr.epoch));
    let man_raw = std::fs::read(&man_path).map_err(|e| {
        Error::new(
            Code::Internal,
            format!(
                "snapshot: read manifest epoch {} for {project}: {}",
                ptr.epoch,
                goerr::open_error(&man_path.display().to_string(), &e)
            ),
        )
    })?;
    if cryptoid::blob_hash(&man_raw) != ptr.manifest_sha256.to_ascii_lowercase() {
        return Err(Error::new(
            Code::BlobHashMismatch,
            format!(
                "snapshot: pointer/manifest hash mismatch for {project} (tamper or partial replica)"
            ),
        ));
    }
    let man: SnapshotManifest = match serde_json::from_slice(&man_raw) {
        Ok(m) => m,
        Err(_) => {
            return Err(Error::new(
                Code::Internal,
                format!("snapshot: manifest for {project} malformed/unsupported schema"),
            ))
        }
    };
    if man.schema != SCHEMA_DATA_MANIFEST {
        return Err(Error::new(
            Code::Internal,
            format!("snapshot: manifest for {project} malformed/unsupported schema"),
        ));
    }
    if man.project != project || man.epoch != ptr.epoch {
        return Err(Error::new(
            Code::Internal,
            format!("snapshot: manifest project/epoch mismatch for {project}"),
        ));
    }
    Ok((man, ptr))
}

/// snapshot_projects, snapshot dizinindeki proje adlarini (secrets/<p>/) doner.
/// SIRALI — Go `sort.Strings`. Siralamasiz birakmak, iki kosumun ciktisini
/// dosya sistemi sirasina baglardi.
pub fn snapshot_projects(dir: &Path) -> Result<Vec<String>, Error> {
    let sdir = dir.join("secrets");
    let rd = std::fs::read_dir(&sdir).map_err(|e| {
        // Go: os.ReadDir -> os.Open -> PathError{Op:"open"}.
        Error::new(
            Code::Internal,
            format!(
                "snapshot: list {}/secrets: {}",
                dir.display(),
                goerr::open_error(&sdir.display().to_string(), &e)
            ),
        )
    })?;
    let mut out = Vec::new();
    for ent in rd.flatten() {
        if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            out.push(ent.file_name().to_string_lossy().to_string());
        }
    }
    out.sort();
    Ok(out)
}

/// short, uzun bir hash'i ekran icin kisaltir: >16 ise ilk 16 + "…".
pub fn short(s: &str) -> String {
    if s.len() <= 16 {
        return s.to_string();
    }
    format!("{}…", &s[..16])
}

// --- dr verify --------------------------------------------------------------------

/// run_verify, replikanin YAPISAL butunlugunu dogrular. Sir KULLANMAZ, aga
/// CIKMAZ — hava-bosluklu bir kopyada kosar.
pub fn run_verify<W: Write>(w: &mut W, snapshot_dir: &Path) -> Result<(), Error> {
    let projects = snapshot_projects(snapshot_dir)?;
    for project in &projects {
        let (man, ptr) = load_snapshot_project(snapshot_dir, project)?;
        for e in &man.entries {
            let bp = snapshot_dir
                .join("secrets")
                .join(project)
                .join("blobs")
                .join(&e.blob_hash);
            let blob = std::fs::read(&bp).map_err(|err| {
                Error::new(
                    Code::Internal,
                    format!(
                        "snapshot: blob missing for {project}/{}: {}",
                        e.key_name,
                        goerr::open_error(&bp.display().to_string(), &err)
                    ),
                )
            })?;
            cryptoid::verify_blob_hash(&blob, &e.blob_hash).map_err(|err| {
                Error::new(
                    Code::BlobHashMismatch,
                    format!(
                        "snapshot: blob content-address mismatch for {project}/{}: {err}",
                        e.key_name
                    ),
                )
            })?;
            if e.wrap.recipient != cryptoid::WRAP_RECIPIENT {
                return Err(Error::new(
                    Code::Internal,
                    format!(
                        "snapshot: unsupported wrap recipient on {project}/{}",
                        e.key_name
                    ),
                ));
            }
        }
        let _ = writeln!(
            w,
            "  {:<20} epoch={} keys={} manifest={}",
            project,
            ptr.epoch,
            man.entries.len(),
            short(&ptr.manifest_sha256)
        );
    }
    let _ = writeln!(
        w,
        "✓ snapshot VERIFIED ({} project(s), {})",
        projects.len(),
        snapshot_dir.display()
    );
    Ok(())
}

// --- pay dosyalari ------------------------------------------------------------------

/// write_secret_file_0600, gizli baytlari YENI bir 0600 dosyaya yazar; dosya
/// VARSA hata verir (O_EXCL).
///
/// NEDEN atomicfile DEGIL: atomicfile gecici dosya + rename yapiyor, yani var
/// olan bir dosyayi SESSIZCE degistirir. Burada istenen tam TERSI. Ve O_EXCL
/// iki seyi birden onluyor: onceden var olan GEVSEK IZINLI bir dosyayi
/// clobber etmeyi, VE "var olan dosyanin modu degismez" tuzagini (duz bir
/// yazici 0644 bir dosyayi 0644 birakir, 0600 sozlesmesi sessizce bozulur).
pub fn write_secret_file_0600(path: &Path, b: &[u8]) -> Result<(), Error> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::new(
                Code::Internal,
                format!(
                    "refusing to overwrite existing {} (remove it or pick a fresh path)",
                    path.display()
                ),
            ))
        }
        Err(e) => {
            return Err(Error::new(
                Code::Internal,
                format!(
                    "create {}: {}",
                    path.display(),
                    goerr::path_error("open", &path.display().to_string(), &e)
                ),
            ))
        }
    };
    f.write_all(b)
        .map_err(|e| Error::new(Code::Internal, format!("write {}: {e}", path.display())))?;
    Ok(())
}

/// read_share_files, hex-kodlu pay dosyalarini okur (bosluk/yenisatir tolere).
/// Operator paylari elle tasiyor; bicimlendirmeye toleransli olmak sozlesme.
pub fn read_share_files(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let raw = std::fs::read_to_string(p).map_err(|e| {
            Error::new(
                Code::Internal,
                format!(
                    "read share {}: {}",
                    p.display(),
                    goerr::open_error(&p.display().to_string(), &e)
                ),
            )
        })?;
        let clean: String = raw.split_whitespace().collect();
        let b = unhex(&clean).ok_or_else(|| {
            Error::new(Code::Internal, format!("share {} is not hex", p.display()))
        })?;
        out.push(b);
    }
    Ok(out)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// wipe, verilen tamponu sifirlar (best-effort bellek temizligi).
///
/// DURUST SINIR — Go yorumu da bunu soyluyor: `master_hex` bir STRING ve wipe
/// EDILEMIYOR. Rust'ta bu bosluk `Zeroizing<String>` ile kapatilabilirdi ama o
/// zaman iki ikili BELLEK HIJYENI olarak ayrisirdi. Bilincli olarak
/// KAPATILMADI: bu dilimin sozlesmesi Go ile parite.
fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
}

// --- dr split ------------------------------------------------------------------------

/// run_split_core, split seremonisinin cekirdegi (TTY guard'i CAGIRANDA).
///
/// RNG PARAMETRE — bu bir tasarim kisiti, kolaylik degil: sabitlenseydi
/// `split` frozen vektorle pinlenemez ve (RNG yuzunden differential'lanamadigi
/// icin) HIC olculemezdi.
pub fn run_split_core<W: Write>(
    w: &mut W,
    out_dir: &Path,
    parts: usize,
    threshold: usize,
    master_hex: &str,
    rng: &mut dyn Read,
) -> Result<(), Error> {
    if out_dir.as_os_str().is_empty() {
        return Err(Error::new(
            Code::Internal,
            "dr split: --out-dir <dir> is required (0600 share files land there)",
        ));
    }
    if threshold < 2 || parts < threshold {
        return Err(Error::new(
            Code::Internal,
            format!(
                "dr split: need parts >= threshold >= 2 (got parts={parts} threshold={threshold})"
            ),
        ));
    }
    let master_hex = master_hex.trim();
    let mut master = match unhex(master_hex) {
        Some(m) if m.len() == 32 => m,
        _ => {
            return Err(Error::new(
                Code::Internal,
                "dr split: MASTER_KEK must be 64 hex chars (32 bytes)",
            ))
        }
    };
    let kid = cryptoid::kek_kid(&master)
        .map_err(|e| Error::new(Code::Internal, format!("derive kid: {e}")))?;
    let mut shares = cryptoid::shamir_split(&master, parts, threshold, rng)
        .map_err(|e| Error::new(Code::Internal, format!("shamir split: {e}")))?;

    // ROUND-TRIP SAGLAMASI — ve NEDEN yazmadan ONCE: ShamirCombine yanlis
    // paylarda hata VERMEZ, yani "paylar geri donuyor mu" sorusunun tek
    // cevabi denemektir. Denemeden yazilsa, kurtarilamaz paylar diske
    // gecerdi ve bu ancak GERCEK felakette anlasilirdi.
    let check: Vec<Vec<u8>> = shares[..threshold].to_vec();
    match cryptoid::shamir_combine(&check) {
        Ok(back) if back == master => {}
        _ => {
            return Err(Error::new(
                Code::Internal,
                "dr split: round-trip check FAILED — shares would not reconstruct (aborted, nothing written)",
            ))
        }
    }

    std::fs::create_dir_all(out_dir)
        .map_err(|e| Error::new(Code::Internal, format!("create out-dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out_dir, std::fs::Permissions::from_mode(0o700));
    }

    let _ = writeln!(
        w,
        "MASTER_KEK kid: {kid}  (this is the key these shares reconstruct — verify against the live Worker)"
    );
    for (i, s) in shares.iter().enumerate() {
        let p = out_dir.join(format!("wapps-master-share-{}-of-{}.hex", i + 1, parts));
        write_secret_file_0600(&p, format!("{}\n", hexs(s)).as_bytes())?;
        let _ = writeln!(w, "  wrote {}", p.display());
    }
    wipe(&mut master);
    for s in shares.iter_mut() {
        wipe(s);
    }
    let _ = writeln!(
        w,
        "\n✓ {parts} shares written (any {threshold} reconstruct). NOW:"
    );
    let _ = writeln!(
        w,
        "  1) move each file to a SEPARATE offline place (paper safe / YubiKey / trusted person)"
    );
    let _ = writeln!(
        w,
        "  2) delete {} afterwards. NEVER commit shares to git or store them together.",
        out_dir.display()
    );
    Ok(())
}

// --- dr combine ----------------------------------------------------------------------

/// run_combine_core, >=threshold paydan MASTER_KEK'i geri kurar ve 0600 yazar.
///
/// BU FONKSIYON YANLIS PAYLARDA DA BASARIR. Bu bir kusur degil Shamir'in
/// kendisi: butunluk SAGLAMAZ. Tek savunma basilan kid'dir — ve asagidaki
/// uyari satiri, operatore o kid'i karsilastirmasini soyleyen TEK sey. Uyari
/// duserse bir kurtarma toreni SESSIZCE yanlis tamamlanir ve bu ancak sifre
/// cozulemedigi anda, yani EN KOTU ANDA anlasilir.
pub fn run_combine_core<W: Write>(
    w: &mut W,
    share_paths: &[PathBuf],
    out: &Path,
) -> Result<(), Error> {
    if share_paths.len() < 2 {
        return Err(Error::new(
            Code::ActionUnavailable,
            "dr combine needs >=2 --share files",
        ));
    }
    if out.as_os_str().is_empty() {
        return Err(Error::new(
            Code::Internal,
            "dr combine: --out <file> is required (the key is NEVER printed)",
        ));
    }
    let mut shares = read_share_files(share_paths)?;
    let mut master = cryptoid::shamir_combine(&shares)
        .map_err(|e| Error::new(Code::Internal, format!("reconstruct MASTER_KEK: {e}")))?;
    if master.len() != 32 {
        return Err(Error::new(
            Code::Internal,
            format!(
                "reconstructed MASTER_KEK is {} bytes, want 32 (wrong/mismatched shares?)",
                master.len()
            ),
        ));
    }
    let kid = cryptoid::kek_kid(&master)
        .map_err(|e| Error::new(Code::Internal, format!("derive kid: {e}")))?;
    write_secret_file_0600(out, format!("{}\n", hexs(&master)).as_bytes())?;
    wipe(&mut master);
    for s in shares.iter_mut() {
        wipe(s);
    }
    let _ = writeln!(
        w,
        "✓ MASTER_KEK reconstructed → {} (0600, kid {kid})",
        out.display()
    );
    let _ = writeln!(
        w,
        "  ⚠ VERIFY this kid matches split's / the live Worker's kid BEFORE use — too few or"
    );
    let _ = writeln!(
        w,
        "    mismatched shares yield a silently-WRONG 32-byte key (no error). Then:"
    );
    let _ = writeln!(
        w,
        "  npx wrangler secret put MASTER_KEK < {}   # then: rm {}",
        out.display(),
        out.display()
    );
    Ok(())
}
