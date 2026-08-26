// `wapps dr` — felaket kurtarma verb'leri (server-decrypt SPEC §8.4).
//
// PORTLANAN: verify, restore, split, combine.
// PORTLANMAYAN, ve NEDEN — bu liste bir eksiklik itirafi degil bir SINIR:
//
//   bootstrap            `internal/tofu` PreflightEnv + BootstrapEnvVars
//                        portunu gerektiriyor; Rust'ta `tofu` modulu YOK.
//   accept-epoch-reset   store'da `AuditHead` rotasi ve `X-Wapps-Intent:
//                        epoch-reset` basligi YOK.
//
// Bu iki verb Go ikilisinde CALISMAYA DEVAM EDIYOR; Rust ikilisi onlari
// TANIMIYOR. Ayrisma BILINCLI ve differential korpusunda ADLANDIRILMIS
// durumda (bkz. cases.py, DR bloğunun baslik yorumu). Yarim bir alt komut
// YAZILMADI: bir kurtarma toreninin yarisi, olmamasindan daha kotudur.
//
// `restore` BU SERITTE INDI ve onu mumkun kilan sey bir onceki turun kendi
// iddiasini CURUTMESIYDI: "XChaCha `ring`de yok, yani yeni bir crate lazim"
// olcumu yerinde DOGRUYDU ama sonucu yanlisti — XChaCha = HChaCha20 +
// ring'in ZATEN tasidigi ChaCha20-Poly1305. Cargo.toml'a TEK bir crate
// eklenmedi (bkz. cryptoid.rs, docs/PORT-dr.md §7.1).
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
        // Manifest'teki wrap kid'leri: bu projenin ciphertext'ini acabilecek
        // MASTER_KEK NESLINI adlandirirlar. Normalde tek bir kid vardir;
        // rotasyon sirasinda iki nesil BIR ARADA olabilir, o yuzden kume
        // olarak toplanip deterministik sirayla basiliyor.
        let mut kid_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
            kid_set.insert(if e.wrap.kid.is_empty() {
                "-".to_string()
            } else {
                e.wrap.kid.clone()
            });
        }
        let kids = if kid_set.is_empty() {
            "-".to_string()
        } else {
            kid_set.into_iter().collect::<Vec<_>>().join(",")
        };
        let _ = writeln!(
            w,
            "  {:<20} epoch={} keys={} kid={} manifest={}",
            project,
            ptr.epoch,
            man.entries.len(),
            kids,
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
/// BU FONKSIYON, `expect_kid` VERILMEDIKCE, YANLIS PAYLARDA DA BASARIR. Bu bir
/// kusur degil Shamir'in kendisi: butunluk SAGLAMAZ — yanlis ya da eksik
/// paylar hata vermeden 32 baytlik BASKA bir anahtar uretir. Tek ayirt edici
/// isaret kid'dir.
///
/// `expect_kid` o karsilastirmayi OPERATORUN GOZUNDEN alip ARACA veriyor.
/// Zorunlu DEGIL ve bu bilincli: operatorun elinde replika olmayabilir
/// (`wapps dr verify` kid'i replikadan basar, ama bu fiil hava-bosluklu bir
/// makinede paylar disinda hicbir seyle de calisabilmeli).
/// Verilmediginde uyari satiri artik SADECE riski degil OTOMATIK YOLU da
/// soyluyor — eski metin "bu kid'i dogrula" diyordu ama karsilastirilacak
/// degerin NEREDE oldugunu soylemiyordu.
pub fn run_combine_core<W: Write>(
    w: &mut W,
    share_paths: &[PathBuf],
    out: &Path,
    expect_kid: &str,
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
    // Operator bu degeri bir terminalden ELLE tasiyor: bosluk ve BUYUK harf
    // tolere edilir. Karsilastirmanin kendisi tam esitlik.
    let want = expect_kid.trim().to_lowercase();
    if !want.is_empty() && want != kid {
        // FAIL-CLOSED, ve SIRA onemli: dosya HENUZ yazilmadi. Once yazip sonra
        // hata vermek, reddedilen bir torenden geriye YANLIS anahtari tasiyan
        // 0600 bir dosya birakirdi.
        wipe(&mut master);
        for s in shares.iter_mut() {
            wipe(s);
        }
        return Err(Error::new(
            Code::ActionUnavailable,
            format!(
                "reconstructed key's kid {kid} does not match --expect-kid {want} — too few or mismatched shares (NOTHING was written; run 'wapps dr verify --snapshot <dir>' to read the replica's kid)"
            ),
        ));
    }
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
    if expect_kid.trim().is_empty() {
        let _ = writeln!(
            w,
            "  ⚠ kid NOT verified — too few or mismatched shares yield a silently-WRONG"
        );
        let _ = writeln!(
            w,
            "    32-byte key (no error). Re-run with --expect-kid <kid> to make this check"
        );
        let _ = writeln!(
            w,
            "    automatic; 'wapps dr verify --snapshot <dir>' prints the replica's kid."
        );
    } else {
        let _ = writeln!(
            w,
            "  ✓ kid MATCHES --expect-kid (these shares reconstruct the expected key)"
        );
    }
    let _ = writeln!(
        w,
        "  npx wrangler secret put MASTER_KEK < {}   # then: rm {}",
        out.display(),
        out.display()
    );
    Ok(())
}

/// b64_decode, standart base64'u (RFC 4648, DOLGULU) cozer — Go'nun
/// `base64.StdEncoding.DecodeString`inin karsiligi.
///
/// ELDE YAZILDI cunku agacta base64 crate'i YOK ve `dr` icin bir tane eklemek
/// Cargo.toml'daki gerekceyi (bkz. `ring`) bir satirlik bir cozumleyici icin
/// delmek olurdu.
///
/// KATI, ve katilik burada bir PARITE sartidir — Go'nun StdEncoding'i de
/// katidir:
///   * uzunluk 4'un kati OLMALI (aksi halde CorruptInputError),
///   * dolgu ('=') YALNIZCA sonda ve en fazla iki tane,
///   * alfabe disi HER karakter (yenisatir DAHIL) reddedilir.
///
/// Gevsek bir cozumleyici, Go'nun REDDETTIGI bir manifest'i KABUL ederdi ve
/// bu bir ayrisma olurdu.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    if b.is_empty() {
        return Some(Vec::new());
    }
    let mut pad = 0usize;
    while pad < 2 && b[b.len() - 1 - pad] == b'=' {
        pad += 1;
    }
    let body = &b[..b.len() - pad];
    // Govdede dolgu KALMAMALI (ornegin "A=B=" reddedilir).
    if body.contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in body.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        match chunk.len() {
            4 => {
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
                out.push(acc as u8);
            }
            3 => {
                let acc = acc << 6;
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
            }
            2 => {
                let acc = acc << 12;
                out.push((acc >> 16) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

// --- dr restore ----------------------------------------------------------------------
//
// Kurtarma toreninin KENDISI: >=2 Shamir payi + bir B2 snapshot'i -> MASTER_KEK
// -> per-proje KEK (§2.3) -> WKW1 DEK unwrap (§2.4) -> WSB1 blob acma (§3.5.4)
// -> 0600 env dosyasi. SIFIR Cloudflare bagimliligi.
//
// PORTLANABILDI cunku "ring'de XChaCha yok" ile "XChaCha portlanamaz" AYNI SEY
// DEGIL: XChaCha = HChaCha20 (bir permutasyon) + ring'in ZATEN tasidigi duz
// ChaCha20-Poly1305. Bkz. cryptoid.rs'teki turetim ve docs/PORT-dr.md §7.1 —
// Cargo.toml'a TEK bir crate eklenmedi.
//
// DEGERLER ASLA BASILMAZ. Ne stdout'a, ne hata metnine: bir hata mesajina
// dusen tek sey anahtar ADI'dir. Cikti yalnizca SAYI verir ("N value(s)").

/// write_restored_env_file, KEY=value satirlarini 0600 ATOMIK yazar
/// (tmp + rename), ASLA stdout'a.
///
/// O_EXCL YOK ve bu `write_secret_file_0600`dan BILINCLI bir ayrim: Go da
/// burada `os.WriteFile` + rename kullaniyor, yani var olan bir --out dosyasi
/// EZILIR. Bir kurtarma torenini "dosya zaten var" diye yarida kesmek, o
/// dosyanin onceki (muhtemelen basarisiz) bir denemeden kalmis olmasi
/// ihtimalinde toreni tikardi. Parite bilincli.
///
/// TUZAK — VE KAPATILDI: tmp dosyayi duz bir yazici ile acmak, tmp ONCEDEN
/// VARSA modunu DEGISTIRMEZ; 0644 kalmis bir artik uzerine yazilirsa gizli
/// degerler dunyaya okunur olurdu. tmp bu yuzden O_EXCL ile acilir.
fn write_restored_env_file(path: &Path, lines: &[Vec<u8>]) -> Result<(), Error> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    // Go: strings.Join(lines, "\n") + "\n". BOS proje de tek bir yenisatir
    // yazar (Join(nil) == "") — bir tuhaflik ama sahadaki davranis.
    let mut body: Vec<u8> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if i > 0 {
            body.push(b'\n');
        }
        body.extend_from_slice(l);
    }
    body.push(b'\n');
    // Artik bir tmp varsa once kaldir ki O_EXCL modu garanti etsin.
    let _ = std::fs::remove_file(&tmp);
    write_secret_file_0600(&tmp, &body)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::new(
            Code::Internal,
            format!(
                "finalize {}: rename {} {}: {}",
                path.display(),
                tmp.display(),
                path.display(),
                goerr::bare_errno(&e)
            ),
        )
    })?;
    Ok(())
}

/// restore_project_from_snapshot, restore seremonisinin cekirdegidir (TTY
/// guard'i CAGIRANDA — `split`/`combine` ile ayni ayrim, test edilebilirlik
/// icin).
///
/// SIRA GUVENLIK ACISINDAN ONEMLI ve Go ile AYNEN korunmali:
///   1. paylar -> MASTER_KEK -> kid
///   2. snapshot zinciri (pointer -> manifest hash) dogrulanir
///   3. HER giris icin ONCE kid karsilastirilir (yanlis nesil = ERKEN dusus),
///      SONRA icerik adresi, SONRA unwrap, SONRA blob acilir
///
/// kid kontrolu one alinmazsa yanlis bir MASTER_KEK ancak AEAD'de duserdi ve
/// hata "tamper" gibi gorunurdu — operatoru YANLIS teshise gonderirdi.
pub fn restore_project_from_snapshot<W: Write>(
    w: &mut W,
    snapshot_dir: &Path,
    project: &str,
    share_paths: &[PathBuf],
    out_path: &Path,
) -> Result<(), Error> {
    let mut shares = read_share_files(share_paths)?;
    let mut master = cryptoid::shamir_combine(&shares).map_err(|e| {
        Error::new(
            Code::Internal,
            format!("reconstruct MASTER_KEK from shares: {e}"),
        )
    })?;
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

    let (man, ptr) = load_snapshot_project(snapshot_dir, project)?;

    let mut lines: Vec<Vec<u8>> = Vec::new();
    for e in &man.entries {
        if e.wrap.kid != kid {
            return Err(Error::new(
                Code::Internal,
                format!(
                    "wrap kid {} on {} does not match the reconstructed key's kid {kid} — wrong MASTER_KEK generation (older shares? see §2.5 rotation)",
                    e.wrap.kid, e.key_name
                ),
            ));
        }
        let wrap_bytes = b64_decode(&e.wrap.wrap).ok_or_else(|| {
            Error::new(
                Code::Internal,
                format!("wrap for {} not base64", e.key_name),
            )
        })?;
        let bp = snapshot_dir
            .join("secrets")
            .join(project)
            .join("blobs")
            .join(&e.blob_hash);
        let blob = std::fs::read(&bp).map_err(|err| {
            Error::new(
                Code::Internal,
                format!(
                    "blob missing for {}: {}",
                    e.key_name,
                    goerr::open_error(&bp.display().to_string(), &err)
                ),
            )
        })?;
        cryptoid::verify_blob_hash(&blob, &e.blob_hash).map_err(|err| {
            Error::new(
                Code::BlobHashMismatch,
                format!("blob content-address mismatch for {}: {err}", e.key_name),
            )
        })?;
        let slot = cryptoid::Slot::new(project, &e.key_name, e.key_version);
        let mut dek =
            cryptoid::unwrap_dek_with_kek(&master, project, &slot, &wrap_bytes).map_err(|err| {
                Error::new(
                    Code::Internal,
                    format!(
                        "DEK unwrap failed for {} (tamper or key mismatch): {err}",
                        e.key_name
                    ),
                )
            })?;
        let pt = cryptoid::open_blob(&blob, &dek, &slot).map_err(|err| {
            Error::new(
                Code::Internal,
                format!("blob open failed for {}: {err}", e.key_name),
            )
        })?;
        wipe(&mut dek);
        // Go: `e.KeyName + "=" + string(pt)`. `string(pt)` GECERSIZ UTF-8
        // baytlari AYNEN tasir — Go string'i bir bayt dizisidir. Rust'ta
        // `String::from_utf8_lossy` onlari U+FFFD'ye cevirirdi ve yazilan
        // DOSYA AYRISIRDI (bir sir her zaman gecerli UTF-8 degildir; ornegin
        // ham bir anahtar baytı). Satirlar bu yuzden BAYT olarak tasiniyor.
        let mut line: Vec<u8> = Vec::with_capacity(e.key_name.len() + 1 + pt.len());
        line.extend_from_slice(e.key_name.as_bytes());
        line.push(b'=');
        line.extend_from_slice(&pt);
        lines.push(line);
    }

    write_restored_env_file(out_path, &lines)?;
    wipe(&mut master);
    for s in shares.iter_mut() {
        wipe(s);
    }
    let _ = writeln!(
        w,
        "✓ RESTORED {project} (epoch {}): {} value(s) → {} (0600; values never printed)",
        ptr.epoch,
        lines.len(),
        out_path.display()
    );
    let _ = writeln!(
        w,
        "NEXT (human half): re-provision the estate from this file, then ROTATE every restored value — see 'wapps rotate-plan'."
    );
    Ok(())
}
