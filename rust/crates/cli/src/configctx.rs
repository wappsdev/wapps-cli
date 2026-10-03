// configctx, "hangi `.wapps.yaml`" sorusunu ve ondan tureyen BAGLAMA kapisini
// tasir.
//
// ORACLE: cmd/root.go (resolveProjectFlag), cmd/secrets/sync.go
// (wappsConfigPath, loadOrNil), cmd/secrets/store_backend.go
// (requireStoreConfig, storeProject), cmd/secrets/agentgate.go
// (checkRepoBinding, repoIdentity).
//
// BU DILIMIN ACTIGI IKI KAPI — `exec`/`apply` tam olarak bunlarin arkasindaydi:
//
//   1. `--project` config gereksinimini ATLATMIYOR. get/set yalnizca proje
//      ADINA ihtiyac duyar (storeProject); exec/apply targets/sources OKUR,
//      yani yerel dosya SART (requireStoreConfig).
//   2. Config varken `--project` yoksa, pinlenmemis bir baglama INSAN/TTY
//      yolunda satir ici ONAY ister.
use crate::binding;
use crate::clierr::{Code, Error};
use crate::projects;
use crate::wappsyaml::{self, WappsYaml};
use std::io::Write;
use std::path::{Path, PathBuf};

/// WAPPS_YAML_PATH, --config/--project override'i yokken kullanilan
/// (cwd-goreli) varsayilan dosya adi.
pub const WAPPS_YAML_PATH: &str = ".wapps.yaml";

/// Ctx, cozulmus config baglamidir.
///
/// `project_override`: `--project <ad>` VERILDI ama kayit defterinde YOK.
/// Store'un ihtiyaci olan tek sey ad oldugundan (list/get/rm/projects yerel
/// dosyaya hic bakmaz) boyle bir cagri deposuz calisir. exec/apply icin ise
/// yeterli DEGILDIR — kendi net "no .wapps.yaml found" hatalarini verirler.
pub struct Ctx {
    pub config_path: Option<PathBuf>,
    pub project_override: Option<String>,
}

/// MUTUALLY_EXCLUSIVE, `--config` + `--project` reddinin TEK metin kaynagi.
///
/// SABIT, fonksiyon DEGIL — cunku iki cagiran onu FARKLI SARIYOR ve fark
/// OLCULDU:
///
///   * dispatch (main.rs) → `CmdError::Plain`. Go'da bu hata root'un
///     `PersistentPreRunE`undan DUZ bir `fmt.Errorf` olarak donuyor, yani
///     insan yolunda "Error: <cumle>" basiliyor — kod oneki YOK, kurtarma
///     satiri YOK. Ilk duzeltme burada `Error::new(Code::Internal, ...)`
///     kullandi ve ajan yolu ESITLENDI ama INSAN yolu ayrisik kaldi
///     (differential DIFFERENT=1): Rust "Error: INTERNAL: ... → run wapps
///     doctor" basiyordu. `Plain` ajan modunda zaten Internal'a sariliyor,
///     yani ZARF da dogru kaliyor.
///   * `Ctx::resolve` → yapisal `Error`. Bu yol programatik/test cagrilari
///     icin duruyor (Go'daki `resolveProjectFlag`in kendi kontrolu gibi) ve
///     dispatch onu yakaladigi icin SAHADAN ERISILEMEZ.
///
/// Metin iki yere KOPYALANSAYDI biri gunun birinde otekinden ayrisirdi.
pub const MUTUALLY_EXCLUSIVE: &str = "--config and --project are mutually exclusive";

impl Ctx {
    /// resolve, --config/--project bayraklarini bir baglama cevirir.
    ///
    /// `--project`, kayit defteri uzerinden <dir>/.wapps.yaml'a cozulmeye
    /// CALISILIR. Defterde yoksa bu bir HATA DEGILDIR: ad, project_override
    /// olarak tasinir.
    pub fn resolve(config: Option<&str>, project: Option<&str>) -> Result<Ctx, Error> {
        if let Some(c) = config {
            if project.is_some() {
                return Err(Error::new(Code::Internal, MUTUALLY_EXCLUSIVE));
            }
            let abs = abs_path(Path::new(c))
                .map_err(|e| Error::new(Code::Internal, format!("resolve --config path: {e}")))?;
            return Ok(Ctx {
                config_path: Some(abs),
                project_override: None,
            });
        }
        match project {
            None => Ok(Ctx {
                config_path: None,
                project_override: None,
            }),
            Some(name) => match projects::resolve(name) {
                Ok(dir) => Ok(Ctx {
                    config_path: Some(Path::new(&dir).join(WAPPS_YAML_PATH)),
                    project_override: None,
                }),
                // Defterde YOKSA ad'in kendisiyle devam edilir.
                Err(_) => Ok(Ctx {
                    config_path: None,
                    project_override: Some(name.to_string()),
                }),
            },
        }
    }

    /// path, yuklenecek `.wapps.yaml` yolunu doner: override varsa o, yoksa
    /// cwd-goreli varsayilan.
    pub fn path(&self) -> PathBuf {
        match &self.config_path {
            Some(p) => p.clone(),
            None => PathBuf::from(WAPPS_YAML_PATH),
        }
    }

    /// load_or_none, dosya YOKSA None doner; ayristirma hatalarini YUKSEK SESLE
    /// yayar. "Dosya yok" ile "dosya bozuk"u ayirmak, sessizce baska bir yola
    /// sapmakla operatore yazim hatasini gostermek arasindaki farktir.
    pub fn load_or_none(&self) -> Result<Option<WappsYaml>, Error> {
        let p = self.path();
        if !p.exists() {
            return Ok(None);
        }
        match wappsyaml::load(&p) {
            Ok(c) => Ok(Some(c)),
            Err(e) => Err(Error::new(Code::Internal, e)),
        }
    }

    /// store_project, YALNIZCA proje ADINA ihtiyac duyan verb'ler
    /// (list/get/rm/projects) icindir: gate'e gitmek icin yerel bir
    /// `.wapps.yaml`, dizin ya da depo GEREKMEZ.
    ///
    /// `--project` bir dizine cozulmediyse ADIN KENDISI yeterlidir; aksi halde
    /// normal yerel config yuklenir ve YOKLUGU bir hatadir.
    ///
    /// Bu, exec/apply'in kullandigi `require_store_config`ten ayri durmali:
    /// oradaki verb'ler `targets`/`sources` OKUYOR, yani yerel dosya SART.
    pub fn store_project(&self, verb: &str) -> Result<String, Error> {
        if let Some(p) = &self.project_override {
            return Ok(p.clone());
        }
        Ok(self.require_store_config(verb)?.project)
    }

    /// require_store_config, yerel `.wapps.yaml`i yukler ve VAR OLMASINI sart
    /// kosar. targets veya sources OKUYAN verb'ler (apply/sync/exec/env) bunu
    /// cagirir; yalnizca proje ADI yeten verb'ler (list/get/rm/projects)
    /// cagirmaz.
    ///
    /// `verb`, hatayi konumlandirmak icin ("apply: ...").
    pub fn require_store_config(&self, verb: &str) -> Result<WappsYaml, Error> {
        match self.load_or_none()? {
            Some(c) => Ok(c),
            None => Err(Error::new(Code::NotFound, format!("{verb}: no .wapps.yaml found"))
                .with_recovery(
                    "run this from a project directory, or pass --config <path>/.wapps.yaml (see 'wapps secrets init')",
                )),
        }
    }
}

fn abs_path(p: &Path) -> std::io::Result<PathBuf> {
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(p))
}

/// check_repo_binding, bir config icin depo→proje baglamasinin GUVENILEN
/// home-dir'de pinli oldugunu dogrular (SPEC §7.1 trust-repo).
///
/// `errw` insan yolundaki onay diyalogunun ve onay satirinin gittigi yerdir
/// (Go'da os.Stderr).
pub fn check_repo_binding<W: Write>(
    ctx: &Ctx,
    is_agent: bool,
    stdin_is_tty: bool,
    errw: &mut W,
    ask: &dyn Fn(&str, &str, &mut W) -> bool,
) -> Result<(), Error> {
    // Ciplak `--project <ad>` (defterde olmayan): ortada baglanacak bir depo
    // YOKTUR. Bir INSAN icin bu, hedefi komut satirinda acikca adlandirmaktir —
    // pinin korudugu confused-deputy durumu degil. Bir AJAN icin degildir: pin
    // tam olarak "A deposundaki ajan B projesini okumasin" icindir ve ajanin
    // `--project` yazabilmesi onu YETKILI YAPMAZ → fail-closed.
    if let Some(p) = &ctx.project_override {
        if is_agent {
            // Kurtarma satiri override ediliyor: ortada pinlenecek bir depo
            // YOK, o yuzden "trust-repo kosur" varsayilani burada anlamsiz.
            return Err(Error::new(
                Code::BindingUnpinned,
                format!(
                    "--project {} names a project with no local repo; an agent may not target a project this way",
                    crate::gojson::quote(p)
                ),
            )
            .with_recovery("a human must run this in a terminal, or work inside the project's repo"));
        }
        return Ok(());
    }

    // Config YOKSA (ya da okunamiyorsa) baglama kontrolu de YOK. Ayristirma
    // hatasi burada YUTULUYOR — Go da yutuyor — ve bir adim sonra
    // require_store_config'ten yuksek sesle geri geliyor.
    let Ok(Some(cfg)) = ctx.load_or_none() else {
        return Ok(());
    };

    // Service principal (CI): CF Access service-token CIFTI env'de doluysa
    // depo-pin kontrolu ATLANIR. Taze bir CI container'inda trust-repo (TTY)
    // imkansiz; bu muafiyet olmadan store tuketen HER adim BINDING_UNPINNED ile
    // olurdu. Cift'in YARISI set ise bypass YOK — fail-closed aynen surer.
    //
    // GUVENLIK KISITI: bu muafiyet per-repo confused-deputy hapsini kaldirir;
    // geriye yalnizca sunucu-tarafi per-key policy kalir. YALNIZCA service
    // token'lar PER-PROJECT scoped ise guvenlidir.
    if service_token_pair_set() {
        return Ok(());
    }

    let repo_id = repo_identity(&cfg);
    let fp = binding::fingerprint(&repo_id);

    let path = binding::default_path().map_err(|e| Error::new(Code::Internal, e))?;
    let mut store = binding::load(&path)
        .map_err(|e| Error::new(Code::Internal, format!("load repo pins: {e}")))?;

    match store.check(&fp, &cfg.project) {
        Ok(()) => return Ok(()),
        Err(binding::CheckError::Mismatch) => {
            // UYUSMAZLIK satir ici COZULMEZ. Config'in PINLI OLANDAN BASKA bir
            // projeyi talep etmesi, pinin var olma sebebinin ta kendisi. Yeni
            // bir baglama siradan ve zararsizdir; bir baglamayi DEGISTIRMEK
            // kasitli bir karar ister.
            return Err(Error::new(
                Code::BindingUnpinned,
                format!(
                    "repo is pinned to a different project than {}; re-pin required",
                    crate::gojson::quote(&cfg.project)
                ),
            )
            .with_recovery("if this is intended, run: wapps secrets trust-repo"));
        }
        Err(binding::CheckError::Unpinned) => {}
    }

    // Buradan sonrasi PINSIZ durum: baglama henuz hic kurulmamis.
    //
    // Ajan/CI → fail-closed. Pinin GERCEKTEN is gordugu yer burasi: uydurulmus
    // ya da ele gecmis bir `.wapps.yaml` kendi basina bir proje TALEP EDEMESIN.
    // Bir ajanin o dosyayi yazabiliyor olmasi, onu yetkili yapmaz.
    if is_agent || !stdin_is_tty {
        // Insan ama TTY yok (boru/script) → SORAMAYIZ, o yuzden sormus gibi de
        // yapmayiz.
        return Err(Error::new(
            Code::BindingUnpinned,
            format!(
                "repo→project binding for {} is not pinned",
                crate::gojson::quote(&cfg.project)
            ),
        ));
    }

    // Insan, terminalde: bu dizine gelip komutu yazmis olmasi NIYET BEYANIDIR.
    // Ayri bir komut ogretmek yerine BURADA soruyoruz — guvenlik ayni (onaylayan
    // yine bir insan), surtunme depo basina tek tus. Proje ADIYLA gosteriliyor:
    // korunan sey tam olarak bu, HANGI projenin talep edildigini gorebilmek.
    if !ask(&repo_id, &cfg.project, errw) {
        return Err(Error::new(
            Code::BindingUnpinned,
            format!(
                "not pinned; binding declined for {}",
                crate::gojson::quote(&cfg.project)
            ),
        ));
    }
    store.pin(
        &fp,
        binding::Pin {
            repo: repo_id,
            project: cfg.project.clone(),
            backend: cfg.backend.clone(),
        },
    );
    store
        .save(&path)
        .map_err(|e| Error::new(Code::Internal, format!("save repo pin: {e}")))?;
    let _ = writeln!(
        errw,
        "✓ bound this repo to project {} (change it later with: wapps secrets trust-repo)",
        crate::gojson::quote(&cfg.project)
    );
    Ok(())
}

/// bind_prompt, pinsiz bir baglamayi SATIR ICI onaylatir.
pub fn bind_prompt<W: Write>(repo_id: &str, project: &str, errw: &mut W) -> bool {
    let _ = write!(
        errw,
        "This repo is not bound to a project yet.\n  repo:    {repo_id}\n  project: {project}\nBind them? [y/N]: "
    );
    let _ = errw.flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    let a = line.trim().to_lowercase();
    a == "y" || a == "yes"
}

// service_token_pair_set, CF Access service-token ciftinin IKISININ de env'de
// dolu oldugunu soyler. Okuma, non-interactive auth yolundaki TrimSpace
// davranisiyla BIREBIR ayni ki "auth geciyor ama pin muafiyeti gecmiyor"
// ayrismasi olmasin.
fn service_token_pair_set() -> bool {
    let get = |k: &str| std::env::var(k).unwrap_or_default().trim().to_string();
    !get("CF_ACCESS_CLIENT_ID").is_empty() && !get("CF_ACCESS_CLIENT_SECRET").is_empty()
}

/// repo_identity, BAGLANAN birimin kararli kimligini doner.
///
/// Bu birim DEPO DEGIL, "su `.wapps.yaml`"dir: origin URL'i + config'in depo
/// kokune gore yolu.
///
/// NEDEN YOL DA DAHIL: eskiden kimlik yalnizca origin URL'iydi, yani bir
/// monorepo'daki BUTUN projeler tek parmak izine cakisiyordu. Biri pinlenince
/// digerleri "repo is pinned to a different project" ile ERISILEMEZ hale
/// geliyordu. Yolu eklemek iliskiyi cok-coka cevirir.
///
/// Config depo KOKUNDEYSE kimlik CIPLAK URL olarak kalir — boylece tek-projeli
/// depolarin MEVCUT pinleri gecerliligini korur.
pub fn repo_identity(cfg: &WappsYaml) -> String {
    let root = if cfg.config_root().is_empty() {
        "."
    } else {
        cfg.config_root()
    };
    let sub = git_repo_subpath(root);

    // origin varsa kimlik ona baglanir: ayni deponun her checkout'u pini
    // PAYLASIR.
    if let Some(url) = git_remote_url(root) {
        return match sub {
            Some(s) if !s.is_empty() => format!("{url}#{s}"),
            _ => url,
        };
    }
    // origin YOKSA (yerel depo) ANA depo koku kullanilir — worktree'nin kendi
    // koku DEGIL. Aksi halde her worktree ayri bir kimlik alirdi: 25 worktree,
    // 25 baglama sorusu ve ajan tarafinda 25 ayri BINDING_UNPINNED demek olurdu.
    if let Some(main) = git_main_repo_root(root) {
        return match sub {
            Some(s) if !s.is_empty() => format!("{main}#{s}"),
            _ => main,
        };
    }
    match abs_path(Path::new(root)) {
        Ok(a) => a.to_string_lossy().into_owned(),
        Err(_) => root.to_string(),
    }
}

fn git_out(dir: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// git_main_repo_root, ANA calisma agacinin kokunu doner (worktree'den cagrilsa
// bile). git --git-common-dir worktree'den de ana depodan da AYNI .git'i
// gosterir, o yuzden hepsi tek pinde bulusur.
fn git_main_repo_root(dir: &str) -> Option<String> {
    let git_dir = git_out(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if git_dir.is_empty() {
        return None;
    }
    Some(Path::new(&git_dir).parent()?.to_string_lossy().into_owned())
}

// git_repo_subpath, dir'in git kokune gore yolunu doner ("" = kokun kendisi).
fn git_repo_subpath(dir: &str) -> Option<String> {
    let p = git_out(dir, &["rev-parse", "--show-prefix"])?;
    Some(p.trim_end_matches('/').to_string())
}

// git_remote_url, `git -C <dir> remote get-url origin` doner; hata/bossa None.
fn git_remote_url(dir: &str) -> Option<String> {
    let u = git_out(dir, &["remote", "get-url", "origin"])?;
    if u.is_empty() {
        None
    } else {
        Some(u)
    }
}
