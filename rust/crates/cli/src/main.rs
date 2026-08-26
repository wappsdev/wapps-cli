// wapps ikilisinin giris noktasi. Adim 6 dilimi: `secrets get`.
use std::io::Write;
use std::process::ExitCode;
use wapps::agentmode;
use wapps::applyverb;
use wapps::binding;
use wapps::cli::{self, CmdError};
use wapps::clierr::{Code, Error};
use wapps::configctx::{self, Ctx};
use wapps::confirm;
use wapps::envverb;
use wapps::envwrite;
use wapps::epochpin;
use wapps::execverb;
use wapps::gojson::quote as go_quote;
use wapps::importenv;
use wapps::initverb;
use wapps::projectsverb;
use wapps::rmverb;
use wapps::session;
use wapps::setverb;
use wapps::statusverb;
use wapps::store;
use wapps::trustrepo;

fn main() -> ExitCode {
    let agent = agentmode::is_agent();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let mut err_out = std::io::stderr();
            cli::report_error(&mut err_out, &e, agent);
            // Sahadaki ikili her hatada 1 ile cikiyor (clap'in 2'si DEGIL).
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), CmdError> {
    let matches = match cli::build().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            // --help / --version clap'in "hata"si olarak gelir ama cikis 0'dir.
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = e.print();
                std::process::exit(0);
            }
            return Err(cli::clap_error_to_cmd_error(&e));
        }
    };

    let project = matches.get_one::<String>("project").cloned();
    let config = matches.get_one::<String>("config").cloned();

    match matches.subcommand() {
        Some(("secrets", sm)) => match sm.subcommand() {
            Some(("set", sm2)) => {
                let keys: Vec<String> =
                    sm2.get_many::<String>("key").map(|v| v.cloned().collect()).unwrap_or_default();
                // ARITE ONCE. Olculdu (differential
                // agent_set_binding_refused_missing_arg): cobra ValidateArgs'i
                // PersistentPreRunE'dan ONCE kosuyor, yani ajan modunda bile
                // eksik arguman BINDING_UNPINNED degil arite hatasi veriyor.
                if keys.len() != 1 {
                    return Err(CmdError::Plain(format!(
                        "accepts 1 arg(s), received {}",
                        keys.len()
                    )));
                }
                run_set(&keys[0], project, sm2.get_one::<String>("from-file").cloned())
            }
            Some(("exec", em)) => {
                let argv: Vec<String> =
                    em.get_many::<String>("argv").map(|v| v.cloned().collect()).unwrap_or_default();
                // ARITE ONCE (cobra MinimumNArgs(1) PersistentPreRunE'dan ONCE
                // kosuyor) — set'te olculen sirayla ayni.
                if argv.is_empty() {
                    return Err(CmdError::Plain(
                        "requires at least 1 arg(s), only received 0".to_string(),
                    ));
                }
                run_exec(
                    &argv,
                    config,
                    project,
                    em.get_one::<String>("prefix").cloned().unwrap_or_default(),
                    em.get_one::<String>("intent").cloned().unwrap_or_else(|| "dev".to_string()),
                    em.get_flag("break-glass"),
                )
            }
            Some(("apply", _)) => run_apply(config, project),
            Some(("list", _)) => run_list(config, project),
            Some(("status", stm)) => run_status(config, project, stm.get_flag("json")),
            Some(("rm", rm)) => {
                let keys: Vec<String> =
                    rm.get_many::<String>("key").map(|v| v.cloned().collect()).unwrap_or_default();
                // ARITE ONCE — ve bu sirayi OLCTUK: ajan modunda eksik
                // arguman AGENT_MODE_REFUSED DEGIL bir arite hatasi veriyor.
                // cobra ValidateArgs'i PersistentPreRunE'dan (ve dolayisiyla
                // ajan kapisindan) ONCE kosuyor.
                if keys.len() != 1 {
                    return Err(CmdError::Plain(format!(
                        "accepts 1 arg(s), received {}",
                        keys.len()
                    )));
                }
                run_rm(&keys[0], config, project, rm.get_flag("yes"))
            }
            Some(("import-env", im)) => {
                let files: Vec<String> =
                    im.get_many::<String>("file").map(|v| v.cloned().collect()).unwrap_or_default();
                // ARITE ONCE — cobra ValidateArgs PersistentPreRunE'dan once
                // kosuyor. Olculdu: ajan modunda eksik arguman bir arite
                // hatasi, bir baglama/ajan reddi DEGIL.
                if files.len() != 1 {
                    return Err(CmdError::Plain(format!(
                        "accepts 1 arg(s), received {}",
                        files.len()
                    )));
                }
                run_import_env(&files[0], config, project)
            }
            Some(("env", em)) => run_env(
                config,
                project,
                em.get_one::<String>("write").cloned().unwrap_or_default(),
                em.get_one::<String>("prefix").cloned().unwrap_or_default(),
            ),
            Some(("trust-repo", _)) => run_trust_repo(config, project),
            Some(("init", im)) => run_init(
                config,
                project,
                im.get_one::<String>("project-name").cloned().unwrap_or_default(),
                im.get_flag("force"),
            ),
            Some(("get", gm)) => {
                let keys: Vec<String> =
                    gm.get_many::<String>("key").map(|v| v.cloned().collect()).unwrap_or_default();
                // cobra ExactArgs(1) ile AYNI metin.
                if keys.len() != 1 {
                    return Err(CmdError::Plain(format!(
                        "accepts 1 arg(s), received {}",
                        keys.len()
                    )));
                }
                run_get(&keys[0], project)
            }
            _ => {
                let _ = cli::build().find_subcommand_mut("secrets").unwrap().print_help();
                std::process::exit(0);
            }
        },
        Some(("projects", pm)) => match pm.subcommand() {
            Some(("list", lm)) => {
                // cobra.NoArgs — ve reddin METNI cobra'nindir: fazladan
                // arguman "unknown command" olarak adlandiriliyor, bir arite
                // hatasi olarak DEGIL.
                if let Some(extra) = lm.get_many::<String>("extra").and_then(|mut v| v.next().cloned())
                {
                    return Err(CmdError::Plain(format!(
                        "unknown command {} for \"wapps projects list\"",
                        go_quote(&extra)
                    )));
                }
                run_projects_list(config, project)
            }
            Some(("rm", rm)) => {
                let names: Vec<String> = rm
                    .get_many::<String>("project")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
                if names.len() != 1 {
                    return Err(CmdError::Plain(format!(
                        "accepts 1 arg(s), received {}",
                        names.len()
                    )));
                }
                run_projects_rm(&names[0], rm.get_flag("yes"))
            }
            _ => {
                let _ = cli::build().find_subcommand_mut("projects").unwrap().print_help();
                std::process::exit(0);
            }
        },
        _ => {
            let _ = cli::build().print_help();
            std::process::exit(0);
        }
    }
}

// run_list, `wapps secrets list` — anahtar ADLARI, deger asla.
//
// KAPI SIRASI:
//   1. ajan politikasi (`allow` → gecer)
//   2. baglama kapisi  (list baglama-MUAF DEGIL)
//   3. proje cozumu    (store_project → NOT_FOUND)
//   4. GET /keys
//
// 2 ile 3'un sirasi GOZLEMLENEBILIR ve olculdu: `--project testproj` ile ajan
// modunda cagirmak "no .wapps.yaml found" DEGIL BINDING_UNPINNED vermeli
// (agent_list_project_flag). Insan yolunda ayni cagri GECER — ciplak
// `--project` bir insan icin acik hedef beyanidir.
//
// GET /keys epoch pin'ini ILERLETIR (Go: WorkerStore.Keys →
// checkAndAdvanceEpochPin). `rm`in aksine: silme sunulan bir epoch okumuyor.
fn run_list(config: Option<String>, project: Option<String>) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    let project = ctx.store_project("list").map_err(CmdError::Cli)?;
    let res = store::keys(&project).map_err(CmdError::Cli)?;
    let names: Vec<String> = res.keys.into_iter().map(|k| k.key_name).collect();

    let mut out = std::io::stdout();
    let _ = write!(out, "{}", wapps::listverb::render(&names));
    Ok(())
}

// run_status, `wapps secrets status` — HER modda ve her ag durumunda guvenli.
//
// TEK fiil ki HICBIR KOSULDA hard-fail ETMEZ: rapor her zaman basilir ve cikis
// 0'dir. Bu yuzden burada `?` YOK — her adim kendi fail-safe degerine duser.
//
// BAGLAMA KAPISI BURADA CAGRILMIYOR ve bu bir unutma degil: Go'da `status`
// bindingExempt kumesinde (trust-repo, policy, rotate-plan ile birlikte).
// Pinlenmemis bir depoda `status` YINE CALISIR — zaten "baska her sey hata
// verdiginde ilk kosulan komut" olmasinin sebebi bu.
//
// Proje adi YALNIZCA yerel config'ten okunuyor: ciplak `--project <ad>`
// (defterde olmayan) status icin bir proje ADLANDIRMAZ, cunku Go'da
// statusProject `loadOrNil(wappsConfigPath())` cagiriyor ve projectOverride'a
// HIC bakmiyor.
fn run_status(
    config: Option<String>,
    project: Option<String>,
    json: bool,
) -> Result<(), CmdError> {
    // --config ile --project birlikte verilirse bu hata YINE yuzeye cikar:
    // Go'da da kok PersistentPreRunE (resolveProjectFlag) status'tan ONCE
    // kosuyor ve orada duser.
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    // Ayristirma hatasi YUTULUYOR (Go: loadOrNil hatasinda "" doner) — bozuk
    // bir `.wapps.yaml` status'u dusurmez, yalnizca epoch_pin 0 kalir.
    let project_name = ctx
        .load_or_none()
        .ok()
        .flatten()
        .map(|c| c.project)
        .unwrap_or_default();

    let epoch_pin = match epochpin::default_path() {
        Ok(p) => statusverb::read_epoch_pin(&p, &project_name),
        Err(_) => 0,
    };
    let (session_valid, session_expires_in) = read_session_now();

    let rep = statusverb::StatusReport {
        online: probe_gate(),
        session_valid,
        session_expires_in,
        epoch_pin,
    };
    let mut out = std::io::stdout();
    let text = if json { statusverb::render_json(&rep) } else { statusverb::render_text(&rep) };
    let _ = write!(out, "{text}");
    Ok(())
}

// read_session_now, uretim oturum okumasidir (env → dosya).
fn read_session_now() -> (bool, i64) {
    let host = statusverb::host_of(&session::gate_url());
    let path = match epochpin::default_path() {
        // epochs.json ile AYNI dizin koku: <XDG>/wapps. Oturum dosyasi
        // session/<host>.json altinda.
        Ok(p) => p
            .parent()
            .map(|d| d.join("session").join(statusverb::host_file(&host)))
            .unwrap_or_default(),
        Err(_) => std::path::PathBuf::new(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    statusverb::read_session_from(&|k| std::env::var(k).ok(), &path, now)
}

// probe_gate, gate'e KISA bir prob atar.
//
// HERHANGI bir HTTP yaniti (401 dahil) → online. Yalnizca tasima
// hatasi/timeout offline demek: "gate ayakta mi" sorusunun cevabi
// "yetkim var mi"dan BAGIMSIZ.
//
// WAPPS_STATUS_NO_PROBE=1, CI'da dis cagriyi onlemek icin deterministik
// olarak offline dondurur.
fn probe_gate() -> bool {
    if std::env::var("WAPPS_STATUS_NO_PROBE").as_deref() == Ok("1") {
        return false;
    }
    let url = format!("{}/v1/whoami", session::gate_url());
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_millis(1500))
        .build();
    match agent.get(&url).call() {
        Ok(_) => true,
        // Status hatasi da bir YANITTIR → online.
        Err(ureq::Error::Status(_, _)) => true,
        Err(ureq::Error::Transport(_)) => false,
    }
}

// run_rm, `wapps secrets rm <KEY>` — bu dilimin SILEN fiili.
//
// KAPI SIRASI (arite zaten cagiran tarafta kontrol edildi):
//   1. arite            → cagiranda, ajan kapisindan ONCE (olculdu)
//   2. ajan politikasi  → `refuse_agent`: AGENT_MODE_REFUSED
//   3. baglama kapisi   → insan yolunda ates eder
//   4. proje cozumu     → NOT_FOUND
//   5. onay             → --yes ile atlanir; kabul edilen TEK cevap "yes"
//   6. DELETE
//
// 2'nin varligi 3'u AJAN yolunda erisilemez kiliyor — `get`teki ayni desen.
fn run_rm(
    key: &str,
    config: Option<String>,
    project: Option<String>,
    yes: bool,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_REFUSE_AGENT, agent)?;

    let project = ctx.store_project("rm").map_err(CmdError::Cli)?;

    // Onay istemi STDOUT'a (Go: cmd.OutOrStdout()) — stderr'e DEGIL.
    let mut out = std::io::stdout();
    if !yes {
        let mut stdin = std::io::stdin();
        if !confirm::ask(&mut stdin, &mut out, &rmverb::prompt(key, &project)) {
            return Err(CmdError::Cli(Error::new(
                Code::Internal,
                "secrets.rm: aborted (confirmation not given)",
            )));
        }
    }

    store::delete(&project, key).map_err(CmdError::Cli)?;
    let _ = write!(out, "{}", rmverb::success_line(key, &project));
    Ok(())
}

// run_projects_list, `wapps projects list`.
//
// BAGLAMA KAPISI YOK — kok mount'un dogrudan sonucu (bkz. projectsverb.rs).
// Ama config GEREKSINIMI VAR ve bu ilk bakista tuhaf gorunuyor: Go
// `storeProject("projects")` cagiriyor, donen proje adini GET /v1/projects'e
// HIC gecirmiyor, yine de config yoksa NOT_FOUND ile duser. Olculdu
// (projects_human_list → "projects: no .wapps.yaml found"), o yuzden AYNEN
// tasiniyor: "gereksiz gorunen" bir kapiyi duzeltmek sahadaki ikiliyle
// ayrisma demek.
fn run_projects_list(config: Option<String>, project: Option<String>) -> Result<(), CmdError> {
    agentmode::guard(agentmode::POLICY_ALLOW, agentmode::is_agent()).map_err(CmdError::Cli)?;
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    let _ = ctx.store_project("projects").map_err(CmdError::Cli)?;

    let res = store::projects().map_err(CmdError::Cli)?;
    let mut out = std::io::stdout();
    let _ = write!(out, "{}", projectsverb::render(&res.projects));
    Ok(())
}

// run_projects_rm, `wapps projects rm <PROJECT>` — KONTROL DUZLEMI op'u.
//
// Bir projeyi silmek, oradaki her anahtari silmenin TOPLAMIDIR; per-key
// `delete` grant'i buna yetmez, global `admin` verb'u + write-AUD ister. Ajan
// modunda CONTROL_PLANE_REQUIRED (rm'in AGENT_MODE_REFUSED'i DEGIL — iki
// farkli sinif, iki farkli kurtarma satiri).
//
// Config GEREKSINIMI YOK (projects list'in aksine): storeProject cagrilmiyor.
fn run_projects_rm(project: &str, yes: bool) -> Result<(), CmdError> {
    agentmode::guard(agentmode::POLICY_CONTROL, agentmode::is_agent()).map_err(CmdError::Cli)?;

    let mut out = std::io::stdout();
    if !yes {
        let mut stdin = std::io::stdin();
        if !confirm::ask(&mut stdin, &mut out, &projectsverb::rm_prompt(project)) {
            return Err(CmdError::Cli(Error::new(
                Code::Internal,
                "secrets.projects.rm: aborted (confirmation not given)",
            )));
        }
    }

    let res = store::project_delete(project).map_err(CmdError::Cli)?;
    let _ = write!(
        out,
        "{}",
        projectsverb::rm_success_line(&res.project, res.deleted_objects, res.pointer_events_kept)
    );
    Ok(())
}

// run_import_env, `wapps secrets import-env <dosya>` — bu dilimin SIR YAZAN
// fiili.
//
// KAPI SIRASI:
//   1. arite            → cagiranda, ajan kapisindan ONCE
//   2. ajan politikasi  → `allow` (set ile ayni sinif: deger BASMIYOR, ALIYOR)
//   3. baglama kapisi
//   4. config gereksinimi → require_store_config (`--project <ad>` ATLATMAZ)
//   5. dosyayi oku + ayristir
//   6. GET /keys  → yalnizca UZERINE YAZILACAK adlari onceden soylemek icin.
//      Hatasi YUTULUYOR (Go: `if kr, kerr := ...; kerr == nil`). Ad duzlemi,
//      yani audit'e value.read DUSMEZ. YAN ETKI: bu cagri EPOCH PIN'INI
//      ILERLETIR — import'un kendisi ilerletmez.
//   7. POST /import → TEK atomik epoch
//   8. bildirilen hedefleri yaz (apply_targets_after_write) — cikti STDERR'e
//   9. basari satiri → STDOUT
//
// 8'in STDERR'e gitmesi `apply`den AYRILDIGI yer (orada stdout). Differential
// ikisini ayri pty'lerde yakaladigi icin bu olculuyor.
fn run_import_env(
    env_file: &str,
    config: Option<String>,
    project: Option<String>,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    let cfg = ctx.require_store_config("import-env").map_err(CmdError::Cli)?;

    let data = std::fs::read(env_file).map_err(|e| {
        CmdError::Plain(format!(
            "secrets.import-env: read {env_file}: {}",
            wapps::goerr::open_error(env_file, &e)
        ))
    })?;
    let sets = importenv::parse_env_file(env_file, &data)
        .map_err(|e| CmdError::Plain(format!("secrets.import-env: {e}")))?;

    let mut errw = std::io::stderr();
    if sets.is_empty() {
        // HATA DEGIL: cikis 0. Bos bir dosya bir yazim TALEBI degildir.
        let _ = write!(errw, "{}", importenv::EMPTY_INPUT_WARNING);
        return Ok(());
    }

    // Hangi adlarin UZERINE yazilacagini onceden soyleyebilmek icin AD DUZLEMI
    // ile kesisim. Hata YUTULUYOR — bu bilgi bir kolayliktir, bir kapi degil.
    let existing: std::collections::BTreeSet<String> = match store::keys(&cfg.project) {
        Ok(kr) => kr.keys.into_iter().map(|k| k.key_name).collect(),
        Err(_) => Default::default(),
    };
    let overridden: Vec<String> =
        sets.keys().filter(|k| existing.contains(*k)).cloned().collect();

    store::import_values(&cfg.project, &sets).map_err(CmdError::Cli)?;

    // Auto-apply: bildirilen hedefler HEMEN yazilir ki tuketim tarafi
    // (.env.local vb.) ikinci bir komut beklemeden import'u yansitsin.
    let archive = values_to_archive_json(&sets)
        .map_err(|e| CmdError::Plain(format!("secrets.import-env: {e}")))?;
    applyverb::apply_targets_after_write(&cfg, archive.as_bytes(), cfg.config_root(), &mut errw)
        .map_err(CmdError::Plain)?;

    let mut out = std::io::stdout();
    let _ = write!(out, "{}", importenv::success_line(sets.len(), env_file, &cfg.project));
    if !overridden.is_empty() {
        let _ = write!(errw, "{}", importenv::override_line(&overridden));
    }
    Ok(())
}

// run_env, `wapps secrets env` — export satirlari.
//
// KAPI SIRASI, ve ucuncu adim bu fiile OZEL:
//   1. ajan politikasi (`allow`) — PersistentPreRunE
//   2. baglama kapisi  — env baglama-MUAF DEGIL
//   3. PRINT-FORM REDDI: `--write` YOKSA ajan modunda REFUSE_AGENT. Ancak
//      `--write FILE` serbest (§7.4.2): degerler stdout'a/transcript'e DEGIL
//      0600 bir dosyaya iniyor.
//   4. config gereksinimi (require_store_config → NOT_FOUND). `--project <ad>`
//      BUNU ATLATMAZ: env `store_project` DEGIL `require_store_config`
//      kullaniyor, cunku... aslinda `targets`/`sources` okumuyor. Yine de
//      Go boyle ve OLCULDU (human_env_project_flag_still_needs_a_config).
//   5. store okumasi
//
// 2 ile 3'un sirasi GOZLEMLENEBILIR ve olculdu: pinsiz bir config'in yaninda
// ajan modunda `env --write out.env` cagirmak AGENT_MODE_REFUSED DEGIL
// BINDING_UNPINNED verir — yani AI-safe yol bile baglama kapisinin ARKASINDA.
fn run_env(
    config: Option<String>,
    project: Option<String>,
    write_path: String,
    prefix: String,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    // env'in print-form'u gizli DUZ METIN basar → ajan modunda YAPISAL red.
    // `--write FILE` bu kapinin DISINDA.
    if write_path.is_empty() {
        agentmode::guard(agentmode::POLICY_REFUSE_AGENT, agent).map_err(CmdError::Cli)?;
    }

    let cfg = ctx.require_store_config("env").map_err(CmdError::Cli)?;
    let values = store::read_all(&cfg.project).map_err(CmdError::Cli)?;
    let archive = values_to_archive_json(&values).map_err(|e| CmdError::Plain(format!("env: {e}")))?;

    if write_path.is_empty() {
        let mut out = std::io::stdout();
        return envwrite::write_tofu_outputs_as_env(archive.as_bytes(), &prefix, &mut out)
            .map_err(CmdError::Plain);
    }
    // Hedef yolu CWD-GORELI birakiliyor (Go: os.OpenFile(writePath...)),
    // `apply`in config_root'a cozdugu hedeflerin AKSINE. Bu fark bilincli
    // tasindi: `env --write` bir kerelik, operatorun bulundugu dizine yazan
    // bir kacis kapisi.
    envverb::write_env_file_atomic(std::path::Path::new(&write_path), archive.as_bytes(), &prefix)
        .map_err(CmdError::Plain)
}

// run_trust_repo, `wapps secrets trust-repo` — baglamayi KURAN fiil.
//
// KAPI SIRASI:
//   1. ajan politikasi → `tty`: AGENT_MODE_REFUSED ("this command requires a
//      human terminal"). `get`/`rm`in POLICY_REFUSE_AGENT metninden FARKLI.
//   2. baglama kapisi  → YOK. trust-repo baglama-MUAF (Go: bindingExempt), ve
//      bu zorunlu: pini KURAN fiil, pinin varligini sart kosamaz.
//   3. config gereksinimi → yoksa INTERNAL (NOT_FOUND DEGIL — Go'nun metni
//      "applies only to a backend: store .wapps.yaml").
//   4. onay → YALNIZCA "y" (bkz. trustrepo::confirm_y)
//   5. pin yazimi
//
// ISTEM STDOUT'A gidiyor. Satir ici baglama istemi (configctx::bind_prompt)
// stderr'e gidiyor; differential ikisini AYRI pty'lerde yakaladigi icin bu
// fark olculuyor.
fn run_trust_repo(config: Option<String>, project: Option<String>) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    agentmode::guard(agentmode::POLICY_TTY, agent).map_err(CmdError::Cli)?;

    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    // ERISILEMEZ DAL — ve bilerek burada: Go'da da runTrustRepo kendi isAgent
    // kontrolunu yapiyor ama PersistentPreRunE (yukaridaki guard) ONCE ates
    // ettigi icin bu satira ajan modunda HIC gelinmiyor. Iki ikilide de
    // olculemez; savunma katmani olarak duruyor.
    if agent {
        return Err(CmdError::Cli(Error::new(
            Code::BindingUnpinned,
            "trust-repo must run in a human terminal",
        )));
    }

    let cfg = match ctx.load_or_none().map_err(CmdError::Cli)? {
        Some(c) => c,
        None => {
            return Err(CmdError::Cli(Error::new(
                Code::Internal,
                "trust-repo applies only to a backend: store .wapps.yaml",
            )))
        }
    };

    let repo_id = configctx::repo_identity(&cfg);
    let path = binding::default_path()
        .map_err(|e| CmdError::Cli(Error::new(Code::Internal, format!("resolve repo-pins path: {e}"))))?;

    let mut out = std::io::stdout();
    let mut stdin = std::io::stdin();
    if !trustrepo::confirm_y(&mut stdin, &mut out, &trustrepo::prompt_block(&repo_id, &cfg)) {
        return Err(CmdError::Cli(Error::new(
            Code::BindingUnpinned,
            "trust-repo aborted; binding not pinned",
        )));
    }

    let mut store = binding::load(&path)
        .map_err(|e| CmdError::Cli(Error::new(Code::Internal, format!("load repo pins: {e}"))))?;
    store.pin(
        &binding::fingerprint(&repo_id),
        binding::Pin {
            repo: repo_id.clone(),
            project: cfg.project.clone(),
            backend: cfg.backend.clone(),
        },
    );
    store
        .save(&path)
        .map_err(|e| CmdError::Cli(Error::new(Code::Internal, format!("save repo pins: {e}"))))?;
    let _ = write!(out, "{}", trustrepo::success_line(&repo_id, &cfg.project));
    Ok(())
}

// run_init, `wapps secrets init` — `.wapps.yaml` YAZAR.
//
// BAGLAMA KAPISI YAZIMDAN ONCE ve bu SIRA olculdu: `init` baglama-muaf DEGIL,
// yani mevcut ama PINLENMEMIS bir config'in yaninda ajan modunda `init`
// cagirmak BINDING_UNPINNED verir ve dosyaya DOKUNULMAZ — `--force` ile bile.
// Ilk bakista ters gorunuyor ("init neden var olan bir baglamayi sorsun?") ama
// korudugu sey gercek: uydurulmus bir `.wapps.yaml` bulunan bir depoda, bir
// ajan onu `--force` ile YENIDEN yazip baska bir projeyi hedefleyemesin.
fn run_init(
    config: Option<String>,
    project: Option<String>,
    project_name: String,
    force: bool,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    // Depo koku DAIMA "." — Go'da da runInitStore(".", ...). `--config` bir
    // konum SECMEZ, yalnizca baglama kapisinin baktigi dosyayi degistirir.
    let text = initverb::run(".", &project_name, force).map_err(CmdError::Plain)?;
    let mut out = std::io::stdout();
    let _ = write!(out, "{text}");
    Ok(())
}

// run_set, `wapps secrets set <KEY>`.
//
// KAPI SIRASI Go'dan OLCULDU ve burasi portun kolayca yanlis yapacagi yer:
//
//   1. arite            (cobra ValidateArgs — PersistentPreRunE'dan ONCE)
//   2. baglama kapisi   (secretsPreRunE; `--project` + ajan → BINDING_UNPINNED)
//   3. proje cozumu     (RunE → storeProject; config yoksa NOT_FOUND)
//   4. deger yakalama   (--from-file | yankisiz prompt)
//   5. store yazimi     (PUT)
//
// 2 ile 4'un sirasi gozlemlenebilir: var olmayan bir dosyayla ajan modunda
// cagirmak "read --from-file" DEGIL BINDING_UNPINNED vermeli
// (agent_set_binding_refused_before_file).
//
// set'in ajan-modu politikasi `allow` (get'inki `refuse_agent`), yani
// agentmode::guard BURADA CAGRILMAZ — set gizli bir deger BASMIYOR, aliyor.
fn run_set(
    key: &str,
    project: Option<String>,
    from_file: Option<String>,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    setverb::binding_gate(project.as_deref(), agent).map_err(CmdError::Cli)?;

    let project = match project {
        Some(p) => p,
        None => {
            return Err(CmdError::Cli(
                Error::new(Code::NotFound, "set: no .wapps.yaml found").with_recovery(
                    "run this from a project directory, or pass --config <path>/.wapps.yaml (see 'wapps secrets init')",
                ),
            ))
        }
    };

    let mut err_out = std::io::stderr();
    let value = setverb::capture_value(&mut err_out, key, from_file.as_deref())
        .map_err(CmdError::Plain)?;

    store::set(&project, key, &value).map_err(CmdError::Cli)?;

    // Basari satiri stdout'a; yalnizca ANAHTAR ADI ve PROJE — deger DEGIL.
    let mut out = std::io::stdout();
    let _ = writeln!(out, "✓ Set {key} (store: {project})");
    Ok(())
}

fn run_get(key: &str, project: Option<String>) -> Result<(), CmdError> {
    // get, gizli bir DUZ METIN degeri basar → ajan modunda YAPISAL red.
    agentmode::guard(agentmode::POLICY_REFUSE_AGENT, agentmode::is_agent())
        .map_err(CmdError::Cli)?;

    let project = match project {
        Some(p) => p,
        None => {
            return Err(CmdError::Cli(
                Error::new(Code::NotFound, "get: no .wapps.yaml found").with_recovery(
                    "run this from a project directory, or pass --config <path>/.wapps.yaml (see 'wapps secrets init')",
                ),
            ))
        }
    };

    let res = store::read(&project, std::slice::from_ref(&key.to_string()))
        .map_err(CmdError::Cli)?;
    match res.values.get(key) {
        Some(v) => {
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{v}");
            Ok(())
        }
        None => Err(CmdError::Cli(Error::new(
            Code::NotFound,
            format!("key {} not returned by the store", go_quote(key)),
        ))),
    }
}

// gate, HER secrets verb'unun onunde duran ORTAK kapidir (Go'da
// secretsPreRunE): once ajan-modu politikasi, sonra depo→proje baglamasi.
//
// SecretsCmd'de oldugu icin Go'da hicbir verb bunu unutamaz; burada da tek
// fonksiyon olmasinin sebebi ayni — bir verb'un kapiyi atlamasi bir SATIRIN
// unutulmasiyla mumkun olmasin.
fn gate(ctx: &Ctx, policy: &str, agent: bool) -> Result<(), CmdError> {
    agentmode::guard(policy, agent).map_err(CmdError::Cli)?;
    let mut errw = std::io::stderr();
    configctx::check_repo_binding(
        ctx,
        agent,
        agentmode::stdin_is_tty(),
        &mut errw,
        &|repo, project, w| configctx::bind_prompt(repo, project, w),
    )
    .map_err(CmdError::Cli)
}

// run_exec, `wapps secrets exec -- <komut> [arg...]`.
//
// KAPI SIRASI Go'dan OLCULDU ve portun kolayca yanlis yapacagi yer burasi:
//
//   1. arite               (cobra MinimumNArgs — PersistentPreRunE'dan ONCE)
//   2. ajan politikasi     (exec `allow`, yani gecer)
//   3. baglama kapisi      (secretsPreRunE)
//   4. --break-glass reddi (RunE'nin ILK satiri)
//   5. --intent deploy reddi
//   6. config gereksinimi  (requireStoreConfig → NOT_FOUND)
//   7. store okumasi, sonra inject→scrub→run
//
// 3 ile 6'nin sirasi GOZLEMLENEBILIR: config'i olan pinlenmemis bir depoda
// ajan modunda cagirmak "no .wapps.yaml found" DEGIL BINDING_UNPINNED vermeli.
fn run_exec(
    argv: &[String],
    config: Option<String>,
    project: Option<String>,
    prefix: String,
    intent: String,
    break_glass: bool,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    if break_glass && agent {
        return Err(CmdError::Cli(Error::new(
            Code::BreakGlassRefused,
            "--break-glass refused in agent mode",
        )));
    }
    // --intent deploy, §7.3.4 fresh-or-fail (receipt/witness/epoch) guvenlik
    // yuzeyini VAAT EDER ama o yol hala baglanmadi. Sessiz no-op yerine FAIL
    // LOUD — deploy guvenlik yuzeyi islevsel sanilmasin.
    if intent == "deploy" || break_glass {
        return Err(CmdError::Cli(Error::new(
            Code::ActionUnavailable,
            "deploy intent not yet wired to the store; --intent deploy is unavailable in this build (use --intent dev)",
        )));
    }
    let cfg = ctx.require_store_config("exec").map_err(CmdError::Cli)?;
    // intent.Parse Go'da runExecStore'un ICINDE, yani config kapisindan SONRA
    // kosuyor. Olculdu (human_exec_unknown_intent): config'i olmayan bir
    // dizinde `--intent wat`, "unknown intent" DEGIL "no .wapps.yaml found"
    // vermeli. Sira gozlemlenebilir.
    if intent != "dev" && !intent.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            format!("unknown intent {} (allowed: dev, deploy)", go_quote(&intent)),
        )));
    }
    let values = store::read_all(&cfg.project).map_err(CmdError::Cli)?;
    let archive = values_to_archive_json(&values).map_err(CmdError::Plain)?;
    let (injected, scrub) = execverb::exec_env_and_values(archive.as_bytes(), &prefix)
        .map_err(|e| CmdError::Plain(format!("exec: {e}")))?;

    let mut out = std::io::stdout();
    let mut errw = std::io::stderr();
    let action = execverb::run_with_injected_env(
        argv,
        &injected,
        &scrub,
        &mut out,
        &mut errw,
        &|name, args, env, so, se| execverb::default_exec_runner(name, args, env, so, se),
    )
    .map_err(CmdError::Plain)?;
    match action {
        // Alt-surecin cikis kodu AYNEN yansitiliyor.
        execverb::ExitAction::Exit(code) => std::process::exit(code),
        execverb::ExitAction::Ok => Ok(()),
    }
}

// run_apply, `wapps secrets apply`: store'dan bir kez ceker ve `.wapps.yaml`in
// `targets:` blogundaki HER hedefi yazar.
fn run_apply(config: Option<String>, project: Option<String>) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    let cfg = ctx.require_store_config("apply").map_err(CmdError::Cli)?;
    if cfg.targets.is_empty() {
        return Err(CmdError::Plain(format!(
            "apply: no targets declared in {} — add a 'targets:' block or use 'wapps secrets env --write <file>' for one-off writes",
            wapps::configctx::WAPPS_YAML_PATH
        )));
    }
    let values = store::read_all(&cfg.project).map_err(CmdError::Cli)?;
    let archive = values_to_archive_json(&values).map_err(CmdError::Plain)?;

    let mut out = std::io::stdout();
    applyverb::apply_targets(&cfg, archive.as_bytes(), cfg.config_root(), &mut out)
        .map_err(CmdError::Plain)
}

// values_to_archive_json, duz metin deger haritasini tofu-output-sekilli zarf
// haritasina ({"KEY":{"value":"..."}}) cevirir — env yazicilari ve hedef
// yazicisi bu bicimi bekler.
fn values_to_archive_json(
    values: &std::collections::BTreeMap<String, String>,
) -> Result<String, String> {
    let envelopes: std::collections::BTreeMap<&String, serde_json::Value> = values
        .iter()
        .map(|(k, v)| (k, serde_json::json!({ "value": v })))
        .collect();
    serde_json::to_string(&envelopes).map_err(|e| format!("store: envelope: {e}"))
}
