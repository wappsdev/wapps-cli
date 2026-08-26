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
use wapps::doctorverb;
use wapps::envverb;
use wapps::envwrite;
use wapps::epochpin;
use wapps::execverb;
use wapps::gojson::quote as go_quote;
use wapps::importenv;
use wapps::policy;
use wapps::policyverb;
use wapps::initverb;
use wapps::projectsverb;
use wapps::rmverb;
use wapps::rotateplan;
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
            Some(("policy", pm)) => match pm.subcommand() {
                Some(("show", shm)) => run_policy_show(shm.get_flag("json")),
                Some(("set", psm)) => {
                    let files: Vec<String> = psm
                        .get_many::<String>("file")
                        .map(|v| v.cloned().collect())
                        .unwrap_or_default();
                    // ARITE ONCE — ve bu SIRA olculdu: ajan modunda eksik
                    // arguman CONTROL_PLANE_REQUIRED DEGIL bir arite hatasi
                    // veriyor (cobra ValidateArgs, PersistentPreRunE'dan once).
                    if files.len() != 1 {
                        return Err(CmdError::Plain(format!(
                            "accepts 1 arg(s), received {}",
                            files.len()
                        )));
                    }
                    run_policy_set(&files[0], psm.get_flag("yes"))
                }
                Some(("lint", plm)) => {
                    let files: Vec<String> = plm
                        .get_many::<String>("file")
                        .map(|v| v.cloned().collect())
                        .unwrap_or_default();
                    if files.len() != 1 {
                        return Err(CmdError::Plain(format!(
                            "accepts 1 arg(s), received {}",
                            files.len()
                        )));
                    }
                    run_policy_lint(&files[0])
                }
                _ => {
                    let _ = cli::build()
                        .find_subcommand_mut("secrets")
                        .unwrap()
                        .find_subcommand_mut("policy")
                        .unwrap()
                        .print_help();
                    std::process::exit(0);
                }
            },
            Some(("rotate-plan", rpm)) => run_rotate_plan(
                rpm.get_one::<String>("identity").cloned().unwrap_or_default(),
                rpm.get_one::<String>("since").cloned().unwrap_or_default(),
                rpm.get_flag("assume-policy"),
                rpm.get_flag("json"),
            ),
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
        Some(("doctor", dm)) => {
            run_doctor(dm.get_one::<String>("for").map(String::as_str).unwrap_or_default())
        }
        Some(("rotate", rm)) => match rm.subcommand() {
            Some(("skip", sm)) => {
                let args: Vec<String> =
                    sm.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default();
                // ARITE ONCE (cobra ExactArgs(2), ValidateArgs RunE'den once).
                if args.len() != 2 {
                    return Err(CmdError::Plain(format!(
                        "accepts 2 arg(s), received {}",
                        args.len()
                    )));
                }
                run_rotate_skip(
                    &args[0],
                    &args[1],
                    sm.get_one::<String>("reason").map(String::as_str).unwrap_or_default(),
                )
            }
            _ => {
                let _ = cli::build().find_subcommand_mut("rotate").unwrap().print_help();
                std::process::exit(0);
            }
        },
        Some(("tofu", tm)) => {
            let args: Vec<String> =
                tm.get_many::<String>("argv").map(|v| v.cloned().collect()).unwrap_or_default();
            // `project` ve `config` BILEREK gecirilmiyor: cobra'da
            // DisableFlagParsing onlari hic ayristirmiyor (bkz. run_tofu).
            run_tofu(&args)
        }
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

// --- `secrets policy` ailesi: KONTROL DUZLEMI --------------------------------
//
// UC SEY BU AILEYI BUTUN DIGER FIILLERDEN AYIRIYOR:
//
//  1. AJAN POLITIKASI `control`, `refuse_agent` DEGIL. Ret kodu
//     CONTROL_PLANE_REQUIRED ve kurtarma satiri bir ADMIN SEREMONISINI
//     adlandiriyor ("write-AUD session"). `rm`in AGENT_MODE_REFUSED'i ile
//     ayni sey DEGIL — iki ayri sinif, iki ayri cikis yolu.
//  2. AILE ADIYLA KAPILANIYOR. Go'da gateKey, SecretsCmd'nin ALTINDAKI ilk
//     seviye adi ("policy") aliyor, yaprak adini ("set") DEGIL. Aksi halde
//     `policy set`, data-plane `set`in `allow` iznini MIRAS ALIRDI ve bir
//     ajan yetki kurallarini yazabilirdi. Burada her yaprak acikca
//     POLICY_CONTROL ile kapiliyor.
//  3. BAGLAMA KAPISI YOK ve config GEREKMIYOR. policy GLOBAL bir dokuman; bir
//     depo→proje baglamasina bagli DEGIL (Go: bindingExempt). Olculdu:
//     pinlenmemis bir config'in yaninda `policy show` baglama sorusunu HIC
//     sormadan gate'e gidiyor.
//
// Oturum yoklugunda kurtarma satiri "wapps login" DEGIL "wapps login --write":
// /v1/admin kenarda AYRI bir CF Access uygulamasi (auth_headers_admin).

fn policy_gate() -> Result<(), CmdError> {
    agentmode::guard(agentmode::POLICY_CONTROL, agentmode::is_agent()).map_err(CmdError::Cli)
}

// run_policy_show, GET /v1/admin/policy.
fn run_policy_show(json: bool) -> Result<(), CmdError> {
    policy_gate()?;
    let res = store::policy_get().map_err(CmdError::Cli)?;
    let mut out = std::io::stdout();
    if json {
        // Go: json.Encoder + SetIndent("","  ") + SetEscapeHTML(false), ve
        // Encode SONA newline ekler. serde_json HTML kacisi YAPMIYOR, yani
        // `<`/`>`/`&` iki tarafta da ciplak cikiyor.
        let text = serde_json::to_string_pretty(&res)
            .map_err(|e| CmdError::Plain(format!("policy show: {e}")))?;
        let _ = writeln!(out, "{text}");
        return Ok(());
    }
    let _ = write!(out, "{}", policyverb::render_show(res.version, &res.sha256, &res.policy));
    Ok(())
}

// run_policy_lint, bir policy dosyasini CEVRIMDISI dogrular. Gate'e HIC
// gidilmez — uyarilar BLOKLAMAZ, sema hatasi BLOKLAR.
fn run_policy_lint(path: &str) -> Result<(), CmdError> {
    policy_gate()?;
    let doc = policyverb::read_policy_file(std::path::Path::new(path)).map_err(CmdError::Cli)?;
    let warns = policy::lint(&doc);
    let mut out = std::io::stdout();
    for w in &warns {
        let _ = writeln!(out, "⚠ {w}");
    }
    let _ = writeln!(
        out,
        "✓ {path}: schema valid ({} rules, {} warnings)",
        doc.rules.len(),
        warns.len()
    );
    Ok(())
}

// run_policy_set, lint + diff + CAS'li PUT.
//
// SIRA OLCULDU ve gozlemlenebilir: lint uyarilari gate'e GITMEDEN ONCE
// basiliyor. Yani gate erisilemezken bile operator dosyasinin uyarilarini
// gorur — `set_good_no_gate` vakasi tam olarak bunu pinliyor.
//
// CAS: version = current+1. Es zamanli bir admin duzenlemesi CAS'i kaybettirir
// (412 POLICY_CONFLICT) → `policy show` ile yeniden cek, rebase et, tekrarla.
fn run_policy_set(path: &str, yes: bool) -> Result<(), CmdError> {
    policy_gate()?;
    let mut doc = policyverb::read_policy_file(std::path::Path::new(path)).map_err(CmdError::Cli)?;

    let mut out = std::io::stdout();
    // Cevrimdisi lint: UYARILAR BLOKLAMAZ (sema hatasi zaten yukarida bloklardi).
    for w in policy::lint(&doc) {
        let _ = writeln!(out, "⚠ {w}");
    }

    let cur = store::policy_get().map_err(CmdError::Cli)?;
    doc.version = cur.version + 1;
    // YENIDEN dogrulama: surum degistigi icin. Buradaki ret POLICY_INVALID
    // ama mesaj FARKLI ("policy file rejected offline") — dosya okumadaki
    // "policy file <yol> invalid" ile karistirilmamali.
    policy::validate(&doc, policyverb::POLICY_TOPOLOGY).map_err(|e| {
        CmdError::Cli(
            Error::new(Code::PolicyInvalid, format!("policy file rejected offline: {e}")),
        )
    })?;

    let _ = write!(out, "{}", policyverb::rule_diff(&cur.policy.rules, &doc.rules));
    let _ = write!(
        out,
        "\nPUT policy v{} → v{} ({} rules). ",
        cur.version,
        doc.version,
        doc.rules.len()
    );
    if !yes {
        // Onay istemi STDOUT'a (Go: cmd.OutOrStdout()), ve kabul edilen TEK
        // cevap "yes" — `rm`/`projects rm` ile ayni katilik, `trust-repo`nun
        // "y"siyle DEGIL.
        let mut stdin = std::io::stdin();
        if !confirm::ask(&mut stdin, &mut out, "Type 'yes' to apply: ") {
            return Err(CmdError::Cli(Error::new(
                Code::ActionUnavailable,
                "policy set aborted (not confirmed)",
            )));
        }
    } else {
        let _ = writeln!(out, "(--yes)");
    }

    let res = store::policy_put(&doc).map_err(CmdError::Cli)?;
    let _ = writeln!(
        out,
        "✓ policy v{} active (sha256 {})",
        res.version,
        policyverb::short12(&res.sha256)
    );
    Ok(())
}

// run_doctor, `wapps doctor` — onboarding preflight.
//
// KAPI: YOK. Ne ajan politikasi, ne baglama, ne config. Kokte mount'lu ve
// RunE'de de bir kontrol yok, yani ajan modunda AYNEN kosar. Bu bir unutma
// degil bir karar (`secrets status` ile ayni gerekce): teshis, baska her sey
// hata verdiginde ilk kosulan komut, ve DEGER BASMIYOR.
//
// NE YAZMADIGI DA SOZLESME: fiil bir CF Access oturumunu ve bir CI
// service-token ciftini OKUYOR; ikisi de kimlik bilgisi. Disari cikan tek sey
// VARLIK ve SURE. Olcusu tests/doctorleak.rs — ve o test differential'da DEGIL,
// cunku differential iki ikiliyi karsilastiriyor ve IKISI de sizdirsa vaka
// "esit" gorunurdu.
fn run_doctor(mode: &str) -> Result<(), CmdError> {
    let mut out = std::io::stdout();
    match mode {
        "tofu" => {
            let (text, ok) = doctorverb::tofu_env_report(tool_on_path("tofu"), &|k| {
                std::env::var(k).unwrap_or_default()
            });
            let _ = write!(out, "{text}");
            if ok {
                return Ok(());
            }
            // DUZ hata (clierr DEGIL): Go `fmt.Errorf` kullaniyor, yani insan
            // yolunda KURTARMA SATIRI BASILMAZ. Ayrimi CmdError::Plain tasiyor.
            Err(CmdError::Plain("doctor --for tofu: env not ready".to_string()))
        }
        "" | "all" => {
            let (text, ok) = doctor_full_report();
            let _ = write!(out, "{text}");
            if ok {
                return Ok(());
            }
            Err(CmdError::Plain("doctor reported failures".to_string()))
        }
        other => Err(CmdError::Plain(format!(
            "doctor: unknown --for mode {} (allowed: tofu, all)",
            go_quote(other)
        ))),
    }
}

// tool_on_path, uretim PATH aramasidir (Go: exec.LookPath).
fn tool_on_path(name: &str) -> bool {
    let path = std::env::var("PATH").unwrap_or_default();
    doctorverb::look_path(name, &path, &doctorverb::is_executable_file)
}

// doctor_full_report, tam bataryayi kosar.
//
// SIRA SOZLESME: araclar → tofu state backend creds → Coolify → oturumlar.
// Her adim kendi ✓/✗ satirini basar ve `all_ok`u AND'ler; hicbir adim digerini
// KISA DEVRE ETTIRMEZ, cunku bir operator TUM eksikleri tek kosumda gormeli.
fn doctor_full_report() -> (String, bool) {
    let mut out = String::new();
    let mut all_ok = true;

    for (display, lookup) in doctorverb::FULL_TOOLS {
        if tool_on_path(lookup) {
            out.push_str(&format!("✓ {display} present\n"));
        } else {
            out.push_str(&format!("✗ {display} not found in PATH\n"));
            all_ok = false;
        }
    }

    // ETIKET BILEREK "tofu state backend", "R2 access" DEGIL: bir sirri okumak
    // istemcide R2 kimlik bilgisi ISTEMIYOR (gate onlari tutuyor). Yalnizca
    // state'i R2'de duran `tofu` bunlari istiyor, yani burada bos bir deger
    // sirlarin calisip calismadigi hakkinda HICBIR SEY soylemiyor.
    if std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default().is_empty() {
        out.push_str("✗ tofu state backend: AWS_ACCESS_KEY_ID not set (only needed for tofu, not for secrets)\n");
        all_ok = false;
    } else {
        out.push_str("✓ tofu state backend creds set\n");
    }

    let (line, ok) = probe_coolify();
    out.push_str(&line);
    all_ok = all_ok && ok;

    // Oturumlar. Gate host'u BURADA ciktiya girebiliyor (yalnizca yok/dolmus
    // dallarinda), o yuzden differential o iki vakada gate URL'ini sabitliyor.
    let host = statusverb::host_of(&session::gate_url());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dir = epochpin::default_path()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("session")))
        .unwrap_or_default();
    let env = |k: &str| std::env::var(k).ok();
    let read = doctorverb::session_state(&env, &dir.join(statusverb::host_file(&host)), now);
    // ADMIN oturumunun saklama anahtari `<host>-admin`: read oturumundan AYRI
    // tutuluyor cunku iki AYRI CF Access uygulamasinin iki ayri jetonu ve
    // suresi var (read saatler, write 15 dk).
    let admin_key = format!("{host}-admin");
    let admin = doctorverb::session_state(&env, &dir.join(statusverb::host_file(&admin_key)), now);
    let (lines, ok) = doctorverb::render_session_lines(&host, &read, &admin);
    out.push_str(&lines);
    all_ok = all_ok && ok;

    if !all_ok {
        return (out, false);
    }
    out.push_str("\nAll checks passed.\n");
    (out, true)
}

// probe_coolify, Coolify API'sine KISA bir /health probu atar.
//
// 5xx BIR HATA, altindaki her sey (404 dahil) "canli": soru "API ayakta mi",
// "bu rota var mi" DEGIL. User-Agent "curl/8" Go tarafiyla ayni — bazi
// kenarlar bilinmeyen ajanlari farkli karsiliyor.
fn probe_coolify() -> (String, bool) {
    let url = doctorverb::coolify_health_endpoint(
        &std::env::var("COOLIFY_URL").unwrap_or_default(),
    );
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    match agent.get(&url).set("User-Agent", "curl/8").call() {
        Ok(_) => ("✓ Coolify API reachable\n".to_string(), true),
        Err(ureq::Error::Status(code, _)) if code >= 500 => {
            (format!("✗ Coolify API server error (HTTP {code})\n"), false)
        }
        Err(ureq::Error::Status(_, _)) => ("✓ Coolify API reachable\n".to_string(), true),
        // TASIMA HATASI METNI Go'nun net/http prozasi ("Get \"...\": dial tcp
        // ...: connect: connection refused") ve o metin PORT EDILMIYOR —
        // `human_gate_down` ile AYNI sinif. Differential'daki her doctor vakasi
        // COOLIFY_URL'i sahte gate'e cevirdigi icin bu kola HIC girilmiyor.
        Err(ureq::Error::Transport(t)) => {
            (format!("✗ Coolify API unreachable: {t}\n"), false)
        }
    }
}

// run_rotate_skip, `wapps rotate skip <run-id> <project>/<key> --reason <why>`.
//
// KAPI SIRASI, ve BIR ONCEKI FIILIN TAM TERSI:
//   1. arite         → cagiranda (cobra ExactArgs(2))
//   2. --reason      → INTERNAL
//   3. AJAN KAPISI   → AGENT_MODE_REFUSED
//   4. ACTION_UNAVAILABLE (her zaman)
//
// 2'nin 3'TEN ONCE olmasi GOZLEMLENEBILIR: ajan modunda `--reason` YOKKEN ret
// AGENT_MODE_REFUSED DEGIL INTERNAL. `secrets rotate-plan`da sira TERSINE —
// orada kapi PersistentPreRunE'da olduğu icin arguman kontrolunden ONCE
// kosuyor. Iki fiil kardes gorunuyor; siralari birbirinden TAHMIN EDILEMEZ.
// Olculdu: agent_rotate_skip_reason_check_precedes_the_agent_gate.
//
// KAPI NEDEN BURADA, BIR TABLODA DEGIL — ve bu bir BULGUYDU:
// Go'da rotateSkipCmd bir `Annotations: {wapps_agent_policy: refuse_agent}`
// TASIYORDU ama o annotation OLUYDU. Onu okudugu sanilan secretsPreRunE
// annotation'a HIC bakmiyor (politikayi AYRI bir tablodan, agentPolicy'den
// aliyor), ve zaten o hook bu komut icin hic kosmuyor cunku RotateCmd KOKE
// mount'lu. Reddi gercekten yapan sey RunE'nin icindeki elle yazilmis kontrol.
// Annotation'a GUVENIP elle kontrolu silen biri `wapps rotate skip`i ajanlara
// ACARDI. Annotation IKI tarafta da SILINDI (olu mekanizma yetkili
// gorunuyordu); kapi burada ACIKCA yaziliyor ve bir tabloya devredilmiyor.
//
// Yorum yeter DEGIL — yorumlar silinir. Kontrolu ADIYLA olcen testler:
// tests/rootmount.rs ve Go tarafinda cmd/secrets/rotate_skip_test.go. Ikisi de
// KARSILASTIRMA degil IDDIA, cunku kontrolu iki tarafta da silmek
// differential'i YESIL birakirdi.
//
// RET METNI `agentmode::guard`in uretecegi metin DEGIL: kendi cumlesi var
// ("presence-admin ceremony"). Kod ayni (AGENT_MODE_REFUSED), cumle ayri —
// `rm` ile `trust-repo` arasindaki ayrimin aynisi.
fn run_rotate_skip(run_id: &str, target: &str, reason: &str) -> Result<(), CmdError> {
    if reason.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "rotate skip: --reason is required (a recorded skip must state WHY the key needs no rotation)",
        )));
    }
    if agentmode::is_agent() {
        return Err(CmdError::Cli(Error::new(
            Code::AgentModeRefused,
            "rotate skip is a presence-admin ceremony; a human must run it in a terminal",
        )));
    }
    // Motor hazir (Go: internal/rotation.RunLedger.SkipKey); eksik olan
    // CLI↔canli rotasyon-ledger baglamasi. Sessiz bir no-op YERINE adlandirilmis
    // bir ret — bir operator SKIP'in yazildigini SANMASIN. Mesaj IKI argumani
    // da gomuyor, cunku operator hangi anahtarin askida kaldigini gormeli.
    Err(CmdError::Cli(Error::new(
        Code::ActionUnavailable,
        format!(
            "rotate skip ({run_id} {target}) is a control-plane admin op; the SKIP engine is ready (internal/rotation) but the CLI↔live rotation-ledger wiring lands with the rotation executor"
        ),
    )))
}

// run_rotate_plan, `wapps secrets rotate-plan --identity <principal>`.
//
// KAPI SIRASI, ve BIRINCI ADIM BU FIILI KARDESINDEN AYIRIYOR:
//   1. ajan politikasi → `control`: CONTROL_PLANE_REQUIRED
//   2. --identity zorunlulugu → INTERNAL
//   3. --since RFC3339 dogrulamasi → INTERNAL
//   4. GET /v1/admin/rotate-plan
//
// 1'in 2'DEN ONCE olmasi GOZLEMLENEBILIR: ajan modunda `--identity` YOKKEN
// bile ret CONTROL_PLANE_REQUIRED, arguman hatasi DEGIL — cunku kapi
// PersistentPreRunE'da, kontrol ise RunE'de. `wapps rotate skip` bunun TAM
// TERSI (orada kapi RunE'nin ICINDE ve `--reason` kontrolundan SONRA), ve iki
// fiil ayni aileden gorunduğu icin bu tahmin edilemez. Olculdu:
// agent_rotate_plan_gate_precedes_the_identity_check.
//
// BAGLAMA KAPISI YOK ve config GEREKMIYOR (Go: bindingExempt): rotate-plan bir
// PRINCIPAL sorgusudur, bir depo->proje baglamasina bagli degil. Pinsiz bir
// config'in yaninda baglama sorusu HIC sorulmaz.
fn run_rotate_plan(
    identity: String,
    since: String,
    assume_policy: bool,
    json: bool,
) -> Result<(), CmdError> {
    agentmode::guard(agentmode::POLICY_CONTROL, agentmode::is_agent()).map_err(CmdError::Cli)?;
    if identity.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "rotate-plan: --identity is required (human:<email> | service:<common_name>)",
        )));
    }
    // BOS `--since` "verilmemis" demek (Go: `if rotatePlanSince != ""`), yani
    // dogrulamaya HIC girmiyor ve sorguya HIC eklenmiyor.
    if !since.is_empty() && !rotateplan::rfc3339_valid(&since) {
        // RET CUMLESI Go'nunkinden AYRI ve bu bilerek: Go'nun time.Parse'i
        // reddi ayristiricinin ic durumuyla anlatiyor (bes ayri bicim). Kod,
        // onek, kurtarma satiri ve cikis kodu AYNI; ayrisan tek sey proza.
        // Vaka differential DISINDA (cases.py, EXCLUDED) ve KABUL KUMESI
        // tests/rotateplan.rs'te Go'dan olculmus bir tabloyla pinli.
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            format!(
                "rotate-plan: --since must be RFC3339: parsing time {} as {}",
                go_quote(&since),
                go_quote("2006-01-02T15:04:05Z07:00")
            ),
        )));
    }

    let res = store::rotate_plan(&identity, &since, assume_policy).map_err(CmdError::Cli)?;
    let mut out = std::io::stdout();
    if json {
        // Go: json.Encoder + SetIndent("","  ") + SetEscapeHTML(false), ve
        // Encode SONA newline ekler. serde_json HTML kacisi YAPMIYOR.
        let text = serde_json::to_string_pretty(&res)
            .map_err(|e| CmdError::Plain(format!("rotate-plan: {e}")))?;
        let _ = writeln!(out, "{text}");
        return Ok(());
    }
    let _ = write!(out, "{}", rotateplan::render_text(&res));
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
//      Ad duzlemi, yani audit'e value.read DUSMEZ. Hatasi SINIFA GORE
//      ayriliyor: EPOCH_DOWNGRADE bir KAPI (reddedilir, yazim BASLAMAZ), geri
//      kalan her sey yutulur. YAN ETKI ve tam da bu yuzden kapi: bu cagri
//      EPOCH PIN'INI kontrol eden TEK cagri — POST /import kontrolu HIC
//      cagirmiyor, yani hata yutulursa geri sarilmis bir store'a SESSIZCE
//      yazilirdi.
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
    // ile kesisim. Hata SINIFA GORE ayriliyor (importenv::existing_names):
    // EPOCH_DOWNGRADE bir KAPI — bu cagri `import-env`in epoch pin'ini gordugu
    // TEK yer, cunku import kontrolu HIC cagirmiyor. Geri kalan her sey bir
    // kolaylik hatasi ve YUTULUYOR.
    let existing = importenv::existing_names(
        store::keys(&cfg.project).map(|kr| kr.keys.into_iter().map(|k| k.key_name).collect()),
    )
    .map_err(CmdError::Cli)?;
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
    exec_core(&ctx, argv, &prefix, &intent, break_glass, agent)
}

// exec_core, exec-ailesinin KAPIDAN SONRAKI ortak yoludur ve Go'daki `runExec`
// ile AYNI parcayi tasiyor: --break-glass reddi, --intent reddi, config
// gereksinimi, store okumasi, inject→scrub→run, exit-code yansimasi.
//
// AYRI BIR FONKSIYON OLMASI BIR TERCIH DEGIL, SOZLESME: `wapps tofu` bu yola
// KAPIYI KENDI UYGULADIKTAN SONRA giriyor (Go: runTofu → runExec). Cift kod
// yazilsaydi iki yol sessizce ayrisabilirdi — ve ayrisacagi yer, sarimin
// scrubber'i ya da exit-code yansimasi olurdu.
//
// `gate` BURADA CAGRILMIYOR: cagiran onu ZATEN cagirdi. Go'da da boyle
// (runExec kapiyi bilmez; kapi ya PersistentPreRunE'da ya runTofu'da).
#[allow(clippy::too_many_arguments)]
fn exec_core(
    ctx: &Ctx,
    argv: &[String],
    prefix: &str,
    intent: &str,
    break_glass: bool,
    agent: bool,
) -> Result<(), CmdError> {
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
    // HATA BAGLAMI DAIMA "exec" — `wapps tofu` icin bile. Sarim bu ORTAK yola
    // giriyor ve Go'da da baglam "exec"; bir port burada kolayca "tofu" yazar
    // ve ayrisir. Olculdu (agent_tofu_no_config).
    let cfg = ctx.require_store_config("exec").map_err(CmdError::Cli)?;
    // intent.Parse Go'da runExecStore'un ICINDE, yani config kapisindan SONRA
    // kosuyor. Olculdu (human_exec_unknown_intent): config'i olmayan bir
    // dizinde `--intent wat`, "unknown intent" DEGIL "no .wapps.yaml found"
    // vermeli. Sira gozlemlenebilir.
    if intent != "dev" && !intent.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            format!("unknown intent {} (allowed: dev, deploy)", go_quote(intent)),
        )));
    }
    let values = store::read_all(&cfg.project).map_err(CmdError::Cli)?;
    let archive = values_to_archive_json(&values).map_err(CmdError::Plain)?;
    let (injected, scrub) = execverb::exec_env_and_values(archive.as_bytes(), prefix)
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

// run_tofu, `wapps tofu <args...>` — `secrets exec --prefix "" -- tofu <args...>`
// icin birinci-sinif sarim.
//
// KAPI SIRASI, ve ILK IKI ADIM BU FIILE OZEL:
//   1. yardim dali    → arguman YOKSA ya da args[0] "-h"/"--help" ise. YALNIZCA
//      args[0]: `tofu plan --help` bayragi tofu'ya GECIRIR.
//   2. ajan politikasi → `allow`, ve BURADA ACIKCA cagriliyor
//   3. baglama kapisi  → BURADA ACIKCA cagriliyor
//   4. exec_core       → config gereksinimi, store okumasi, inject→scrub→run
//
// 2 ve 3'un BURADA olmasi bir tekrar degil bir ZORUNLULUK: TofuCmd KOKE
// mount'lu, yani Go'da SecretsCmd.PersistentPreRunE HIC kosmuyor. Kapi burada
// yeniden uygulanmasaydi `wapps tofu`, `secrets exec`in confused-deputy
// korumasinin etrafindan dolasan kapisiz bir sir yolu olurdu. Go kaynagi bunu
// "F1 fix" diye adlandiriyor; olcusu
// agent_tofu_binding_is_enforced_despite_the_root_mount.
//
// `--project` / `--config` ATIL ve bu bir eksiklik degil, sahadaki ikilinin
// OLCULEN davranisi: cobra'da `DisableFlagParsing: true` bayraklarin HICBIRINI
// ayristirmiyor, global olanlari da. Ayni bayrakla `secrets exec` ajan modunda
// BINDING_UNPINNED verirken `tofu` NOT_FOUND veriyor
// (agent_tofu_project_flag_is_inert). Bu yuzden asagida Ctx VARSAYILAN yolla
// cozuluyor — cagiranin gordugu bayraklar BILEREK gecirilmiyor.
//
// prefix "" (VERBATIM) ve intent "dev" SABIT. Prefix'in bos olmasi sarimin var
// olma sebebi: store anahtarlari zaten TAM adlariyla duruyor (`TF_VAR_*`,
// `AWS_*`), o yuzden bir onek daha eklemek cift-prefix uretirdi — v0.23.0
// oncesinde tam olarak bu oluyordu. Olcusu human_tofu_injects_values_verbatim.
fn run_tofu(args: &[String]) -> Result<(), CmdError> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        let _ = cli::build().find_subcommand_mut("tofu").unwrap().print_help();
        std::process::exit(0);
    }
    let agent = agentmode::is_agent();
    agentmode::guard(agentmode::POLICY_ALLOW, agent).map_err(CmdError::Cli)?;
    let ctx = Ctx::resolve(None, None).map_err(CmdError::Cli)?;
    let mut errw = std::io::stderr();
    configctx::check_repo_binding(
        &ctx,
        agent,
        agentmode::stdin_is_tty(),
        &mut errw,
        &|repo, project, w| configctx::bind_prompt(repo, project, w),
    )
    .map_err(CmdError::Cli)?;

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("tofu".to_string());
    argv.extend_from_slice(args);
    exec_core(&ctx, &argv, "", "dev", false, agent)
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
