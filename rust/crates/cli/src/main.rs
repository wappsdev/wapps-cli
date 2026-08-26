// wapps ikilisinin giris noktasi. Adim 6 dilimi: `secrets get`.
use std::io::Write;
use std::process::ExitCode;
use wapps::agentmode;
use wapps::applyverb;
use wapps::cli::{self, CmdError};
use wapps::configctx::{self, Ctx};
use wapps::execverb;
use wapps::clierr::{Code, Error};
use wapps::gojson::quote as go_quote;
use wapps::setverb;
use wapps::store;

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
        _ => {
            let _ = cli::build().print_help();
            std::process::exit(0);
        }
    }
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
