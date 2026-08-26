// wapps ikilisinin giris noktasi. Adim 6 dilimi: `secrets get`.
use std::io::Write;
use std::process::ExitCode;
use wapps::agentmode;
use wapps::cli::{self, CmdError};
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
