// wapps ikilisinin giris noktasi. Adim 6 dilimi: `secrets get`.
use std::io::Write;
use std::process::ExitCode;
use wapps::agentmode;
use wapps::cli::{self, CmdError};
use wapps::clierr::{Code, Error};
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

// go_quote, Go'nun %q bicimini taklit eder (basit ASCII vakasi yeterli: anahtar
// adlari bu kumeden).
fn go_quote(s: &str) -> String {
    format!("{s:?}")
}
