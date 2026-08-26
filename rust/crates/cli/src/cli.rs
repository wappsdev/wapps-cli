// cli, komut agacini ve tek hata basma yolunu tasir.
//
// YASAK — MEKANIZMA OLARAK: bu dosyadaki clap yapilarinda `///` doc yorumu
// KULLANILMAZ. clap'in derive'i `///`'yi yardim metnine cevirir ve boylece bir
// spec referansi sessizce `--help` ciktisina girer; bu estate tam olarak onu iki
// release boyunca ELLE temizledi. Yardim metni ACIKCA `help = ...` ile yazilir.
// Korumasi: tests/helptext.rs (mutasyonla kanitli).
use crate::clierr::{self, Code};
use clap::{Arg, ArgAction, Command};
use std::io::Write;

/// CmdError, Go'daki iki hata sinifini AYIRIR ve bu ayrim gozlemlenebilir:
/// insan yolunda bir clierr hatasi kurtarma satiri basar, duz bir hata BASMAZ
/// (Go'da RecoveryOf duz hatada "" doner).
pub enum CmdError {
    Cli(clierr::Error),
    Plain(String),
}

impl From<clierr::Error> for CmdError {
    fn from(e: clierr::Error) -> Self {
        CmdError::Cli(e)
    }
}

/// build, komut agacini kurar.
pub fn build() -> Command {
    Command::new("wapps")
        .about("wapps umbrella CLI — secrets, Tofu, Coolify and deploys for the wappsdev estate")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Verbose output"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("string")
                .help("Path to a .wapps.yaml; secrets resolve against its dir (default: ./.wapps.yaml)"),
        )
        .arg(
            Arg::new("project")
                .short('p')
                .long("project")
                .value_name("string")
                .conflicts_with("config")
                .help("Registered project name; resolves to that project's .wapps.yaml"),
        )
        .subcommand(
            Command::new("secrets")
                .about("Read and write this project's secrets in the gate")
                .subcommand(
                    Command::new("set")
                        .about("Write a secret value into the store (interactive, no echo)")
                        // Arite ELLE kontrol ediliyor (cobra ExactArgs(1) gibi).
                        .arg(Arg::new("key").num_args(0..).help("Secret key name"))
                        .arg(
                            Arg::new("from-file")
                                .long("from-file")
                                .value_name("string")
                                .help("read the value from this file instead of prompting (keeps it out of argv and shell history)"),
                        ),
                )
                .subcommand(
                    Command::new("exec")
                        .about("Run a command with the project's secrets injected as env vars")
                        // trailing_var_arg + allow_hyphen_values: `exec -- pnpm dev`
                        // sonrasindaki HER SEY cocuga ait. Aksi halde clap
                        // `--watch` gibi bir cocuk bayragini KENDI bayragi
                        // sanip reddederdi.
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .arg(Arg::new("argv").num_args(0..).help("Command and arguments"))
                        .arg(
                            Arg::new("prefix")
                                .long("prefix")
                                .value_name("string")
                                .help("prefix prepended to each env var name (default: none — keys are stored under their final name)"),
                        )
                        .arg(
                            Arg::new("break-glass")
                                .long("break-glass")
                                .action(ArgAction::SetTrue)
                                .help("deploy-intent only: TTY-only CF-outage override; HARD-REFUSED in agent mode"),
                        )
                        .arg(
                            Arg::new("intent")
                                .long("intent")
                                .value_name("string")
                                .help("freshness intent: dev (tolerate cache) | deploy (fresh-or-fail)"),
                        ),
                )
                .subcommand(
                    Command::new("apply")
                        .about("Write every declared consumption target from the store"),
                )
                .subcommand(
                    Command::new("get")
                        .about("Print a single secret value (TTY only; refused in agent mode)")
                        // Arite KONTROLU elle yapiliyor (cobra'nin ExactArgs(1)'i
                        // gibi), clap'e birakilmiyor: clap'in kendi metni
                        // ("unexpected argument ... found") sahadaki ikilinin
                        // bastigi metin DEGIL.
                        .arg(Arg::new("key").num_args(0..).help("Secret key name")),
                )
                .subcommand(
                    Command::new("list")
                        .about("List the project's secret names (never values)")
                        // cobra'da listCmd'in Args'i YOK, yani varsayilan
                        // ArbitraryArgs: fazladan arguman SESSIZCE yok sayiliyor.
                        // Olculdu (`secrets list EXTRA` → cikis 0). Burada da
                        // serbest birakiliyor; clap'e birakilsa "unexpected
                        // argument" ile 2 dondururdu.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("status")
                        .about("Machine-readable gate/session state (safe in every mode)")
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("emit the machine-readable JSON schema"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("rm")
                        .about("Remove a key from the store (irreversible; refused in agent mode)")
                        // Arite ELLE (cobra ExactArgs(1)).
                        .arg(Arg::new("key").num_args(0..).help("Secret key name"))
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("skip the interactive confirm (still refused in agent mode)"),
                        ),
                )
                .subcommand(
                    Command::new("trust-repo")
                        .about("Pin this repo to its project so an agent cannot target another (TTY only)")
                        // cobra'da trustRepoCmd'in Args'i YOK -> ArbitraryArgs:
                        // fazladan arguman SESSIZCE yok sayiliyor. Olculdu.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("init")
                        .about("Scaffold .wapps.yaml for a fresh repo")
                        .arg(
                            Arg::new("force")
                                .long("force")
                                .action(ArgAction::SetTrue)
                                .help("overwrite an existing .wapps.yaml (default refuses to clobber)"),
                        )
                        .arg(
                            Arg::new("project-name")
                                .long("project-name")
                                .value_name("string")
                                .help("project name in the gate (default: current directory name)"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                ),
        )
        // `projects` KOKTE mount'lu, `secrets` altinda DEGIL — ve bu bir
        // duzenleme tercihi degil, GOZLEMLENEBILIR bir kapi farki: kok mount
        // demek Go'da SecretsCmd.PersistentPreRunE'un (ajan-guard + depo pini)
        // CALISMAMASI demek. Her yaprak kendi guard'ini cagirir ve depo→proje
        // baglama kontrolu HIC yapilmaz. Olculdu: ajan modunda
        // `--project testproj projects list` CALISIR, ayni bayrakla
        // `secrets list` BINDING_UNPINNED ile duser.
        .subcommand(
            Command::new("projects")
                .about("List the projects in the secrets gate / remove one entirely")
                .subcommand(
                    Command::new("list")
                        .about("Project names you can see (names only, never values)")
                        // cobra.NoArgs — ve reddin METNI cobra'ya ait:
                        // `unknown command "X" for "wapps projects list"`.
                        .arg(Arg::new("extra").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("rm")
                        .about("Remove a project and ALL its data (admin; irreversible; refused in agent mode)")
                        .arg(Arg::new("project").num_args(0..).help("Project name"))
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("skip the interactive confirm (still refused in agent mode)"),
                        ),
                ),
        )
}

/// clap_error_to_cmd_error, clap'in KENDI hata yolunu ele gecirir.
///
/// Bu, portun acik regresyonlarindan biriydi: clap hatayi kendisi basip
/// exit(2) yapiyor, yani bozuk bir cagri HIC zarf uretmiyor. Sahadaki ikili
/// bozuk cagrida da zarf uretip 1 ile cikiyor.
pub fn clap_error_to_cmd_error(e: &clap::Error) -> CmdError {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let invalid = e.get(ContextKind::InvalidArg).and_then(|v| match v {
        ContextValue::String(s) => Some(s.clone()),
        ContextValue::Strings(s) => s.first().cloned(),
        _ => None,
    });
    match e.kind() {
        ErrorKind::UnknownArgument => {
            let raw = invalid.unwrap_or_default();
            // cobra "unknown flag: --x" der; bayrak adindan deger kismini atar.
            let name = raw.split('=').next().unwrap_or(&raw).to_string();
            CmdError::Plain(format!("unknown flag: {name}"))
        }
        ErrorKind::InvalidValue | ErrorKind::InvalidSubcommand => {
            CmdError::Plain(e.kind().as_str().unwrap_or("invalid command").to_string())
        }
        _ => CmdError::Plain(
            e.to_string().lines().next().unwrap_or("invalid command").trim_start_matches("error: ").to_string(),
        ),
    }
}

/// report_error, CLI'nin TEK hata basma yeridir ve okuyucuya gore BICIM secer.
///
/// Sozlesme tek eksenli: `agent` bayragi, verb'leri zaten kapilayan
/// agentmode::is_agent() ile AYNI saptama. Boylece bir reddin KENDISI ile o
/// reddin BICIMI ayrisamaz.
///
///   - insan terminali → "Error: <cumle>" + "  → <kurtarma>"
///   - ajan/CI → zarf: stderr'e TEK satir JSON
///
/// Iki bicim YAN YANA basilmaz; her okuyucu TAM OLARAK birini gorur.
pub fn report_error<W: Write>(w: &mut W, err: &CmdError, agent: bool) {
    match (agent, err) {
        (true, CmdError::Cli(e)) => clierr::emit(w, e),
        // Duz hata ajan modunda Internal'a sarilir; mesaj ZATEN hatanin tam
        // metni oldugu icin bir kez daha sarilmaz ("x: x" olmasin).
        (true, CmdError::Plain(msg)) => {
            clierr::emit(w, &clierr::Error::new(Code::Internal, msg.clone()))
        }
        (false, CmdError::Cli(e)) => {
            let _ = writeln!(w, "Error: {e}");
            if !e.recovery.is_empty() {
                let _ = writeln!(w, "  → {}", e.recovery);
            }
        }
        // Duz hatada kurtarma satiri YOK — Go'da RecoveryOf("") doner.
        (false, CmdError::Plain(msg)) => {
            let _ = writeln!(w, "Error: {msg}");
        }
    }
}
