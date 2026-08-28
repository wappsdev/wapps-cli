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
                // `conflicts_with("config")` BILEREK YOK. clap onu
                // AYRISTIRMA aninda reddediyordu ve KENDI cumlesini basiyordu
                // ("the argument '--config <string>' cannot be used with
                // '--project <string>'"). Go'da konusan katman o DEGIL:
                // cobra'nin grup dogrulamasi degil, `resolveProjectFlag`in
                // programatik kontrolu ates ediyor ve "--config and --project
                // are mutually exclusive" diyor. OLCULDU (differential
                // human_/agent_both_identity_flags_are_rejected, duzeltmeden
                // ONCE DIFFERENT=2).
                //
                // Ret artik main.rs'te, dispatch'ten once — cunku `tofu` bu
                // reddi ALMIYOR (bkz. orasi).
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
                // `policy` bir AILE komutu. Ajan-modu anahtarı SecretsCmd'nin
                // ALTINDAKI ILK seviye addir ("policy"), yaprak adi degil —
                // boylece `policy set` data-plane `set`in `allow` iznini MIRAS
                // ALAMAZ. Go'da gateKey bunu yapiyor; burada agac zaten oyle
                // kurulu ve her yaprak POLICY_CONTROL ile kapiliyor.
                .subcommand(
                    Command::new("policy")
                        .about("Show / set / lint the gate's access policy (admin)")
                        .subcommand(
                            Command::new("show")
                                .about("Fetch the active policy version + rules (admin verb, write-AUD session)")
                                .arg(
                                    Arg::new("json")
                                        .long("json")
                                        .action(ArgAction::SetTrue)
                                        .help("emit the raw policy JSON"),
                                )
                                .arg(Arg::new("ignored").num_args(0..).hide(true)),
                        )
                        .subcommand(
                            Command::new("set")
                                .about("Lint + diff + CAS write of a policy file (version = current+1)")
                                // Arite ELLE (cobra ExactArgs(1)).
                                .arg(Arg::new("file").num_args(0..).help("Policy file path"))
                                .arg(
                                    Arg::new("yes")
                                        .long("yes")
                                        .action(ArgAction::SetTrue)
                                        .help("skip the interactive confirm (still TTY-only via the agent gate)"),
                                ),
                        )
                        .subcommand(
                            Command::new("lint")
                                .about("Offline schema validation + overlap analysis (warnings only)")
                                .arg(Arg::new("file").num_args(0..).help("Policy file path")),
                        ),
                )
                .subcommand(
                    Command::new("rotate-plan")
                        .about("What must be rotated after an offboard, derived from the audit ledger")
                        .arg(
                            Arg::new("identity")
                                .long("identity")
                                .value_name("string")
                                .help("principal to plan for (human:<email> | service:<common_name>)"),
                        )
                        .arg(
                            Arg::new("since")
                                .long("since")
                                .value_name("string")
                                .help("RFC3339 lower bound for ledger rows"),
                        )
                        .arg(
                            Arg::new("assume-policy")
                                .long("assume-policy")
                                .action(ArgAction::SetTrue)
                                .help("union every key the identity's rules COULD read (paranoid superset)"),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .action(ArgAction::SetTrue)
                                .help("emit machine-readable JSON"),
                        )
                        // cobra'da rotatePlanCmd'in Args'i YOK -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("import-env")
                        .about("Bulk import KEY=VALUE pairs from an env file into the store")
                        // Arite ELLE (cobra ExactArgs(1)).
                        .arg(Arg::new("file").num_args(0..).help("Env file path")),
                )
                .subcommand(
                    Command::new("env")
                        .about("Emit the project's secrets as .envrc-style export lines")
                        .arg(
                            Arg::new("write")
                                .long("write")
                                .value_name("string")
                                .help("write env output to this file (0600, atomic) instead of stdout; AI-safe path that never prints values"),
                        )
                        .arg(
                            Arg::new("prefix")
                                .long("prefix")
                                .value_name("string")
                                .help("prefix prepended to each KEY (default: none — keys are stored under their final name)"),
                        )
                        // cobra'da envCmd'in Args'i YOK -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
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
        // `doctor` KOKTE mount'lu ve AJAN KAPISI YOK — ne PersistentPreRunE
        // (kok mount), ne RunE'de bir kontrol. Bu bir bosluk degil bir karar:
        // teshis, "baska her sey hata veriyor" anindaki ilk komut ve DEGER
        // BASMIYOR (`secrets status` ile ayni gerekce).
        .subcommand(
            Command::new("doctor")
                .about("Check all dependencies + access (onboarding preflight)")
                .arg(
                    Arg::new("for")
                        .long("for")
                        .value_name("string")
                        .help("scope the check: 'tofu' validates only the env needed by 'wapps secrets sync'; empty/'all' runs the full check"),
                )
                // cobra'da doctorCmd'in Args'i YOK -> ArbitraryArgs: fazladan
                // arguman SESSIZCE yutulur. Olculdu.
                .arg(Arg::new("ignored").num_args(0..).hide(true)),
        )
        // `rotate` KOKTE mount'lu, `secrets` altinda DEGIL — ve bunun
        // gozlemlenebilir sonucu var: Go'da SecretsCmd.PersistentPreRunE
        // KOSMUYOR, yani ajan kapisi ve baglama kapisi bu agac icin HIC
        // calismiyor. Reddi yapan sey yaprak RunE'nin ICINDEKI elle yazilmis
        // kontrol (bkz. run_rotate_skip).
        .subcommand(
            Command::new("rotate")
                .about("Manage value-rotation worklist runs (offboard cleanup)")
                .subcommand(
                    Command::new("skip")
                        .about("Recorded admin SKIP of a rotation worklist key (resolves NEEDS_TRIAGE)")
                        // Arite ELLE (cobra ExactArgs(2)).
                        .arg(Arg::new("args").num_args(0..).help("Run id and <project>/<key>"))
                        .arg(
                            Arg::new("reason")
                                .long("reason")
                                .value_name("string")
                                .help("why this key needs no value rotation (recorded in the skip attestation; required)"),
                        ),
                ),
        )
        // `tofu` KOKTE mount'lu — `secrets` altinda DEGIL, ve bu GOZLEMLENEBILIR
        // bir kapi farki: Go'da SecretsCmd.PersistentPreRunE (ajan-guard + depo
        // pini) CALISMAZ, o yuzden runTofu kapiyi ACIKCA yeniden uyguluyor.
        //
        // `disable_flag_parsing` YOK, cunku clap'te oyle bir sey gerekmiyor:
        // `trailing_var_arg` + `allow_hyphen_values` tofu'nun kendi
        // bayraklarini (`-target`, `-var`, `-input=false`) cocuga aynen
        // birakir. cobra'nin `DisableFlagParsing: true`sunun IKINCI etkisi —
        // GLOBAL bayraklarin da atil kalmasi — burada agac degil CAGIRAN
        // tarafinda tasiniyor: main.rs tofu dalinda `--project`/`--config`
        // degerlerini GORMEZDEN gelir. Olculdu
        // (agent_tofu_project_flag_is_inert).
        //
        // `disable_help_flag`: `-h`/`--help` clap tarafindan YAKALANMAMALI.
        // Go'da yardim YALNIZCA args[0] "-h"/"--help" iken basiliyor;
        // `tofu plan --help` bayragi tofu'ya GECIRIYOR. Ayni ayrimi
        // koruyabilmek icin bayragi clap'ten geri aliyoruz.
        .subcommand(
            Command::new("tofu")
                .about("Run tofu with the project's secrets injected as TF_VAR_*")
                .trailing_var_arg(true)
                .allow_hyphen_values(true)
                .disable_help_flag(true)
                .arg(Arg::new("argv").num_args(0..).help("Command and arguments")),
        )
        // `dr` KOKTE mount'lu (Go: rootCmd.AddCommand(secrets.DrCmd)), yani
        // SecretsCmd.PersistentPreRunE bu agac icin HIC kosmuyor: ne ajan
        // kapisi ne baglama kapisi. Her yaprak kendi guard'ini ELDE cagiriyor
        // ve `verify` BILEREK guard'siz (sir kullanmiyor, aga cikmiyor —
        // `doctor` ile ayni gerekce). `projects list`in baglama kapisini hic
        // gormemesiyle AYNI yapisal sebep.
        //
        // `dr` AGACI ARTIK TAM: alti alt komutun altisi da burada. En son
        // `accept-epoch-reset` indi ve onu disarida tutan gerekce ("store'da
        // `AuditHead` rotasi + `X-Wapps-Intent` basligi, sahte gate'te o rota
        // — ucu de YOK") bir EKSIKLIK listesiydi, bir imkansizlik degil:
        // ucu de yazildi ve Cargo.toml'a TEK bir crate eklenmedi.
        //
        // `restore` ARTIK VAR. Onceki tur onu "XChaCha20-Poly1305 ring'de yok,
        // yani yeni bir CRATE gerekiyor" diye disarida birakmisti; olcum o
        // SONUCU curuttu (yerinde olcum DOGRUYDU: ring'de gercekten yok).
        // XChaCha = HChaCha20 + ring'in ZATEN tasidigi ChaCha20-Poly1305, ve
        // port Cargo.toml'a TEK bir crate eklemeden indi (docs/PORT-dr.md §7.1).
        .subcommand(
            Command::new("dr")
                .about("Disaster recovery against the B2 ciphertext replica")
                .subcommand(
                    Command::new("verify")
                        .about("Structural integrity check of the B2 replica snapshot (read-only)")
                        .arg(
                            Arg::new("snapshot")
                                .long("snapshot")
                                .value_name("string")
                                .help("local (air-gapped) copy of the B2 replica"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("restore")
                        .about("TTY-only DR ceremony: Shamir shares + snapshot → 0600 env file")
                        .arg(
                            Arg::new("snapshot")
                                .long("snapshot")
                                .value_name("string")
                                .help("local (air-gapped) copy of the B2 replica"),
                        )
                        .arg(
                            Arg::new("project")
                                .long("project")
                                .value_name("string")
                                .help("project to reconstruct"),
                        )
                        .arg(
                            Arg::new("out")
                                .long("out")
                                .value_name("string")
                                .help("0600 env file to write the restored values into"),
                        )
                        .arg(
                            Arg::new("confirm")
                                .long("confirm")
                                .action(ArgAction::SetTrue)
                                .help("confirm the TTY restore ceremony"),
                        )
                        // StringArrayVar: `--share` TEKRARLANABILIR, sira KORUNUR.
                        .arg(
                            Arg::new("share")
                                .long("share")
                                .value_name("string")
                                .action(ArgAction::Append)
                                .help("MASTER_KEK Shamir share file, hex (repeat ≥2; assembled key NEVER persisted)"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("split")
                        .about("TTY-only: split the store's MASTER_KEK into N-of-M Shamir shares for offline custody")
                        .arg(
                            Arg::new("parts")
                                .long("parts")
                                .value_name("int")
                                .help("total Shamir shares to create"),
                        )
                        .arg(
                            Arg::new("threshold")
                                .long("threshold")
                                .value_name("int")
                                .help("shares required to reconstruct"),
                        )
                        .arg(
                            Arg::new("out-dir")
                                .long("out-dir")
                                .value_name("string")
                                .help("directory for the 0600 hex share files"),
                        )
                        .arg(
                            Arg::new("master-hex")
                                .long("master-hex")
                                .value_name("string")
                                .help("supply the MASTER_KEK (64-hex) explicitly; NOTE: argv is visible via `ps`/shell history — prefer the no-echo prompt default"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("combine")
                        .about("TTY-only: reconstruct MASTER_KEK from >=threshold Shamir shares (to re-set the Worker secret)")
                        // StringArrayVar: `--share` TEKRARLANABILIR ve sira
                        // KORUNUR. clap'te bunun karsiligi Append.
                        .arg(
                            Arg::new("share")
                                .long("share")
                                .value_name("string")
                                .action(ArgAction::Append)
                                .help("hex Shamir share file (repeat >= threshold)"),
                        )
                        .arg(
                            Arg::new("out")
                                .long("out")
                                .value_name("string")
                                .help("0600 file to write the reconstructed MASTER_KEK hex into"),
                        )
                        .arg(
                            Arg::new("expect-kid")
                                .long("expect-kid")
                                .value_name("string")
                                .help("refuse unless the reconstructed key's kid equals this (get it from `wapps dr verify`); without it the check is left to your eyes"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                // `bootstrap` ARTIK VAR. Onceki tur onu "internal/tofu portu
                // gerekiyor, Rust'ta tofu modulu YOK" diye disarida
                // birakmisti; olcum o gerekcenin YARISININ BAYAT oldugunu
                // gosterdi: `REQUIRED_ENV_VARS` (bes girdi, adlar VE ipuclari)
                // `doctorverb.rs` icinde ZATEN duruyordu. Eksik olan yalnizca
                // `PreflightEnv`in METNI ile `BootstrapEnvVars` katalogu idi —
                // ikisi de saf veri/bicimleme, ag da disk de YOK.
                //
                // `trailing_var_arg` + `allow_hyphen_values`: `-- tofu apply
                // -target=x` sonrasindaki HER SEY cocuga ait (`exec` ile ayni
                // gerekce; aksi halde clap `-target`i KENDI bayragi sanardi).
                .subcommand(
                    Command::new("bootstrap")
                        .about("TTY-only: prompt for bootstrap tokens (no echo) and run a command with them injected")
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .arg(Arg::new("argv").num_args(0..).help("Command and arguments"))
                        // StringArrayVar -> Append: `--var` TEKRARLANABILIR.
                        .arg(
                            Arg::new("var")
                                .long("var")
                                .value_name("string")
                                .action(ArgAction::Append)
                                .help("extra env var NAME to prompt and inject (repeatable; skipped if already set)"),
                        )
                        .arg(
                            Arg::new("skip-preflight")
                                .long("skip-preflight")
                                .action(ArgAction::SetTrue)
                                .help("skip the tofu backend env contract preflight (non-tofu commands)"),
                        ),
                )
                // `--project` BURADA YEREL, ve bu bir duzenleme tercihi degil
                // Go'nun gozlemlenebilir sekli: cobra'da `StringVar` kokun
                // persistent `-p`sini GOLGELIYOR (olculdu — bu alt komutun
                // yardiminda "Global Flags" altinda `-p` YOK, yalnizca `-c`
                // ve `-v` var). Deger `Ctx::resolve`e HIC girmiyor; seremoni
                // proje adini dogrudan bayraktan okuyor.
                //
                // Kisa bicim (`-p`) BILEREK YOK: Go'daki `StringVar` da
                // kisasiz. Buraya `-p` eklemek kokun kisa bicimini bu alt
                // komutta yeniden acardi.
                .subcommand(
                    Command::new("accept-epoch-reset")
                        .about("TTY-only ceremony: verify the audit head against the paper envelope, then lower the epoch pin")
                        .arg(
                            Arg::new("project")
                                .long("project")
                                .value_name("string")
                                .help("project whose epoch pin will be reset"),
                        ),
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
