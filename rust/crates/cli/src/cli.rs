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
    /// Exit: the verb has already written everything it had to say and owns
    /// its process exit code — `wapps deploy`'s 0..8 contract, or a child's
    /// code mirrored by the exec family. The reporter prints nothing for it.
    Exit(u8),
}

impl CmdError {
    /// exit_code, the code the process leaves with. Every reported error
    /// exits 1, as Go's root does after reportError (not clap's 2).
    pub fn exit_code(&self) -> u8 {
        match self {
            CmdError::Exit(code) => *code,
            CmdError::Cli(_) | CmdError::Plain(_) => 1,
        }
    }
}

impl From<clierr::Error> for CmdError {
    fn from(e: clierr::Error) -> Self {
        CmdError::Cli(e)
    }
}

/// build, the command tree as the dispatch parses it.
pub fn build() -> Command {
    // The help command's words are a hidden positional for the parser; the
    // completion tree gives `help` the command tree instead.
    cobra_shape(tree()).mut_subcommand("help", |h| {
        h.arg(Arg::new("topic").num_args(0..).hide(true))
    })
}

// cobra_shape gives every node cobra's parsing surface for help: a `-h/--help`
// bool the dispatch reads (clap's own help flag would print clap's page and
// stop parsing at once; cobra parses every flag first, so `--help --bogus` is
// an unknown flag), and on every family node a hidden positional, because
// cobra lets a family take stray words (`wapps secrets nosuchverb` prints the
// family's help; on the root it is "unknown command"). `tofu` keeps clap's
// help flag disabled and reads `-h`/`--help` itself, as Go's
// DisableFlagParsing command does.
fn cobra_shape(mut cmd: Command) -> Command {
    if !cmd.is_disable_help_flag_set() {
        cmd = cmd.disable_help_flag(true).arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::SetTrue),
        );
    }
    if cmd.has_subcommands() {
        cmd = cmd.arg(Arg::new("args").num_args(0..).hide(true));
    }
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(name, cobra_shape);
    }
    cmd
}

/// completion_tree, the command tree as the completion scripts describe it:
/// cobra's completion surface, not its parsing surface. Every node gets the
/// help flag, and every node below the root the root's persistent flags
/// (cobra adds them to each command's flag set unless a local flag already
/// has the name, which is how a local `--project` shadows the root's). No
/// node gets `cobra_shape`'s hidden stray-word positional: it exists for the
/// parser, and in a zsh script a variadic positional on a family swallows the
/// subcommand name, so Tab would never descend (measured).
pub fn completion_tree() -> Command {
    let root = tree();
    let persistent: Vec<Arg> = root
        .get_arguments()
        .filter(|a| ["verbose", "config", "project"].contains(&a.get_id().as_str()))
        .cloned()
        .collect();
    // cobra's help command completes a command path (`help secrets <Tab>`
    // offers `secrets`'s commands): a mirror of the tree, names only, each
    // node with the help command's flags as cobra offers them past `help`.
    // Except `help help`: in clap_complete's zsh script a node with options
    // under a parent of the same name adds them on the parent's empty word
    // (measured: `wapps help <Tab>` offered `-c -h -p -v`), so it stays bare.
    let topics: Vec<Command> = root
        .get_subcommands()
        .map(|c| match c.get_name() {
            "help" => help_topic(c),
            _ => completion_shape(help_topic(c), &persistent),
        })
        .collect();
    let mut root = with_help_flag(root);
    let names: Vec<String> = root
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in names {
        root = root.mut_subcommand(name, |c| completion_shape(c, &persistent));
    }
    root.mut_subcommand("help", |h| h.subcommands(topics))
}

fn completion_shape(cmd: Command, persistent: &[Arg]) -> Command {
    let mut cmd = with_help_flag(cmd);
    for flag in persistent {
        let long = flag.get_long();
        if cmd.get_arguments().any(|a| a.get_long() == long) {
            continue;
        }
        // A distinct id: a positional may already use the flag's (`projects
        // rm`'s `project`), and cobra matches flags by name, not by id.
        let id = format!("persistent-{}", flag.get_id());
        cmd = cmd.arg(flag.clone().id(id));
    }
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(name, |c| completion_shape(c, persistent));
    }
    cmd
}

fn help_topic(cmd: &Command) -> Command {
    let topic =
        Command::new(cmd.get_name().to_string()).subcommands(cmd.get_subcommands().map(help_topic));
    match cmd.get_about() {
        Some(about) => topic.about(about.clone()),
        None => topic,
    }
}

fn with_help_flag(cmd: Command) -> Command {
    if cmd.is_disable_help_flag_set() {
        return cmd;
    }
    let usage = format!("help for {}", cmd.get_name());
    cmd.disable_help_flag(true).arg(
        Arg::new("help")
            .short('h')
            .long("help")
            .action(ArgAction::SetTrue)
            .help(usage),
    )
}

const ROOT_LONG: &str = "wapps is the umbrella CLI for the wappsdev estate.

It wraps:
  - the secrets gate (server-side decryption; values never touch git)
  - Tofu (wapps tofu — project secrets injected as TF_VAR_*)
  - Coolify v4 REST API (gap shim for the SierraJC Tofu provider)
  - deploys through the company deploy-proxy
  - doctor (end-to-end dependency + access check)";

// tree, the command tree with cobra's texts (Short, Long, Use, flag usages)
// byte for byte; cobrahelp renders it.
fn tree() -> Command {
    Command::new("wapps")
        .about("wapps umbrella CLI — secrets, Tofu, Coolify and deploys for the wappsdev estate")
        .long_about(ROOT_LONG)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .disable_help_subcommand(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::SetTrue),
        )
        // cobra's help command, mounted on the root only.
        .subcommand(
            Command::new("help")
                .about("Help about any command")
                .long_about(
                    "Help provides help for any command in the application.\nSimply type wapps help [path to command] for full details.",
                )
                .override_usage("help [command]"),
        )
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
                .help("Registered project name (see ~/.config/wapps/projects.yaml); resolves to that project's .wapps.yaml"),
        )
        .subcommand(
            Command::new("secrets")
                .about("Read and write this project's secrets in the gate")
                .subcommand(
                    Command::new("set")
                        .about("Write a secret value into the store (interactive, no echo)")
.override_usage("set <KEY>")
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
.long_about(LONG_SECRETS_EXEC)
.override_usage("exec -- <command> [args...]")
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
                                .help("freshness intent: dev (tolerate cache) | deploy (fresh-or-fail) (default \"dev\")"),
                        ),
                )
                .subcommand(
                    Command::new("apply")
                        .about("Write every declared consumption target from the store")
.long_about(LONG_SECRETS_APPLY),
                )
                .subcommand(
                    Command::new("get")
                        .about("Print a single secret value (TTY only; refused in agent mode)")
.override_usage("get <key>")
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
.long_about(LONG_SECRETS_STATUS)
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
.long_about(LONG_SECRETS_RM)
.override_usage("rm <KEY>")
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
                                .about("GET /v1/policy — active version + rules (admin verb, write-AUD session)")
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
                                .about("Lint + diff + CAS PUT /v1/policy (version = current+1)")
.long_about(LONG_SECRETS_POLICY_SET)
.override_usage("set <file>")
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
.override_usage("lint <file>")
                                .arg(Arg::new("file").num_args(0..).help("Policy file path")),
                        ),
                )
                .subcommand(
                    Command::new("rotate-plan")
                        .about("What must be rotated after an offboard, derived from the audit ledger")
.long_about(LONG_SECRETS_ROTATE_PLAN)
.override_usage("rotate-plan --identity <principal>")
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
                    Command::new("sync")
                        .about("Push declared sources into the store (or to a target with --target)")
                        // COPIED BYTE FOR BYTE from cmd/secrets/sync.go, and
                        // WRONG: the code writes the store in one epoch, there
                        // is no "encrypted archive to dest". The behavior
                        // follows the code; the text follows the text, so
                        // `--help` does not diverge once it is measured.
                        .long_about(SYNC_LONG)
                        // pflag lets every flag repeat, the last value
                        // winning; clap refuses a repeated single-value flag
                        // unless it overrides itself. Measured:
                        // agent_sync_coolify_repeated_app_last_wins.
                        .args_override_self(true)
                        // Value flags take the next token even when it starts
                        // with `-` (pflag), as on `token exchange`.
                        .arg(
                            Arg::new("all-apps")
                                .long("all-apps")
                                .action(ArgAction::SetTrue)
                                .help("push to every app in .wapps.yaml's coolify_sync.apps (prefix-stripped, non-destructive)"),
                        )
                        .arg(
                            Arg::new("app")
                                .long("app")
                                .value_name("string")
                                .allow_hyphen_values(true)
                                .help("Coolify app UUID for single-app push (mutually exclusive with --all-apps)"),
                        )
                        .arg(
                            Arg::new("coolify-url")
                                .long("coolify-url")
                                .value_name("string")
                                .allow_hyphen_values(true)
                                .default_value("https://coolify.meapps.dev/api/v1")
                                .help("Coolify API base URL (default \"https://coolify.meapps.dev/api/v1\")"),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(ArgAction::SetTrue)
                                .help("show which keys would be added or changed (names only) without writing"),
                        )
                        .arg(
                            Arg::new("force")
                                .long("force")
                                .action(ArgAction::SetTrue)
                                .help("with --target=coolify: apply the diff (default is dry-run only)"),
                        )
                        .arg(
                            Arg::new("prefix")
                                .long("prefix")
                                .value_name("string")
                                .allow_hyphen_values(true)
                                .help("with --target=coolify: prefix prepended to each pushed env var name (default empty)"),
                        )
                        .arg(
                            Arg::new("target")
                                .long("target")
                                .value_name("string")
                                .allow_hyphen_values(true)
                                .help("sync target: empty rebuilds archive from sources; 'coolify' pushes archive to a Coolify app's env"),
                        )
                        // syncCmd has no Args in cobra -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("import-env")
                        .about("Bulk import KEY=VALUE pairs from an env file into the store")
.override_usage("import-env <file>")
                        // Arite ELLE (cobra ExactArgs(1)).
                        .arg(Arg::new("file").num_args(0..).help("Env file path")),
                )
                .subcommand(
                    Command::new("env")
                        .about("Emit the project's secrets as .envrc-style export lines")
.long_about(LONG_SECRETS_ENV)
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
.long_about(LONG_SECRETS_TRUST_REPO)
                        // cobra'da trustRepoCmd'in Args'i YOK -> ArbitraryArgs:
                        // fazladan arguman SESSIZCE yok sayiliyor. Olculdu.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("init")
                        .about("Scaffold .wapps.yaml for a fresh repo")
.long_about(LONG_SECRETS_INIT)
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
.long_about(LONG_DOCTOR)
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
.long_about(LONG_ROTATE_SKIP)
.override_usage("skip <run-id> <project>/<key> --reason <why>")
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
.long_about(LONG_TOFU)
.override_usage("tofu [args...]")
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
.long_about(LONG_DR)
                .subcommand(
                    Command::new("verify")
                        .about("Structural integrity check of the B2 replica snapshot (read-only)")
.long_about(LONG_DR_VERIFY)
.override_usage("verify --snapshot <dir>")
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
.long_about(LONG_DR_RESTORE)
.override_usage("restore --project <p> --snapshot <dir> --share <file> --share <file> --out <env-file>")
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
                                .value_name("stringArray")
                                .action(ArgAction::Append)
                                .help("MASTER_KEK Shamir share file, hex (repeat ≥2; assembled key NEVER persisted)"),
                        )
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("split")
                        .about("TTY-only: split the store's MASTER_KEK into N-of-M Shamir shares for offline custody")
.long_about(LONG_DR_SPLIT)
                        .arg(
                            Arg::new("parts")
                                .long("parts")
                                .value_name("int")
                                .help("total Shamir shares to create (default 3)"),
                        )
                        .arg(
                            Arg::new("threshold")
                                .long("threshold")
                                .value_name("int")
                                .help("shares required to reconstruct (default 2)"),
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
.long_about(LONG_DR_COMBINE)
                        // StringArrayVar: `--share` TEKRARLANABILIR ve sira
                        // KORUNUR. clap'te bunun karsiligi Append.
                        .arg(
                            Arg::new("share")
                                .long("share")
                                .value_name("stringArray")
                                .action(ArgAction::Append)
                                .help("hex Shamir share file (repeat ≥ threshold)"),
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
.long_about(LONG_DR_BOOTSTRAP)
.override_usage("bootstrap [--var NAME]... -- <command> [args...]")
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .arg(Arg::new("argv").num_args(0..).help("Command and arguments"))
                        // StringArrayVar -> Append: `--var` TEKRARLANABILIR.
                        .arg(
                            Arg::new("var")
                                .long("var")
                                .value_name("stringArray")
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
.long_about(LONG_DR_ACCEPT_EPOCH_RESET)
.override_usage("accept-epoch-reset --project <p>")
                        .arg(
                            Arg::new("project")
                                .long("project")
                                .value_name("string")
                                .help("project whose epoch pin will be reset"),
                        ),
                ),
        )
        // `whoami` KOKTE mount'lu ve KAPISIZ: ne ajan guard'i, ne baglama
        // kapisi, ne `Ctx::resolve`. Go'da `whoamiCmd`in RunE'si dogrudan
        // `store.Whoami`ye gidiyor — `doctor`/`secrets status` ile ayni sinif
        // ve ayni gerekce: DEGER BASMIYOR, yalnizca principal/grup/grant
        // ADLARI. Kok bayraklari (`-c`/`-p`) kabul edilir ve ATILDIR.
        .subcommand(
            Command::new("whoami")
                .about("Show the gate's view of you: groups + effective grants")
                // cobra'da whoamiCmd'in Args'i YOK -> ArbitraryArgs.
                .arg(Arg::new("ignored").num_args(0..).hide(true)),
        )
        // `login` is root-mounted like `whoami`, with no `Ctx::resolve`: the
        // root `-c`/`-p` are accepted and inert. The verb's own gate (TTY
        // only for the plain form) lives in run_login.
        .subcommand(
            Command::new("login")
                .about("Log in to the secrets gate via CF Access SSO (TTY only)")
.long_about(LONG_LOGIN)
                .arg(
                    Arg::new("check")
                        .long("check")
                        .action(ArgAction::SetTrue)
                        .help("print session subject + remaining TTL (no token bytes)"),
                )
                .arg(
                    Arg::new("write")
                        .long("write")
                        .action(ArgAction::SetTrue)
                        .help("log in to the WRITE (admin) Access app — required by control-plane verbs"),
                )
                // cobra: loginCmd has no Args -> ArbitraryArgs.
                .arg(Arg::new("ignored").num_args(0..).hide(true)),
        )
        // `token` bir AILE komutu (kendi Run'i YOK): alt komutsuz cagrilinca
        // cobra yardimi basip 0 ile cikiyor, ve dispatch tarafi da oyle.
        .subcommand(
            Command::new("token")
                .about("Machine-token operations (CI)")
                // `--project` BURADA YEREL, ve `dr restore`/`dr
                // accept-epoch-reset` ile AYNI sekil: cobra'da
                // `tokenExchangeCmd.Flags().StringVar` kokun persistent
                // `-p`sini GOLGELIYOR (olculdu — bu alt komutun yardiminda
                // "Global Flags" altinda `-p` YOK, yalnizca `-c` ve `-v`).
                // Deger `Ctx::resolve`e HIC girmiyor; mint kapsaminin proje
                // alanina dogrudan gidiyor.
                //
                // Kisa bicim (`-p`) BILEREK YOK: Go'daki `StringVar` da
                // kisasiz — ve golgenin bu yuzu GOZLEMLENEBILIR, cunku
                // shorthand'i kaldirmak `-p`yi topyekun REDDEDILIR yapiyor
                // (bkz. main.rs, `short_project_token`).
                .subcommand(
                    Command::new("exchange")
                        .about("Exchange a CF Access service token for a scoped token (≤10 min)")
.long_about(LONG_TOKEN_EXCHANGE)
.override_usage("exchange --project <p> --key K [--key K2] [--verb read]")
                        // `allow_hyphen_values`: pflag'de BOSLUKLA ayrilmis bir
                        // uzun bayrak SONRAKI jetonu KOSULSUZ deger sayiyor —
                        // `-` ile baslasa bile. Olculdu: `--ttl -5`,
                        // `--key -K`, `--project -p1` Go'da CALISIYOR, clap'in
                        // varsayilaninda ise "unknown flag" oluyordu. Dordu de
                        // ayni sebeple isaretli ve her biri korpusta.
                        //
                        // AYNI FARK bu deponun DIGER deger alan bayraklarinda
                        // da duruyor (`dr restore --snapshot -x` bugun
                        // ayrisiyor) ve orasi OLCULMEMIS bir eksen; bu dilim
                        // KENDI yapraginin dort bayragini kapatiyor, otekileri
                        // adlandirip birakiyor.
                        .arg(
                            Arg::new("project")
                                .long("project")
                                .value_name("string")
                                .allow_hyphen_values(true)
                                .help("project scope for the minted token"),
                        )
                        // StringArrayVar -> Append: `--key` TEKRARLANABILIR
                        // ve SIRA korunur (mint kapsami sirali gidiyor).
                        .arg(
                            Arg::new("key")
                                .long("key")
                                .value_name("stringArray")
                                .action(ArgAction::Append)
                                .allow_hyphen_values(true)
                                .help("exact key name in scope (repeatable)"),
                        )
                        // `--verb`in VARSAYILANI ["read"] ve ILK `--verb`
                        // varsayilani EZER (pflag stringArray: ilk Set
                        // replace, sonrakiler append). clap'te `default_value`
                        // AYNI davraniyor — olculdu, tel'e binen govde iki
                        // ikilide de ayni.
                        .arg(
                            Arg::new("verb")
                                .long("verb")
                                .value_name("stringArray")
                                .action(ArgAction::Append)
                                .default_value("read")
                                .allow_hyphen_values(true)
                                .help("verb in scope (read|write|rotate) (default [read])"),
                        )
                        // `--ttl` cobra'da bir `IntVar`, yani deger
                        // AYRISTIRICIDA cozuluyor ve bozuk bir deger RunE'ye
                        // HIC girmiyor. Burada bir dize olarak aliniyor ve
                        // `gostrconv` ile cozuluyor: clap'in kendi tamsayi
                        // ayristiricisi hem KABUL KUMESINI (taban 0) hem RET
                        // METNINI ayristirirdi.
                        .arg(
                            Arg::new("ttl")
                                .long("ttl")
                                .value_name("int")
                                .allow_hyphen_values(true)
                                .help("token TTL seconds (≤600; 0 = gate default)"),
                        )
                        // cobra'da tokenExchangeCmd'in Args'i YOK -> ArbitraryArgs:
                        // fazladan arguman SESSIZCE yok sayiliyor. Olculdu
                        // (`token exchange --project p --key K EXTRA` -> cikis 0);
                        // clap'e birakilsa "unknown flag: EXTRA" ile 1 donerdi.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                ),
        )
        // `coolify` is a FAMILY (no Run of its own): bare, it prints help and
        // exits 0, like `token`. The parsing of the leaves' flag VALUES is
        // pflag's and lives in coolifyverb::parse_flags, so every value flag is
        // taken as a raw string here: Append (pflag lets a flag repeat; for a
        // StringVar the last wins) and allow_hyphen_values (pflag takes the
        // next token of a spaced long flag unconditionally). Defaults are
        // applied there too, so a flag that was never given stays absent
        // (cobra's required-flag check needs to know).
        .subcommand(
            Command::new("coolify")
                .about("Coolify v4 API shim commands (fill gaps in SierraJC Tofu provider)")
                .subcommand(
                    Command::new("deploy-app")
                        .about("Create a dockercompose application via Coolify API (and start it)")
                        .arg(pflag_value("compose-file", "string", "Path to docker-compose.yml"))
                        .arg(pflag_value("env-from-shell", "strings", "Env var names to pass through (repeatable)"))
                        .arg(pflag_value("name", "string", "Application name"))
                        .arg(pflag_value("project-uuid", "string", "Coolify project UUID"))
                        .arg(pflag_value("server-uuid", "string", "Target server UUID"))
                        // deployAppCmd has no Args -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("deploy-app-git")
                        .about("Create Coolify Application from a private GitHub repo (Coolify builds on the target server)")
                        .arg(pflag_value("base-dir", "string", "Build context base directory (default \"/\")"))
                        .arg(pflag_value("build-arg", "strings", "Docker build arg KEY=VALUE (repeatable). Stored as is_build_time env var."))
                        .arg(pflag_value("build-pack", "string", "Build pack: dockerfile, nixpacks, static (default \"dockerfile\")"))
                        .arg(pflag_value("dockerfile", "string", "Dockerfile path relative to base-dir (default \"Dockerfile\")"))
                        .arg(pflag_value("git-branch", "string", "Git branch (default \"main\")"))
                        .arg(pflag_value("git-repo", "string", "GitHub org/repo (e.g. wappsdev/vaulter-api)"))
                        .arg(pflag_value("github-app-uuid", "string", "Coolify GitHub App source UUID"))
                        .arg(pflag_bool("instant-deploy", "Trigger initial build immediately on create (default true)"))
                        .arg(pflag_value("name", "string", "Application name"))
                        .arg(pflag_value("ports", "string", "Exposed ports (comma-separated)"))
                        .arg(pflag_value("project-uuid", "string", "Coolify project UUID"))
                        .arg(pflag_value("server-uuid", "string", "Target server UUID"))
                        .arg(pflag_value("watch-path", "strings", "Path patterns to trigger rebuild (repeatable, e.g. cmd/gateway/**)"))
                        // deployAppGitCmd has no Args -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("import-app")
                        .about("List Coolify apps on a server → emit Tofu import commands + HCL stubs")
                        .arg(pflag_value("output-dir", "string", "Where to write imports.sh + apps.tf (default \"./.outputs/import\")"))
                        .arg(pflag_value("server-uuid", "string", "Filter by server UUID (empty = all)"))
                        // importAppCmd has no Args -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("set-labels")
                        .about("PATCH custom_labels (base64) with optional certresolver=letsencrypt strip")
                        .arg(pflag_value("app-uuid", "string", "Coolify app UUID"))
                        .arg(pflag_value("label", "strings", "Label (repeatable, e.g. --label 'traefik.enable=true')"))
                        .arg(pflag_bool(
                            "strip-cert-resolver",
                            "Strip certresolver=letsencrypt labels (file-based Origin Cert pattern) (default true)",
                        ))
                        // setLabelsCmd has no Args -> ArbitraryArgs.
                        .arg(Arg::new("ignored").num_args(0..).hide(true)),
                )
                .subcommand(
                    Command::new("update-env")
                        .about("Update application env vars (--env KEY=VAL, repeatable)")
                        .arg(pflag_value("app-uuid", "string", "Coolify app UUID"))
                        .arg(pflag_value("env", "strings", "KEY=VAL (repeatable)"))
                        // updateEnvCmd has no Args -> ArbitraryArgs.
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
.long_about(LONG_PROJECTS_RM)
.override_usage("rm <PROJECT>")
                        .arg(Arg::new("project").num_args(0..).help("Project name"))
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("skip the interactive confirm (still refused in agent mode)"),
                        ),
                ),
        )
        .subcommand(skill_command())
        .subcommand(deploy_command())
        .subcommand(completion_command())
        .subcommand(
            Command::new("broker")
                .about("Local broker bridge")
                .subcommand(Command::new("serve").about("Serve the broker over stdio MCP"))
                .subcommand(Command::new("daemon").about("Run the local broker daemon")
                    .arg(Arg::new("stop").long("stop").action(ArgAction::SetTrue).help("Gracefully stop the local daemon"))
                    .arg(Arg::new("detached").long("detached").hide(true).conflicts_with("stop").action(ArgAction::SetTrue))),
        )
}

// skill_command, `wapps skill`: Go's Short/Long texts byte for byte (pinned
// by tests/skill.rs against cmd/skill/skill.go). All three leaves are
// cobra.NoArgs, so each takes a hidden positional and the dispatch names an
// extra argument as cobra does ("unknown command ...").
fn skill_command() -> Command {
    let local = |help: &'static str| {
        Arg::new("local")
            .long("local")
            .action(ArgAction::SetTrue)
            .help(help)
    };
    let dir = Arg::new("dir")
        .long("dir")
        .value_name("string")
        .allow_hyphen_values(true)
        .help("Project directory for --local (default: current directory)");
    let extra = Arg::new("extra").num_args(0..).hide(true);
    Command::new("skill")
        .about("Manage the wapps-secrets Claude Code skill (AI-safe secret handling)")
        .long_about(SKILL_LONG)
        .subcommand(
            Command::new("install")
                .about("Install the wapps-secrets skill (default: user-wide ~/.claude/skills)")
                .long_about(SKILL_INSTALL_LONG)
                .arg(local(
                    "Install into the current repo's .claude/skills (project-based) instead of user-wide",
                ))
                .arg(dir.clone())
                .arg(
                    Arg::new("copy")
                        .long("copy")
                        .action(ArgAction::SetTrue)
                        .help("Write real files instead of symlinks (committable; recommended with --local)"),
                )
                .arg(extra.clone()),
        )
        .subcommand(
            Command::new("status")
                .about("Show whether the wapps-secrets skill is installed and current")
                .arg(extra.clone()),
        )
        .subcommand(
            Command::new("uninstall")
                .about("Remove the wapps-secrets skill")
                .arg(local("Uninstall from the current repo instead of user-wide"))
                .arg(dir)
                .arg(extra),
        )
}

// completion_command, cobra's default `completion` command (cobra v1.10.2
// completions.go, InitDefaultCompletionCmd): its Short/Long texts and those of
// its four shells, byte for byte, with the root's name filled in. The family
// has no Run; each shell is NoArgs (the hidden `extra` positional, so main can
// give cobra's sentence) and has `--no-descriptions`.
fn completion_command() -> Command {
    let shell = |name: &'static str, long: &'static str| {
        Command::new(name)
            .about(format!("Generate the autocompletion script for {name}"))
            .long_about(long)
            .arg(pflag_bool(
                "no-descriptions",
                "disable completion descriptions",
            ))
            .arg(Arg::new("extra").num_args(0..).hide(true))
    };
    Command::new("completion")
        .about("Generate the autocompletion script for the specified shell")
        .long_about(COMPLETION_LONG)
        .subcommand(shell("bash", COMPLETION_BASH_LONG))
        .subcommand(shell("zsh", COMPLETION_ZSH_LONG))
        .subcommand(shell("fish", COMPLETION_FISH_LONG))
        .subcommand(shell("powershell", COMPLETION_POWERSHELL_LONG))
}

const COMPLETION_LONG: &str =
    "Generate the autocompletion script for wapps for the specified shell.
See each sub-command's help for details on how to use the generated script.
";

const COMPLETION_BASH_LONG: &str = "Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

\tsource <(wapps completion bash)

To load completions for every new session, execute once:

#### Linux:

\twapps completion bash > /etc/bash_completion.d/wapps

#### macOS:

\twapps completion bash > $(brew --prefix)/etc/bash_completion.d/wapps

You will need to start a new shell for this setup to take effect.
";

const COMPLETION_ZSH_LONG: &str = "Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

\techo \"autoload -U compinit; compinit\" >> ~/.zshrc

To load completions in your current shell session:

\tsource <(wapps completion zsh)

To load completions for every new session, execute once:

#### Linux:

\twapps completion zsh > \"${fpath[1]}/_wapps\"

#### macOS:

\twapps completion zsh > $(brew --prefix)/share/zsh/site-functions/_wapps

You will need to start a new shell for this setup to take effect.
";

const COMPLETION_FISH_LONG: &str = "Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

\twapps completion fish | source

To load completions for every new session, execute once:

\twapps completion fish > ~/.config/fish/completions/wapps.fish

You will need to start a new shell for this setup to take effect.
";

const COMPLETION_POWERSHELL_LONG: &str = "Generate the autocompletion script for powershell.

To load completions in your current shell session:

\twapps completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.
";

// deploy_command, `wapps deploy <service>`: Go's Short/Long texts byte for
// byte (pinned by tests/deployverb.rs against cmd/deploy/deploy.go). The
// service is a 0..n positional so main can give cobra's ExactArgs(1) sentence;
// the int and bool flags are parsed by deployverb::parse_flags with pflag's
// rules and error texts.
fn deploy_command() -> Command {
    Command::new("deploy")
        .about("Deploy a service through the company-deploy-proxy")
        .override_usage("deploy <service>")
        .long_about(DEPLOY_LONG)
        .arg(Arg::new("service").num_args(0..).hide(true))
        .arg(pflag_value(
            "ep",
            "string",
            "Deploy-proxy base URL (default DEPLOY_PROXY_EP or https://deploy-proxy.meapps.dev)",
        ))
        .arg(pflag_bool(
            "json",
            "Emit one machine-readable JSON line instead of human status (still AI-safe)",
        ))
        .arg(pflag_value(
            "poll-interval",
            "int",
            "Seconds between status polls under --wait (default 15)",
        ))
        .arg(pflag_value(
            "repo",
            "string",
            "Logical repo whose scoped token + app subset to use (default \"vaulter\")",
        ))
        .arg(pflag_value(
            "timeout",
            "int",
            "Seconds to wait with --wait before timing out (must stay < 90m) (default 1200)",
        ))
        .arg(pflag_bool(
            "wait",
            "Poll until the deployment finishes (or fails/times out)",
        ))
}

const DEPLOY_LONG: &str = "Trigger a redeploy of a service via the company-deploy-proxy — the only
supported path for the root-level vaulter trio (proxy/db-admin/migrator) and
gateway, whose scoped Coolify tokens intentionally cannot deploy via the direct
Coolify API.

Credentials (proxy token + Cloudflare Access service-token) resolve env-first,
then the config-resolved server-decrypt store (backend: store .wapps.yaml;
values never printed):

  DEPLOY_PROXY_TOKEN_<REPO>             (or DEPLOY_PROXY_TOKEN / PROXY_TOKEN)
  DEPLOY_PROXY_CF_ACCESS_CLIENT_ID      (or CF_ACCESS_CLIENT_ID)
  DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET  (or CF_ACCESS_CLIENT_SECRET)
  DEPLOY_PROXY_EP                       (default https://deploy-proxy.meapps.dev)

Examples:
  wapps deploy migrator --repo vaulter --wait
  wapps deploy gateway  --repo vaulter --wait
  wapps deploy auth     --json

Exit codes: 0 ok · 1 usage · 2 creds · 3 auth/scope · 4 CF Access · 5 network ·
6 proxy/upstream · 7 timeout · 8 deploy failed.";

const SKILL_LONG: &str = "Install the \"wapps-secrets\" skill that teaches AI coding agents
(Claude Code, Cursor, Aider) to handle this repo's secrets with apply-only
commands — never reading or printing raw values.

The skill files ship inside the wapps binary, so a Homebrew install needs no
repo checkout: `wapps skill install` materializes them and symlinks
them into place. Re-run it after `brew upgrade wapps` to refresh.";

const SKILL_INSTALL_LONG: &str = "Install the wapps-secrets skill.

  wapps skill install                  user-wide (~/.claude/skills) — recommended
  wapps skill install --local --copy   into ./.claude/skills as committable files
  wapps skill install --local --dir X  into X/.claude/skills

User-wide is the default: the skill is available in every repo, but its own
description only activates it where a .wapps.yaml exists.";

// pflag_bool, a pflag BoolVar: `--x`, `--x=<bool>`, never a spaced value
// (`--x false` leaves `false` as an argument). The value is parsed by
// ParseBool in coolifyverb::parse_flags / deployverb::parse_flags.
fn pflag_bool(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .num_args(0..=1)
        .require_equals(true)
        .default_missing_value("true")
        .action(ArgAction::Append)
        .help(help)
}

// pflag_value, a value flag as pflag reads it (see `coolify`; `deploy` too);
// `value_name` is pflag's type word ("string" / "strings").
fn pflag_value(name: &'static str, value_name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .value_name(value_name)
        .action(ArgAction::Append)
        .allow_hyphen_values(true)
        .help(help)
}

// --- GOLGENIN KISA-BICIM YUZU --------------------------------------------------
//
// Golge yalnizca UZUN adi degil, KISA bicimi de kaldiriyor, ve bu OLCULDU:
//
//   wapps -p x dr accept-epoch-reset   GO "unknown shorthand flag: 'p' in -p"
//   wapps -p x dr restore …            GO ayni
//   wapps -p x token exchange …        GO ayni
//   wapps -p x dr verify …             GO CALISIR (yerel `--project`i YOK)
//
// Sebep: cobra yapragin `Flags()`ini kurarken YEREL bayragi once koyuyor ve
// ayni ADLI kalitilan bayragi ATLIYOR. Yerel `--project`in shorthand'i
// olmadigi icin `p` harfi flagset'e HIC girmiyor. clap'te ise kokun `-p`si
// alt komuttan bagimsiz kayitli, yani duzeltilmeden once Rust `-p`yi sessizce
// KABUL EDIYORDU (ve ust dilimin `dr` yapraklarinda da oyleydi — bu, o
// tuzagin OLCULMEMIS dorduncu yuzuydu).

/// short_project_token, KOK BAYRAK BOLGESINDE yazilmis bir `-p...` jetonunu
/// doner (metin Go'nun hatasina AYNEN giriyor: "in -p", "in -ptestproj").
///
/// KAPSAM DAR VE BILINCLI: yalnizca `-p` ile BASLAYAN tek bir kisa jeton
/// taniniyor. `-vp` gibi KUMELER kapsam DISI ve bu bir eksiklik degil bir
/// sinir: kume semantigi (pflag bitisik degeri kumenin kalanindan aliyor) bu
/// depoda HIC olculmemis bir eksen ve iki ikili orada `secrets list` gibi
/// GOLGESIZ yapraklarda da ayrisiyor. Olculmemis bir ekseni taklit etmek,
/// olculmus olani tasimaktan farkli bir istir.
///
/// PUR, ve `main.rs`te DEGIL burada: cagrisi tek ama karari testten
/// gorulebilmeli. Bir ikilinin icinde duran karar test edilemez.
pub fn short_project_token(args: &[String]) -> Option<String> {
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        // `--` ve ilk BAYRAK OLMAYAN jeton kok bolgesini bitirir (alt komut).
        if a == "--" || !a.starts_with('-') || a == "-" {
            return None;
        }
        if let Some(long) = a.strip_prefix("--") {
            // `--config x` / `--project x` bir sonraki jetonu YUTAR;
            // `--config=x` yutmaz.
            i += if long == "config" || long == "project" {
                2
            } else {
                1
            };
            continue;
        }
        if a.starts_with("-p") {
            return Some(a.clone());
        }
        if a == "-c" {
            i += 2;
            continue;
        }
        i += 1;
    }
    None
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
            e.to_string()
                .lines()
                .next()
                .unwrap_or("invalid command")
                .trim_start_matches("error: ")
                .to_string(),
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
        // The verb wrote its own output; there is nothing left to report.
        (_, CmdError::Exit(_)) => {}
    }
}

// SYNC_LONG, syncCmd's Long text from cmd/secrets/sync.go, byte for byte.
// It is stale (see the comment on the `sync` subcommand): kept verbatim on
// purpose until the Go text itself is corrected.
const SYNC_LONG: &str = "Without --target: read all sources declared in .wapps.yaml, merge
them, and write an encrypted archive to dest.

With --target=coolify: read the existing archive and push its contents to
a Coolify application's env vars. Default is dry-run — pass --force to
actually apply (which deletes Coolify-only keys to mirror the archive).

Single-app (--app): pushes the WHOLE archive to one app, mirroring
destructively (Coolify keys absent from the archive deleted on --force).

Multi-app (--all-apps): requires coolify_sync.apps in .wapps.yaml. Each app
gets only the archive keys matching its archive_prefix, prefix stripped.
Non-destructive unless coolify_sync.delete_unmanaged: true.

  wapps secrets sync                                        # rebuild archive
  wapps secrets sync --target=coolify --app <uuid>          # single-app dry-run
  wapps secrets sync --target=coolify --app <uuid> --force  # single-app apply
  wapps secrets sync --target=coolify --all-apps            # multi-app dry-run
  wapps secrets sync --target=coolify --all-apps --force    # multi-app apply";

// cobra Long texts, byte for byte from the Go commands (cmd/...).

const LONG_DOCTOR: &str = "Verify the local environment can run wapps commands.

Default mode runs the full battery of checks (CLI tools, R2 env, Coolify
API reachability, git remote). Use --for to scope:

  --for tofu     check ONLY the env required by 'wapps secrets sync' against
                 a Tofu project (AWS_*, TF_VAR_state_passphrase, tofu binary).
                 Useful before the first sync in a freshly-bootstrapped repo.";

const LONG_DR: &str = "Disaster recovery against the NON-Cloudflare, append-only B2 replica.
The replica holds ONLY ciphertext + metadata — MASTER_KEK never reaches B2, so the
replica alone yields nothing. dr verify is a structural integrity check; dr restore
is the true-disaster TTY ceremony (Shamir shares + snapshot → plaintext env files).";

const LONG_DR_ACCEPT_EPOCH_RESET: &str =
    "accept-epoch-reset is the ONLY legitimate way to lower a project's local epoch
pin (rollback tripwire, internal/store/epochpin.go). It exists for ONE scenario:
the store was LEGITIMATELY rebuilt (F5) and clients must re-accept it.

The ceremony:
  1. fetches the LIVE audit-chain head from the gate,
  2. asks you to TYPE the first 12 hex chars of the head hash FROM THE PAPER
     ENVELOPE (typing the paper value IS the out-of-band verification),
  3. on mismatch it HARD-ABORTS — store substitution is assumed; open an incident,
  4. on match it performs ONE pin-lowering read tagged X-Wapps-Intent: epoch-reset.

REFUSED in agent mode. The accept flag is never available on exec/apply/get.";

const LONG_DR_BOOTSTRAP: &str =
    "Bootstrap/DR runbook verb for when the store itself is unreachable (e.g. a
bricked Worker — flow F3). REFUSED in agent mode: bootstrap tokens must never
cross an AI transcript.

For every bootstrap env var (backend contract + provisioning tokens + --var):
  - already set in your environment  -> inherited, NOT prompted
  - constant (AWS_REGION=auto)       -> injected as-is, NEVER prompted
  - otherwise                        -> no-echo TTY prompt (Enter = skip)

The command then runs with the values injected as process env, through the
same output scrubber as 'wapps secrets exec' — an apply that echoes a token
prints ***. Nothing is ever written to disk, the store, or shell history.

  wapps dr bootstrap -- tofu apply
  wapps dr bootstrap --var TF_VAR_extra_token -- tofu apply -target=module.gate

On success it prints the differentiated burn checklist: burn ceremony/
temp tokens NOW, burn a rotated-out token only AFTER its successor is in the
store, and do NOT burn standing tokens self-hosted in the store.";

const LONG_DR_COMBINE: &str =
    "combine reads >=threshold hex share files and reconstructs the MASTER_KEK (64-hex),
writing it 0600 to --out (NEVER stdout). Use it to re-provision the store after a loss:

  wapps dr combine --share s1.hex --share s2.hex --out master.hex
  npx wrangler secret put MASTER_KEK < master.hex   # re-set the Worker secret
  rm master.hex

Refused in agent mode.";

const LONG_DR_RESTORE: &str = "TRUE-disaster restore. TTY-ONLY — REFUSED under agent mode.
Reconstructs MASTER_KEK from ANY 2-of-3 Shamir share files (hex), verifies the
snapshot chain, derives the project KEK, unwraps every DEK, opens every blob and
writes a 0600 env file. The assembled MASTER_KEK
and the plaintext values are NEVER printed and never persisted beyond --out.
Works with zero Cloudflare availability.";

const LONG_DR_SPLIT: &str =
    "split TAKES the store's MASTER_KEK (64-hex) and writes {--parts} Shamir share
files (hex, 0600) such that ANY {--threshold} reconstruct it (dr combine) and fewer
reveal NOTHING. Move each share to a SEPARATE offline place (paper safe / YubiKey /
trusted person).

MASTER_KEK source (NEVER printed, NEVER echoed):
  default        no-echo TTY prompt — paste the 64-hex value; input stays hidden
  --master-hex   supply the 64-hex value explicitly (argv is visible via ps/shell
                 history — prefer the prompt)

Refused in agent mode — the MASTER_KEK must never reach an AI transcript.";

const LONG_DR_VERIFY: &str =
    "Verify the ciphertext replica: for every project, current pointer → manifest
hash chain, manifest schema, and every referenced blob's content address. Uses NO
secrets and NO Cloudflare — runnable against an air-gapped snapshot copy.
(Live-B2 lag comparison alerts run in the Worker's nightly reconcile.)";

const LONG_LOGIN: &str = "login runs the CF Access SSO for the secrets gate via cloudflared
(edge token transfer — the CF Access CLI flow rejects a localhost callback), then
caches the returned app token 0600 at ~/.config/wapps/session/<gate-host>.json.
Every store call then presents it as the cf-access-token header.

Agent/CI contexts never run login: CI uses a CF Access service token via
CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET (no browser, no session file).

--write runs the SSO against the WRITE (admin) Access application instead. The
edge protects <gate>/v1/admin with a separate, short-lived app (15 min + WebAuthn)
that issues a different AUD; control-plane verbs (secrets policy, projects rm,
rotate-plan) need it and the read session cannot stand in. The two sessions are
cached separately, so logging in for admin does not evict the read session.

--check prints the current session subject + remaining TTL (never token bytes).";

const LONG_PROJECTS_RM: &str = "Remove a project and all of its data from the store.

This deletes every key, manifest and blob under the project. It needs the
global `admin` verb and a write-AUD session — a per-key `delete` grant is NOT
enough. The append-only pointer-event trail is KEPT: it is the tamper-evident
record that the project existed, and deleting it would forge a clean history.";

const LONG_ROTATE_SKIP: &str =
    "Mark a value-rotation worklist key as SKIPPED with a recorded admin attestation.

A key that carries no rotation metadata is flagged NEEDS_TRIAGE and BLOCKS run
completion — it is never swallowed. An admin resolves it here by writing a SKIP
row (canonical attestation, no secret values) recording WHY the key needs no
value rotation (e.g. the value is a public constant, or it rotates at its
origin). Once written, the run reaches terminal.

This is a control-plane admin op: authorization is enforced by the Worker admin
API (write-AUD session + admin verb). The engine transition (internal/rotation
RunLedger.SkipKey) is implemented and tested; the CLI↔live-ledger wiring lands
with the rotation executor.";

const LONG_SECRETS_APPLY: &str =
    "Fetch the project's secrets once and write every target declared in
.wapps.yaml's 'targets:' block atomically. Idempotent: if a target file on
disk already matches what would be written, the file is left alone (mtime
unchanged). Errors if no targets are declared — use
'wapps secrets env --write <file>' for one-off writes.

Safe to call from npm 'predev' / 'prebuild' scripts so '.env.local' always
matches the store.";

const LONG_SECRETS_ENV: &str = "Emit the project's secrets as 'export KEY=VALUE' lines.

By default writes to stdout (printable). Use --write <file> to write to a
file silently (AI-safe path — no secret value reaches stdout, terminal,
or LLM transcript).

Keys are emitted under the name they are stored with. --prefix prepends
something to every key; it is idempotent, so a key that already starts with
the prefix is emitted unchanged.";

const LONG_SECRETS_EXEC: &str =
    "Decrypt secrets and exec the given command with each secret exported
as an env var. wapps forwards the subprocess's stdout and stderr THROUGH A
STREAMING SCRUBBER that redacts any injected secret value to ***, then
exits with the subprocess's exit code.

AI-safe contract: wapps itself prints no secret values — only the
subprocess does, and even that output is scrubbed of injected values. Use this
from agent contexts that need credentialed commands without putting values in
the agent transcript.

  wapps secrets exec -- pnpm dev
  wapps secrets exec -- ./scripts/deploy.sh";

const LONG_SECRETS_INIT: &str = "Initialize wapps secrets in the current repo.

Creates a single file — .wapps.yaml — naming the project this repo reads from
in the secrets gate. Nothing encrypted is written to the repo: values live
server-side and are fetched on demand.

An existing .wapps.yaml is never overwritten unless --force is passed.

After init: 'wapps login', then 'wapps secrets trust-repo' to pin this repo to
the project, then 'wapps secrets set <KEY>'.";

const LONG_SECRETS_POLICY_SET: &str = "policy set validates <file> offline (schema + lint), fetches
the current policy for the version CAS, prints the rule diff old→new, asks for a
TTY confirm, then PUTs with version = current+1. A concurrent admin edit loses
the CAS (412 POLICY_CONFLICT) — refetch with policy show and retry.";

const LONG_SECRETS_RM: &str = "Remove a key from the store.

Deletion is irreversible and needs its own `delete` grant in policy.json —
a `write` grant is NOT enough. Use this when the thing a secret pointed at is
gone (deleted service account, retired provider) and the entry is now orphaned.";

const LONG_SECRETS_ROTATE_PLAN: &str =
    "rotate-plan queries the gate's hash-chained audit ledger (GET
/v1/admin/rotate-plan, admin verb + write-AUD session) for every (project, key)
the identity read, wrote, imported, synced or rotation-wrote — the precise
rotate set for offboarding.

  --identity        human:<email> | service:<common_name>
  --since           RFC3339 lower bound (optional)
  --assume-policy   ALSO union every key the identity's policy rules COULD read
                    (paranoid superset when audit coverage is doubted)

Execute the resulting worklist with wapps secrets rotate.";

const LONG_SECRETS_STATUS: &str =
    "Report {online, session_valid, session_expires_in, epoch_pin}. status is SAFE
in every mode and every network state — it never touches plaintext and never fails
hard; it is the first command an agent runs when anything else errors.";

const LONG_SECRETS_TRUST_REPO: &str =
    "A .wapps.yaml names a project, but a repo file is attacker-writable
content (confused-deputy seam). trust-repo pins the (repo → project) binding in
the TRUSTED home dir (~/.config/wapps/repo-pins.json), NOT in the repo. An agent
hitting an unpinned store-backed binding is refused (BINDING_UNPINNED); only a
human at a terminal can pin.";

const LONG_TOFU: &str = "Resolve the project from the current directory's .wapps.yaml, inject its
secrets as env vars (VERBATIM — the store holds TF_VAR_* / AWS_* names directly),
and run tofu with the given args. Secrets never touch disk; the child's stdout/
stderr pass through the same scrubber as 'secrets exec' (injected values -> ***).

  wapps tofu init
  wapps tofu plan -target=module.gate
  wapps tofu apply

Equivalent to (but cleaner than):
  wapps secrets exec -- tofu <args...>

Project resolution is cwd-based (run it from the project's .wapps.yaml dir, as you
would tofu). AI-safe: wapps prints no secret values — safe from agent/CI
contexts (a fresh CI container authenticates with a CF Access service-token pair).";

const LONG_TOKEN_EXCHANGE: &str = "token exchange swaps the pipeline's CF Access service-token pair
(CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET) for a short-TTL machine token
scoped to {project, keys[], verbs[]} ⊆ the service's policy rows, via
POST /v1/token. The minted token is printed to stdout for the pipeline step to
capture; subsequent calls present it via WAPPS_MACHINE_TOKEN. Optional layer —
service tokens may also use the data plane directly.";
