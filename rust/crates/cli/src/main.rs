// wapps ikilisinin giris noktasi. Adim 6 dilimi: `secrets get`.
use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;
use wapps::agentmode;
use wapps::applyverb;
use wapps::binding;
use wapps::cli::{self, CmdError};
use wapps::clierr::{Code, Error};
use wapps::configctx::{self, Ctx};
use wapps::confirm;
use wapps::coolifysync;
use wapps::coolifyverb;
use wapps::deployverb;
use wapps::doctorverb;
use wapps::drverb;
use wapps::envverb;
use wapps::envwrite;
use wapps::epochpin;
use wapps::execverb;
use wapps::gojson::quote as go_quote;
use wapps::gostrconv;
use wapps::gotime;
use wapps::importenv;
use wapps::initverb;
use wapps::loginverb;
use wapps::policy;
use wapps::policyverb;
use wapps::projectsverb;
use wapps::rmverb;
use wapps::rotateplan;
use wapps::session;
use wapps::setverb;
use wapps::skill;
use wapps::statusverb;
use wapps::store;
use wapps::storevalues;
use wapps::syncverb;
use wapps::trustrepo;

fn main() -> ExitCode {
    let agent = agentmode::is_agent();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let mut err_out = std::io::stderr();
            cli::report_error(&mut err_out, &e, agent);
            // 1 for every reported error (Go's root, not clap's 2); a verb
            // that owns its code (deploy, a mirrored child) carries it here.
            ExitCode::from(e.exit_code())
        }
    }
}

// --- YEREL `--project`, KOKUNKINI GOLGELER --------------------------------------
//
// `dr restore` ve `dr accept-epoch-reset` KENDI `--project` bayraklarini
// tasiyor, ve o bayrak bir KIMLIK bayragi DEGIL: `Ctx::resolve` cagrilmiyor,
// deger dogrudan fiilin argumani olarak okunuyor (snapshot icindeki proje adi
// / pini indirilecek proje). cobra'da bir yapragin yerel bayragi kokun ayni
// adli persistent bayragini GOLGELIYOR ve golge KOMUT SATIRINDAKI YERDEN
// BAGIMSIZ — butun bayraklar yapragin flagset'ine karsi ayristiriliyor.
//
// clap'te ise ikisi AYRI arguman ve hangisinin dolacagini KONUM belirliyor.
// Duzeltilmeden once bu IKI yerde ayrisiyordu ve ikisi de OLCULDU:
//
//   wapps --project p dr accept-epoch-reset
//        GO: calisir (deger yapraga ulasir) · RS: "--project is required"
//   wapps --config c --project p dr accept-epoch-reset
//        GO: calisir (kokun `--project`i HIC dolmadigi icin karsilikli
//            dislama ATESLEMEZ) · RS: "--config and --project are mutually
//            exclusive"
//
// DOGRU TARAF GO ve gerekce olculdu, hizalama degil: karsilikli dislama bir
// KIMLIK kurali; kimlik bayragi OLMAYAN bir bayraga carpmasi yanlis. Kural
// KALDIRILMIYOR — yerel `--project`i OLMAYAN yapraklarda (`dr verify` dahil)
// aynen suruyor, ve kontrol vakasi korpusta.

// LOCAL_PROJECT_LEAVES, KENDI `--project`ini tasiyan (aile, yaprak) ciftleri.
// Tek bir yerde duruyor ki `shadows_root_project` ile dispatch'teki geri
// dusum AYRISAMASIN: biri digerini unutursa golge yarim kalirdi.
//
// `token exchange` bu listeye `dr`in iki yapragiyla AYNI olcumle girdi:
// `wapps token exchange --help` "Global Flags" altinda `-p` GOSTERMIYOR,
// yalnizca `-c` ve `-v`.
const LOCAL_PROJECT_LEAVES: &[(&str, &str)] = &[
    ("dr", "restore"),
    ("dr", "accept-epoch-reset"),
    ("token", "exchange"),
];

// shadows_root_project, cagrilan yaprak kokun `--project`ini golgeliyor mu.
// Kisa bicimin karsiligi cli::short_project_token (orada, cunku PUR).
fn shadows_root_project(matches: &clap::ArgMatches) -> bool {
    matches!(matches.subcommand(), Some((fam, fm))
        if fm.subcommand_name()
            .is_some_and(|leaf| LOCAL_PROJECT_LEAVES.contains(&(fam, leaf))))
}

// shadowed_project, yapragin degerini, yoksa kokte KALMIS olani doner.
//
// SIRA "yerel once": clap'te yerel arguman ancak alt komuttan SONRA yazilmis
// bir `--project` ile dolar, yani ikisi birden verildiginde yerel olan DAIMA
// komut satirinda SONRAKIDIR. cobra tek bir degiskene yazdigi icin orada da
// sonuncu kazanir — yani bu `or` Go'nun "son yazan kazanir"inin AYNISI.
fn shadowed_project(leaf: &clap::ArgMatches, root: &Option<String>) -> Option<String> {
    leaf.get_one::<String>("project")
        .cloned()
        .or_else(|| root.clone())
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

    // GOLGENIN KISA-BICIM YUZU: yerel `--project` tasiyan bir yaprakta kokun
    // `-p`si HIC KAYITLI DEGIL (cobra yapragin flagset'ini kurarken ayni adli
    // kalitilan bayragi atliyor ve yerel olanin shorthand'i yok). Ret
    // AYRISTIRMA aninda, yani ajan kapisindan da fiil kontrollerinden de
    // ONCE — vakalar bu sirayi ayrica pinliyor.
    if shadows_root_project(&matches) {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        if let Some(tok) = cli::short_project_token(&argv) {
            // `Plain`: Go'da bu bir pflag hatasi, yani kod oneki YOK.
            return Err(CmdError::Plain(format!(
                "unknown shorthand flag: 'p' in {tok}"
            )));
        }
    }

    // `coolify` leaves: pflag parses flag VALUES (CSV slices, the bool) at
    // parse time, so a bad value is reported BEFORE the root's mutual
    // exclusion below. Measured: agent_coolify_update_env_flag_value_error_
    // before_identity_flags.
    let coolify_leaf = match matches.subcommand() {
        Some(("coolify", cm)) => match cm.subcommand() {
            Some((leaf, lm)) => coolifyverb::parse_flags(leaf, lm)
                .map(|r| r.map_err(CmdError::Plain))
                .transpose()?,
            None => None,
        },
        _ => None,
    };

    // `deploy`: pflag's value errors, then cobra's ExactArgs(1). Both run
    // before the root's PersistentPreRunE, so before the mutual exclusion
    // below; the corpus pins both orders.
    let deploy_opts = match matches.subcommand() {
        Some(("deploy", dm)) => {
            let mut opts = deployverb::parse_flags(dm).map_err(CmdError::Plain)?;
            let args: Vec<String> = dm
                .get_many::<String>("service")
                .map(|v| v.cloned().collect())
                .unwrap_or_default();
            let [service] = args.as_slice() else {
                return Err(CmdError::Plain(format!(
                    "accepts 1 arg(s), received {}",
                    args.len()
                )));
            };
            opts.service = service.clone();
            Some(opts)
        }
        _ => None,
    };

    // `--config` + `--project` BIRLIKTE: ret DISPATCH'TEN ONCE, ve FIILDEN
    // BAGIMSIZ. Buraya konmasinin sebebi olculdu: Go'da bu kontrol root'un
    // `PersistentPreRunE`unda (`resolveProjectFlag`), yani `Ctx::resolve`
    // cagirmayan fiiller icin de ates ediyor — `doctor`, `dr verify`,
    // `secrets policy show`, `rotate skip`, `projects rm`in HEPSI Go'da bu
    // hatayi veriyor. Kontrol `Ctx::resolve`in ICINDE kalsaydi o bes fiil
    // Rust'ta iki bayragi da SESSIZCE kabul ederdi.
    //
    // `tofu` ISTISNA ve bu da olculdu: Go'da `TofuCmd` root'a mount'lu ve
    // `DisableFlagParsing: true`, o yuzden root'un hook'u onun icin
    // CALISMIYOR — `wapps --config x --project p tofu plan` mutual-exclusion
    // DEGIL, "exec: no .wapps.yaml found" veriyor. Ayni istisna zaten
    // asagida da var (tofu dali iki bayragi da GORMEZDEN geliyor); bu satir
    // onunla ayni gercegi tasiyor.
    if config.is_some()
        && project.is_some()
        && matches.subcommand_name() != Some("tofu")
        && !shadows_root_project(&matches)
    {
        // `Plain` — `Cli` DEGIL. Go'da bu hata duz bir `fmt.Errorf`, yani
        // insan yolunda kod oneki ve kurtarma satiri YOK. `Plain` ajan
        // modunda zaten INTERNAL zarfina sariliyor, yani iki bicim de dogru.
        return Err(CmdError::Plain(configctx::MUTUALLY_EXCLUSIVE.to_string()));
    }

    match matches.subcommand() {
        Some(("secrets", sm)) => match sm.subcommand() {
            Some(("set", sm2)) => {
                let keys: Vec<String> = sm2
                    .get_many::<String>("key")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
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
                run_set(
                    &keys[0],
                    config,
                    project,
                    sm2.get_one::<String>("from-file").cloned(),
                )
            }
            Some(("exec", em)) => {
                let argv: Vec<String> = em
                    .get_many::<String>("argv")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
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
                    em.get_one::<String>("intent")
                        .cloned()
                        .unwrap_or_else(|| "dev".to_string()),
                    em.get_flag("break-glass"),
                )
            }
            Some(("apply", _)) => run_apply(config, project),
            Some(("list", _)) => run_list(config, project),
            Some(("status", stm)) => run_status(config, project, stm.get_flag("json")),
            Some(("rm", rm)) => {
                let keys: Vec<String> = rm
                    .get_many::<String>("key")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
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
                rpm.get_one::<String>("identity")
                    .cloned()
                    .unwrap_or_default(),
                rpm.get_one::<String>("since").cloned().unwrap_or_default(),
                rpm.get_flag("assume-policy"),
                rpm.get_flag("json"),
            ),
            Some(("import-env", im)) => {
                let files: Vec<String> = im
                    .get_many::<String>("file")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
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
            Some(("sync", sy)) => run_sync(
                config,
                project,
                sy.get_one::<String>("target").cloned().unwrap_or_default(),
                sy.get_flag("dry-run"),
                CoolifyTarget {
                    app: sy.get_one::<String>("app").cloned().unwrap_or_default(),
                    all_apps: sy.get_flag("all-apps"),
                    force: sy.get_flag("force"),
                    prefix: sy.get_one::<String>("prefix").cloned().unwrap_or_default(),
                    url: sy
                        .get_one::<String>("coolify-url")
                        .cloned()
                        .unwrap_or_default(),
                },
            ),
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
                im.get_one::<String>("project-name")
                    .cloned()
                    .unwrap_or_default(),
                im.get_flag("force"),
            ),
            Some(("get", gm)) => {
                let keys: Vec<String> = gm
                    .get_many::<String>("key")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
                // cobra ExactArgs(1) ile AYNI metin.
                if keys.len() != 1 {
                    return Err(CmdError::Plain(format!(
                        "accepts 1 arg(s), received {}",
                        keys.len()
                    )));
                }
                run_get(&keys[0], config, project)
            }
            _ => {
                let _ = cli::build()
                    .find_subcommand_mut("secrets")
                    .unwrap()
                    .print_help();
                std::process::exit(0);
            }
        },
        Some(("doctor", dm)) => run_doctor(
            dm.get_one::<String>("for")
                .map(String::as_str)
                .unwrap_or_default(),
        ),
        Some(("rotate", rm)) => match rm.subcommand() {
            Some(("skip", sm)) => {
                let args: Vec<String> = sm
                    .get_many::<String>("args")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
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
                    sm.get_one::<String>("reason")
                        .map(String::as_str)
                        .unwrap_or_default(),
                )
            }
            _ => {
                let _ = cli::build()
                    .find_subcommand_mut("rotate")
                    .unwrap()
                    .print_help();
                std::process::exit(0);
            }
        },
        Some(("tofu", tm)) => {
            let args: Vec<String> = tm
                .get_many::<String>("argv")
                .map(|v| v.cloned().collect())
                .unwrap_or_default();
            // `project` ve `config` BILEREK gecirilmiyor: cobra'da
            // DisableFlagParsing onlari hic ayristirmiyor (bkz. run_tofu).
            run_tofu(&args)
        }
        // `dr` — kokte mount'lu, kapilar YAPRAKTA. Sira Go ile AYNI ve
        // yaprak basina FARKLI: `verify` guard'siz, `split`/`combine` PolicyTTY.
        Some(("dr", dm)) => match dm.subcommand() {
            Some(("verify", vm)) => run_dr_verify(vm.get_one::<String>("snapshot").cloned()),
            Some(("restore", rm)) => run_dr_restore(
                shadowed_project(rm, &project),
                rm.get_one::<String>("snapshot").cloned(),
                rm.get_one::<String>("out").cloned(),
                rm.get_flag("confirm"),
                rm.get_many::<String>("share")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default(),
            ),
            Some(("split", sm)) => run_dr_split(
                sm.get_one::<String>("out-dir").cloned(),
                sm.get_one::<String>("parts").cloned(),
                sm.get_one::<String>("threshold").cloned(),
                sm.get_one::<String>("master-hex").cloned(),
            ),
            Some(("combine", cm)) => run_dr_combine(
                cm.get_many::<String>("share")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default(),
                cm.get_one::<String>("out").cloned(),
                cm.get_one::<String>("expect-kid").cloned(),
            ),
            Some(("bootstrap", bm)) => {
                let argv: Vec<String> = bm
                    .get_many::<String>("argv")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default();
                // ARITE ONCE, ve bu SIRA GOZLEMLENEBILIR: Go'da
                // `cobra.MinimumNArgs(1)` ajan guard'indan (RunE'nin ICINDE)
                // ONCE kosuyor, yani ajan modunda KOMUTSUZ bir cagri
                // AGENT_MODE_REFUSED degil bir ARITE hatasi verir. `dr split`
                // bunun TERSI (Args kisiti yok -> ret once gelir) ve iki
                // davranis da differential'da ayri ayri olculuyor.
                if argv.is_empty() {
                    return Err(CmdError::Plain(
                        "requires at least 1 arg(s), only received 0".to_string(),
                    ));
                }
                run_dr_bootstrap(
                    &argv,
                    &bm.get_many::<String>("var")
                        .map(|v| v.cloned().collect::<Vec<String>>())
                        .unwrap_or_default(),
                    bm.get_flag("skip-preflight"),
                )
            }
            Some(("accept-epoch-reset", am)) => {
                run_dr_accept_epoch_reset(shadowed_project(am, &project))
            }
            _ => {
                let _ = cli::build().find_subcommand_mut("dr").unwrap().print_help();
                std::process::exit(0);
            }
        },
        Some(("whoami", _)) => run_whoami(),
        Some(("skill", sm)) => run_skill(sm),
        Some(("login", lm)) => run_login(lm.get_flag("check"), lm.get_flag("write")),
        Some(("token", tm)) => match tm.subcommand() {
            Some(("exchange", em)) => run_token_exchange(
                shadowed_project(em, &project),
                em.get_many::<String>("key")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default(),
                em.get_many::<String>("verb")
                    .map(|v| v.cloned().collect())
                    .unwrap_or_default(),
                em.get_one::<String>("ttl").cloned(),
            ),
            _ => {
                let _ = cli::build()
                    .find_subcommand_mut("token")
                    .unwrap()
                    .print_help();
                std::process::exit(0);
            }
        },
        Some(("deploy", _)) => match deploy_opts {
            Some(opts) => run_deploy(config, project, &opts),
            None => Ok(()),
        },
        Some(("coolify", _)) => match coolify_leaf {
            Some(leaf) => coolifyverb::run(leaf, &mut std::io::stdout()).map_err(CmdError::Plain),
            None => {
                let _ = cli::build()
                    .find_subcommand_mut("coolify")
                    .unwrap()
                    .print_help();
                std::process::exit(0);
            }
        },
        Some(("projects", pm)) => match pm.subcommand() {
            Some(("list", lm)) => {
                // cobra.NoArgs — ve reddin METNI cobra'nindir: fazladan
                // arguman "unknown command" olarak adlandiriliyor, bir arite
                // hatasi olarak DEGIL.
                if let Some(extra) = lm
                    .get_many::<String>("extra")
                    .and_then(|mut v| v.next().cloned())
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
                let _ = cli::build()
                    .find_subcommand_mut("projects")
                    .unwrap()
                    .print_help();
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
fn run_status(config: Option<String>, project: Option<String>, json: bool) -> Result<(), CmdError> {
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
    let text = if json {
        statusverb::render_json(&rep)
    } else {
        statusverb::render_text(&rep)
    };
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
// --- dr ---------------------------------------------------------------------------
//
// UC KAPI FARKI, ve ucu de Go'dan OKUNDU, tahmin EDILMEDI:
//   1. `dr` kokte mount'lu -> baglama kapisi HIC kosmuyor (Ctx cozulmuyor);
//   2. `verify` ajan kapisi TASIMIYOR (sir yok, ag yok);
//   3. `split`/`combine` PolicyTTY -> ajan modunda REDDEDILIYOR, ve red
//      DIGER HER SEYDEN ONCE gelir (eksik bayrak kontrolunden bile).
// Sira onemli: guard'i bayrak kontrolunden SONRA cagirmak, ajan moduna
// "hangi bayragi unuttugunu" soyleyen bir sizinti olurdu.

fn run_dr_verify(snapshot: Option<String>) -> Result<(), CmdError> {
    let dir = snapshot.unwrap_or_default();
    if dir.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::ActionUnavailable,
            "dr verify runs against a local snapshot copy of the B2 replica: sync it first (rclone/b2 CLI, read-only key) and pass --snapshot <dir>",
        )));
    }
    let mut out = std::io::stdout();
    drverb::run_verify(&mut out, std::path::Path::new(&dir)).map_err(CmdError::Cli)
}

/// run_dr_restore, gercek felaket toreni. GUARD SIRASI Go ile AYNEN ayni ve
/// bu OLCULEBILIR bir sozlesme: once TTY guard'i (ajan modunda HICBIR bayrak
/// bakilmadan reddedilir — bayrak hatalari bile sizmaz), sonra --project /
/// --snapshot, sonra --out, sonra pay sayisi, EN SON --confirm.
fn run_dr_restore(
    project: Option<String>,
    snapshot: Option<String>,
    out: Option<String>,
    confirm: bool,
    shares: Vec<String>,
) -> Result<(), CmdError> {
    // TTY-only seremoni: ajan modunda ASLA (§7.1 dr restore REFUSED).
    agentmode::guard(agentmode::POLICY_TTY, agentmode::is_agent()).map_err(CmdError::Cli)?;
    let project = project.unwrap_or_default();
    let snapshot = snapshot.unwrap_or_default();
    if project.is_empty() || snapshot.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "dr restore: --project and --snapshot are required",
        )));
    }
    let out = out.unwrap_or_default();
    if out.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "dr restore: --out <env-file> is required (values are NEVER printed)",
        )));
    }
    if shares.len() < 2 {
        return Err(CmdError::Cli(Error::new(
            Code::ActionUnavailable,
            "dr restore needs ≥2 Shamir share files (--share PATH --share PATH); the assembled MASTER_KEK is NEVER persisted",
        )));
    }
    if !confirm {
        return Err(CmdError::Cli(Error::new(
            Code::ActionUnavailable,
            "dr restore is a disaster ceremony; re-run with --confirm once the air-gapped machine holds ≥2 shares and the snapshot copy",
        )));
    }
    let paths: Vec<std::path::PathBuf> = shares.iter().map(std::path::PathBuf::from).collect();
    let mut w = std::io::stdout();
    drverb::restore_project_from_snapshot(
        &mut w,
        std::path::Path::new(&snapshot),
        &project,
        &paths,
        std::path::Path::new(&out),
    )
    .map_err(CmdError::Cli)
}

fn run_dr_split(
    out_dir: Option<String>,
    parts: Option<String>,
    threshold: Option<String>,
    master_hex: Option<String>,
) -> Result<(), CmdError> {
    // TTY-only: MASTER_KEK bir AI transcript'inden ASLA gecmemeli.
    agentmode::guard(agentmode::POLICY_TTY, agentmode::is_agent()).map_err(CmdError::Cli)?;
    // Go'da bunlar cobra IntVar VARSAYILANLARI (3 / 2), bayrak verilmezse
    // sifir DEGIL. Varsayilani dusurmek `--parts`siz bir cagriyi sessizce
    // "parts=0" yapardi ve hata metni ayrisirdi.
    let parts = parse_int_flag(parts.as_deref(), 3, "parts")?;
    let threshold = parse_int_flag(threshold.as_deref(), 2, "threshold")?;
    let out_dir = out_dir.unwrap_or_default();
    if out_dir.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "dr split: --out-dir <dir> is required (0600 share files land there)",
        )));
    }

    // MASTER_KEK kaynagi: --master-hex, yoksa YANKISIZ prompt. Guard TTY'yi
    // zaten kanitladi (non-TTY stdin -> ajan modu -> yukarida reddedildi).
    let mut master = master_hex.unwrap_or_default().trim().to_string();
    if master.is_empty() {
        let mut errw = std::io::stderr();
        let (v, _) = setverb::prompt_no_echo(&mut errw, "MASTER_KEK (64-hex, input hidden): ")
            .map_err(|e| {
                CmdError::Cli(Error::new(
                    Code::Internal,
                    format!("dr split: read MASTER_KEK from prompt: {e}"),
                ))
            })?;
        master = v.trim().to_string();
        if master.is_empty() {
            return Err(CmdError::Cli(Error::new(
                Code::ActionUnavailable,
                "dr split: no MASTER_KEK provided — paste the 64-hex value at the prompt, or pass --master-hex",
            )));
        }
    }

    let mut out = std::io::stdout();
    // CSPRNG. `shamir_split` RNG'yi PARAMETRE aliyor (frozen vektorun sarti);
    // uretimde parametre isletim sisteminin entropi kaynagidir.
    let mut rng = OsRng;
    let res = drverb::run_split_core(
        &mut out,
        std::path::Path::new(&out_dir),
        parts,
        threshold,
        &master,
        &mut rng,
    );
    // Best-effort: String'in kendisi wipe EDILEMIYOR (Go yorumu da bunu
    // soyluyor). Kapatilabilirdi (Zeroizing) ama o zaman iki ikili BELLEK
    // HIJYENI olarak ayrisirdi — bilincli olarak parite tercih edildi.
    master.clear();
    res.map_err(CmdError::Cli)
}

// run_dr_bootstrap, `wapps dr bootstrap` — cekirdegi URETIM dikisleriyle baglar.
//
// BU FONKSIYON OLMADAN `run_bootstrap_core` OLU KOD OLURDU. Bu depoda olculmus
// bir kural var: "test var" ile "davranis sevk ediliyor" AYNI SEY DEGIL
// (`derive_project_kek` uretimden sifir kez cagriliyor; `slot_for` sifir
// cagriyla SILINDI). Cekirdegin uc dikisi burada, ve YALNIZCA burada,
// gercek karsiliklarina baglaniyor:
//   lookup  -> surecin gercek ortami
//   prompt  -> setverb::prompt_no_echo (YANKISIZ; `dr split` ile ayni giris)
//   runner  -> execverb::default_exec_runner (gercek alt-surec)
fn run_dr_bootstrap(
    argv: &[String],
    extra_vars: &[String],
    skip_preflight: bool,
) -> Result<(), CmdError> {
    let mut out = std::io::stdout();
    let mut errw = std::io::stderr();
    let action = drverb::run_bootstrap_core(
        argv,
        extra_vars,
        skip_preflight,
        agentmode::is_agent(),
        &mut out,
        &mut errw,
        &|k| std::env::var(k).unwrap_or_default(),
        // Istem STDERR'e yaziliyor (Go: promptValueNoEcho -> os.Stderr) ve
        // deger YANKILANMIYOR. Ikinci deger stdin'in TTY olup olmadigi:
        // cekirdek bununla "boru gecmisi" uyarisini TEK KEZ basiyor.
        &|prompt| {
            let mut e = std::io::stderr();
            setverb::prompt_no_echo(&mut e, prompt)
        },
        &|name, args, env, so, se| execverb::default_exec_runner(name, args, env, so, se),
    )?;
    match action {
        // The child's exit code is mirrored as is (Go: os.Exit). `as u8` is
        // the truncation exit(2) applies anyway: -1 (no code) leaves as 255.
        execverb::ExitAction::Exit(code) => Err(CmdError::Exit(code as u8)),
        execverb::ExitAction::Ok => Ok(()),
    }
}

// HEAD_PREFIX_LEN, operatorun KAGITTAN yazdigi hex onekinin uzunlugu.
const HEAD_PREFIX_LEN: usize = 12;

// is_hex12, Go'daki `^[0-9a-f]{12}$` regexinin karsiligi — regex crate'i YOK.
//
// Desen bir KARAKTER SINIFI + sabit uzunluk, yani bir ayristirici gerekmiyor;
// `regex`i yalnizca bunun icin agaca almak, docs/PORT-kalan-yuzey.md §4.1'in
// `deploy` icin olctugu kararla ayni sinifta olurdu.
//
// KUCUK HARF SART ve bu bir ayrinti degil: cagiran metni ONCE ToLower ediyor,
// yani buraya buyuk harf ULASAMAZ. Sinifi `[0-9a-fA-F]` yapmak Go ile ayni
// sonucu verirdi ama Go'nun REDDETTIGI bir girdiyi kabul eden bir yol acardi.
fn is_hex12(s: &str) -> bool {
    s.len() == HEAD_PREFIX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// run_dr_accept_epoch_reset, `wapps dr accept-epoch-reset` — epoch pinini
// INDIREN TEK yol.
//
// Pin (epochpin.rs) tam olarak bir seyi yakalamak icin var: degistirilmis ya
// da yeniden kurulmus bir store. Onu indirmenin mesru tek yolu bu seremoni ve
// kural sert (kritik H4):
//
//   1. canli audit-chain head'i gate'ten cekilir (GET /v1/audit/head);
//   2. operator KAGIT ZARFTAKI head hash'inin ilk 12 hex'ini YAZAR — kagit
//      degeri yazmak out-of-band dogrulamanin KENDISIDIR, bir y/n DEGIL;
//   3. uyusmazlik -> HARD ABORT: store substitution varsayilir, pin'e
//      DOKUNULMAZ ve kabul eden store HIC kurulmaz;
//   4. eslesme -> TEK bir pin-indiren okuma (`X-Wapps-Intent: epoch-reset`).
//
// KAPI SIRASI GOZLEMLENEBILIR ve Go ile AYNEN ayni: ajan reddi HER SEYDEN
// once — bayrak hatalari bile sizmaz, gate'e tek istek cikmaz, prompt hic
// gorunmez (`dr split` ile ayni yon, `dr bootstrap` ile ters).
//
// BILINEN AYRISMA — prompt HATA yolu: Go `clierr.Wrapf(..., perr, "dr
// accept-epoch-reset: read paper head prefix")` ile sarip altindaki HAM
// hatayi basiyor ("... : EOF"); buradaki `prompt_no_echo` kendi metnini
// ("read value: <std::io hatasi>") tasiyor. Kod (INTERNAL), onek ve cikis
// kodu ESIT; ayrisan sey isletim sistemi seviyesindeki dize. Bu yol pty
// altinda TETIKLENEMIYOR (bir pty master'i asla EOF vermez, okuma bloklanir
// ve olculen sey bir davranis degil bir zaman asimi olurdu), o yuzden
// differential'a KONMADI — sahte bir sadakat olurdu.
fn run_dr_accept_epoch_reset(project: Option<String>) -> Result<(), CmdError> {
    // (0) TTY-only guard HER SEYDEN ONCE (kritik H4 — sosyal muhendislik kolu).
    agentmode::guard(agentmode::POLICY_TTY, agentmode::is_agent()).map_err(CmdError::Cli)?;
    let project = project.unwrap_or_default();
    if project.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "dr accept-epoch-reset: --project is required",
        )));
    }

    // (1) Canli audit head. Bu okuma pin'e DOKUNMAZ.
    let (seq, hash) = store::audit_head().map_err(CmdError::Cli)?;
    // `len` BAYT sayar (Go'daki `len(hash)` gibi) ve metne de bayt sayisi
    // girer. Bir hex hash zaten ASCII; bayt saymak ayni zamanda asagidaki
    // dilimlemeyi de guvenli kiliyor.
    if hash.len() < HEAD_PREFIX_LEN {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            format!(
                "dr accept-epoch-reset: gate returned a malformed head hash (len {})",
                hash.len()
            ),
        )));
    }

    // ON KONTROL, DEFAULT-FALSE store ile: bu cagri pin'i ASLA INDIREMEZ.
    // Uc dal ve ucu de ayri: basari -> indirilecek bir sey yok (seremoni
    // no-op); EPOCH_DOWNGRADE -> durum ozeti basilir ve devam edilir;
    // BASKA bir hata -> AYNEN yayilir. Ucuncusu unutulmasi en kolay olani:
    // "hata varsa demek ki downgrade" diyen bir port, coken bir gate'i
    // seremoniye devam etme sebebi sayardi.
    //
    // YAN ETKI KASITLI: bu okuma default-false oldugu icin pin'i ILERLETIR
    // (served > pinned oldugunda). Yani "indirecek bir sey yok" dali bile
    // diske yazabilir, ve differential pin dosyasini karsilastiriyor.
    match store::keys(&project) {
        Ok(_) => {
            println!(
                "epoch pin for {} is already <= the served epoch — nothing to reset.",
                go_quote(&project)
            );
            return Ok(());
        }
        Err(e) if e.code != Code::EpochDowngrade => return Err(CmdError::Cli(e)),
        // EPOCH_DOWNGRADE mesaji pinned/served ciftini ICERIYOR; operatore
        // durum ozeti olarak AYNEN basiliyor.
        Err(e) => println!("gate state: {e}"),
    }
    // Sondaki bos satir Go'daki "\n\n"in ta kendisi — istem ondan sonra gelir.
    println!("live audit head: seq={seq} hash={hash}\n");

    // (2) Out-of-band dogrulama. Metin STDERR'e: ekrandan KOPYALAMAK
    // dogrulama DEGILDIR, zarfi acmak dogrulamadir.
    let mut errw = std::io::stderr();
    let _ = writeln!(
        errw,
        "Open the paper envelope from the custodian kit. Do NOT copy from this screen —"
    );
    let _ = writeln!(
        errw,
        "type the value recorded on paper at the last successful dr verify."
    );
    // YANKISIZ okuma (`dr split`/`bootstrap` ile AYNI giris). Yazilan 12-hex
    // bir SIR degil, ama ayni yardimci kullaniliyor: ikinci bir istem yuzeyi
    // acmak, birinin gun gelip yankilamaya baslamasi demekti.
    let (typed, _) = setverb::prompt_no_echo(
        &mut errw,
        &format!("First {HEAD_PREFIX_LEN} hex chars of the PAPER head hash: "),
    )
    .map_err(|e| {
        CmdError::Cli(Error::new(
            Code::Internal,
            format!("dr accept-epoch-reset: read paper head prefix: {e}"),
        ))
    })?;
    let typed = typed.trim().to_lowercase();
    if !is_hex12(&typed) {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            format!(
                "dr accept-epoch-reset: expected exactly {HEAD_PREFIX_LEN} hex chars from the paper envelope"
            ),
        )));
    }
    // Gate'ten gelen hash de KUCUK HARFE indiriliyor: kagida buyuk harf
    // yazilmis bir zarf ile buyuk harf donen bir gate ayni seremoniyi
    // gecirmeli. `to_ascii_lowercase` yeterli ve DOGRU: `is_hex12` yazilan
    // degerin saf ASCII oldugunu zaten kanitladi, yani ASCII disi bir gate
    // hash'i her halukarda uyusmaz.
    if typed.as_bytes() != hash.as_bytes()[..HEAD_PREFIX_LEN].to_ascii_lowercase() {
        // (3) HARD ABORT. Pin'e DOKUNULMAZ; kabul eden store HIC kurulmaz.
        return Err(CmdError::Cli(
            Error::new(
                Code::EpochDowngrade,
                "paper head hash does NOT match the live audit head — store substitution assumed; open an incident (risk register #8)",
            )
            .with_recovery(
                "do NOT retry with a different value; verify the custodian envelopes and open an incident",
            ),
        ));
    }

    // (4) Eslesme: TEK pin-indiren okuma.
    let res = store::keys_accepting_epoch_reset(&project).map_err(CmdError::Cli)?;
    println!(
        "✓ epoch pin for {} reset to served epoch {} (audit head seq={seq} verified against paper).",
        go_quote(&project),
        res.epoch
    );
    println!(
        "NEXT: re-record the CURRENT head hash on paper and re-seal the envelopes (verify → paper → seal)."
    );
    Ok(())
}

fn run_dr_combine(
    shares: Vec<String>,
    out: Option<String>,
    expect_kid: Option<String>,
) -> Result<(), CmdError> {
    agentmode::guard(agentmode::POLICY_TTY, agentmode::is_agent()).map_err(CmdError::Cli)?;
    if shares.len() < 2 {
        return Err(CmdError::Cli(Error::new(
            Code::ActionUnavailable,
            "dr combine needs >=2 --share files",
        )));
    }
    let out = out.unwrap_or_default();
    if out.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "dr combine: --out <file> is required (the key is NEVER printed)",
        )));
    }
    let paths: Vec<std::path::PathBuf> = shares.iter().map(std::path::PathBuf::from).collect();
    let mut w = std::io::stdout();
    drverb::run_combine_core(
        &mut w,
        &paths,
        std::path::Path::new(&out),
        &expect_kid.unwrap_or_default(),
    )
    .map_err(CmdError::Cli)
}

/// parse_int_flag, cobra'nin IntVar'inin karsiligi: bayrak yoksa VARSAYILAN,
/// varsa ayristirilir ve ayristirilamiyorsa cobra'nin METNIYLE reddedilir.
fn parse_int_flag(v: Option<&str>, default: usize, name: &str) -> Result<usize, CmdError> {
    match v {
        None => Ok(default),
        Some(s) => s.parse::<usize>().map_err(|_| {
            CmdError::Plain(format!(
                "invalid argument {} for \"--{name}\" flag: strconv.ParseInt: parsing {}: invalid syntax",
                go_quote(s),
                go_quote(s)
            ))
        }),
    }
}

/// OsRng, isletim sisteminin CSPRNG'si — `shamir_split`in Read parametresi
/// icin. Yeni bir crate EKLENMEDI: /dev/urandom dogrudan okunuyor. Kisa okuma
/// `read_exact`te HATA olur (fail-closed), sessizce sifir DOLDURMAZ.
struct OsRng;

impl std::io::Read for OsRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut std::fs::File::open("/dev/urandom")?, buf)
    }
}

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
    let _ = write!(
        out,
        "{}",
        policyverb::render_show(res.version, &res.sha256, &res.policy)
    );
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
    let mut doc =
        policyverb::read_policy_file(std::path::Path::new(path)).map_err(CmdError::Cli)?;

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
        CmdError::Cli(Error::new(
            Code::PolicyInvalid,
            format!("policy file rejected offline: {e}"),
        ))
    })?;

    let _ = write!(
        out,
        "{}",
        policyverb::rule_diff(&cur.policy.rules, &doc.rules)
    );
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
            Err(CmdError::Plain(
                "doctor --for tofu: env not ready".to_string(),
            ))
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
    if std::env::var("AWS_ACCESS_KEY_ID")
        .unwrap_or_default()
        .is_empty()
    {
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
    let url =
        doctorverb::coolify_health_endpoint(&std::env::var("COOLIFY_URL").unwrap_or_default());
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
        Err(ureq::Error::Transport(t)) => (format!("✗ Coolify API unreachable: {t}\n"), false),
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

    let cfg = ctx
        .require_store_config("import-env")
        .map_err(CmdError::Cli)?;

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
    let overridden: Vec<String> = sets
        .keys()
        .filter(|k| existing.contains(*k))
        .cloned()
        .collect();

    store::import_values(&cfg.project, &sets, false).map_err(CmdError::Cli)?;

    // Auto-apply: bildirilen hedefler HEMEN yazilir ki tuketim tarafi
    // (.env.local vb.) ikinci bir komut beklemeden import'u yansitsin.
    let archive = values_to_archive_json(&sets)
        .map_err(|e| CmdError::Plain(format!("secrets.import-env: {e}")))?;
    applyverb::apply_targets_after_write(&cfg, archive.as_bytes(), cfg.config_root(), &mut errw)
        .map_err(CmdError::Plain)?;

    let mut out = std::io::stdout();
    let _ = write!(
        out,
        "{}",
        importenv::success_line(sets.len(), env_file, &cfg.project)
    );
    if !overridden.is_empty() {
        let _ = write!(errw, "{}", importenv::override_line(&overridden));
    }
    Ok(())
}

// run_sync, `wapps secrets sync` without `--target`.
//
// GATE ORDER, measured from the Go oracle:
//   1. agent policy `allow`, then the binding gate (secretsPreRunE)
//   2. `--target`: "coolify" is the Coolify arm (run_sync_coolify); anything
//      else non-empty is refused by name
//   3. config requirement (require_store_config; `--project <name>` does not
//      stand in for one: sync reads `sources:`)
//   4. tofu preflight, only when a tofu source is declared, BEFORE any
//      source is read
//   5. read every source in order, merge (later wins, one STDERR line per
//      overridden key), envelopes -> plain strings
//   6. no keys -> error; --dry-run -> names-only report (one bulk read, so
//      the epoch pin advances); otherwise ONE import tagged
//      `X-Wapps-Intent: sync` (a write: the pin is not touched)
//
// Unlike `import-env`, sync does NOT write the declared targets afterwards.
fn run_sync(
    config: Option<String>,
    project: Option<String>,
    target: String,
    dry_run: bool,
    coolify: CoolifyTarget,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;

    if target == "coolify" {
        return run_sync_coolify(&ctx, coolify);
    }
    if !target.is_empty() {
        return Err(CmdError::Plain(format!(
            "sync: unknown --target {} (allowed: coolify)",
            go_quote(&target)
        )));
    }

    let cfg = ctx.require_store_config("sync").map_err(CmdError::Cli)?;
    if cfg.sources.iter().any(|s| s.r#type == "tofu") {
        let lookup = |name: &str| std::env::var(name).unwrap_or_default();
        if let Some(msg) = wapps::tofu::preflight_env(&lookup) {
            return Err(CmdError::Plain(msg));
        }
    }

    let mut parts = Vec::new();
    for (i, src) in cfg.resolved_sources().iter().enumerate() {
        parts.push(syncverb::read_source(i, src).map_err(CmdError::Plain)?);
    }
    let (merged, overridden) = syncverb::merge(parts);
    let mut errw = std::io::stderr();
    for k in &overridden {
        let _ = write!(errw, "{}", syncverb::override_line(k));
    }
    let sets = syncverb::merged_to_sets(&merged).map_err(CmdError::Plain)?;
    if sets.is_empty() {
        return Err(CmdError::Plain(
            "secrets.sync: no source keys to commit to the store".to_string(),
        ));
    }

    let mut out = std::io::stdout();
    if dry_run {
        let current = store::read_all(&cfg.project).map_err(CmdError::Cli)?;
        let _ = write!(out, "{}", syncverb::render_plan(&sets, &current));
        return Ok(());
    }
    store::import_values(&cfg.project, &sets, true).map_err(CmdError::Cli)?;
    let _ = write!(
        out,
        "{}",
        syncverb::committed_line(sets.len(), &cfg.project)
    );
    Ok(())
}

// CoolifyTarget, the flags only `sync --target=coolify` reads. `--dry-run`
// is not among them: dry-run is that arm's default and `--force` applies.
struct CoolifyTarget {
    app: String,
    all_apps: bool,
    force: bool,
    prefix: String,
    url: String,
}

// run_sync_coolify, `wapps secrets sync --target=coolify`, after the agent
// policy and the binding gate (cmd/secrets/sync_coolify.go, runSyncCoolify):
//
//   1. --app / --all-apps: exclusive, one of them required;
//   2. COOLIFY_API_TOKEN;
//   3. the config, loaded but NOT through require_store_config: a missing one
//      is this arm's own sentence (and `--project <name>` does not stand in);
//   4. ONE bulk store read (the epoch pin advances, even when the app uuid
//      turns out to be invalid);
//   5. the Coolify half (coolifysync): single-app or multi-app.
//
// The Coolify URL is `--coolify-url` only; COOLIFY_URL is not read here.
fn run_sync_coolify(ctx: &Ctx, flags: CoolifyTarget) -> Result<(), CmdError> {
    if !flags.app.is_empty() && flags.all_apps {
        return Err(CmdError::Plain(
            "sync --target=coolify: --app and --all-apps are mutually exclusive".to_string(),
        ));
    }
    if flags.app.is_empty() && !flags.all_apps {
        return Err(CmdError::Plain(
            "sync --target=coolify: one of --app <uuid> or --all-apps required".to_string(),
        ));
    }
    let token = std::env::var("COOLIFY_API_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err(CmdError::Plain(
            "sync --target=coolify: COOLIFY_API_TOKEN not set".to_string(),
        ));
    }
    // Go returns config.Load's error as a plain error.
    let Some(cfg) = ctx.load_or_none().map_err(|e| CmdError::Plain(e.message))? else {
        return Err(CmdError::Plain(
            "sync --target=coolify: .wapps.yaml required (need dest path for archive)".to_string(),
        ));
    };
    let values = store::read_all(&cfg.project).map_err(CmdError::Cli)?;
    let client = wapps::coolify::Client::new(&flags.url, &token);
    let mut out = std::io::stdout();
    if flags.all_apps {
        coolifysync::run_all_apps(
            &client,
            cfg.coolify_sync.as_ref(),
            &values,
            flags.force,
            &mut out,
        )
    } else {
        coolifysync::run_single(
            &client,
            &flags.app,
            &values,
            &flags.prefix,
            flags.force,
            &mut out,
        )
    }
    .map_err(CmdError::Plain)
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
    let archive =
        values_to_archive_json(&values).map_err(|e| CmdError::Plain(format!("env: {e}")))?;

    if write_path.is_empty() {
        let mut out = std::io::stdout();
        return envwrite::write_tofu_outputs_as_env(archive.as_bytes(), &prefix, &mut out)
            .map_err(CmdError::Plain);
    }
    // Hedef yolu CWD-GORELI birakiliyor (Go: os.OpenFile(writePath...)),
    // `apply`in config_root'a cozdugu hedeflerin AKSINE. Bu fark bilincli
    // tasindi: `env --write` bir kerelik, operatorun bulundugu dizine yazan
    // bir kacis kapisi.
    envverb::write_env_file_atomic(
        std::path::Path::new(&write_path),
        archive.as_bytes(),
        &prefix,
    )
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
    let path = binding::default_path().map_err(|e| {
        CmdError::Cli(Error::new(
            Code::Internal,
            format!("resolve repo-pins path: {e}"),
        ))
    })?;

    let mut out = std::io::stdout();
    let mut stdin = std::io::stdin();
    if !trustrepo::confirm_y(
        &mut stdin,
        &mut out,
        &trustrepo::prompt_block(&repo_id, &cfg),
    ) {
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
// run_set, `wapps secrets set <KEY>`.
//
// KAPI SIRASI, Go'dan OLCULDU (set.go RunE + SecretsCmd.PersistentPreRunE):
//
//   1. arite            (cobra ExactArgs(1) — PersistentPreRunE'dan ONCE)
//   2. ajan politikasi  (`set` -> allow, agentgate.go:30; yani gecer)
//   3. baglama kapisi   (secretsPreRunE — confused-deputy korumasi)
//   4. proje cozumu     (storeProject("set") -> NOT_FOUND)
//   5. deger yakalama, sonra tek-anahtar PUT
//
// BURADA BIR PORT BOSLUGU VARDI ve OLCULDU: run_set eskiden Ctx'i HIC
// cozmuyordu; `--project` yoksa dogrudan "set: no .wapps.yaml found" diyordu.
// Yani KENDI .wapps.yaml'i olan bir dizinde Go BINDING_UNPINNED verirken (3.
// adim) Rust NOT_FOUND veriyordu, ve pinli bir depoda Go YAZARKEN Rust
// calismiyordu.
//
// Bu ayrisma differential'da GORUNMUYORDU: butun `set` vakalari ya
// `--project testproj` veriyordu ya da .wapps.yaml'i OLMAYAN workdir'de
// kosuyordu, yani config kolu HIC gezilmemisti. Uc vaka eklendi
// (agent_set_config_unpinned, human_set_binding_{declined,accepted}) ve
// duzeltmeden ONCE DIFFERENT=3 raporladilar.
//
// Sira artik run_exec/run_apply ile AYNI mekanizmayi kullaniyor (Ctx::resolve
// -> gate -> store_project); `set`in kendi kopyasi olsaydi zamanla ayrisirdi.
fn run_set(
    key: &str,
    config: Option<String>,
    project: Option<String>,
    from_file: Option<String>,
) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    gate(&ctx, agentmode::POLICY_ALLOW, agent)?;
    // store_project, Go'daki storeProject("set"): ciplak `--project <ad>`
    // dogrudan proje ADI olur, yoksa .wapps.yaml ZORUNLU.
    let project = ctx.store_project("set").map_err(CmdError::Cli)?;

    let mut err_out = std::io::stderr();
    let value =
        setverb::capture_value(&mut err_out, key, from_file.as_deref()).map_err(CmdError::Plain)?;

    store::set(&project, key, &value).map_err(CmdError::Cli)?;

    // Basari satiri stdout'a; yalnizca ANAHTAR ADI ve PROJE — deger DEGIL.
    let mut out = std::io::stdout();
    let _ = writeln!(out, "✓ Set {key} (store: {project})");
    Ok(())
}

// run_get, `wapps secrets get <KEY>` — TEK anahtarin DUZ METIN degerini basar.
//
// KAPI SIRASI Go'dan OLCULDU:
//
//   1. arite            (cobra ExactArgs(1) — PersistentPreRunE'dan ONCE)
//   2. --config/--project cozumu (kok PersistentPreRunE: resolveProjectFlag)
//   3. ajan politikasi  (secretsPreRunE: `refuse_agent`)
//   4. baglama kapisi   (secretsPreRunE: checkRepoBinding)
//   5. proje cozumu     (storeProject("get") -> NOT_FOUND)
//   6. POST /read
//
// 3'un varligi 4'u AJAN yolunda ERISILEMEZ kiliyor — `rm`teki ayni desen.
//
// BURADA BIR PORT BOSLUGU VARDI ve OLCULDU: run_get 2. ve 4. adimlari HIC
// kosturmuyordu. `--config` parametresini almiyordu bile (bayrak sessizce yere
// dusuyordu), ve `--project` yoksa dogrudan "get: no .wapps.yaml found"
// diyordu. Yani KENDI `.wapps.yaml`i olan bir dizinde:
//
//   Go   -> baglama kapisi (satir ici onay, sonra deger)
//   Rust -> NOT_FOUND, pinli bir depoda bile OKUYAMIYORDU
//
// Ayrisma differential'da GORUNMUYORDU: `get`in 21 pty vakasinin TAMAMI
// `--project testproj` geciriyordu, yani yapilandirma kolu hic gezilmemisti.
// Uc vaka eklendi (human_get_binding_{declined,accepted},
// human_get_config_flag_binding_accepted) ve duzeltmeden ONCE DIFFERENT=3
// raporladilar.
//
// NEDEN `store_project` ve `require_store_config` DEGIL: ayirici eksen
// "okuyor mu yaziyor mu" DEGIL, "YEREL bir dosya OKUYOR mu". exec/apply
// `targets`/`sources` okuyor, yani `.wapps.yaml` SART. `get` gate'ten TEK
// anahtar cekiyor ve bunun icin yalnizca proje ADI gerekiyor — Go'nun
// storeProject yorumu bu kumeyi ADIYLA sayiyor: list/get/rm/projects. Ciplak
// `--project <ad>` bu yuzden deposuz calisiyor.
//
// Mekanizma ise `set`/`exec`/`apply` ile AYNI (Ctx::resolve -> gate ->
// store_project). `get`in kendi kopyasi olsaydi zamanla ayrisirdi; ayrisacagi
// yer de tam olarak yeni kapatilan bu delik olurdu.
fn run_get(key: &str, config: Option<String>, project: Option<String>) -> Result<(), CmdError> {
    let agent = agentmode::is_agent();
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    // get, gizli bir DUZ METIN degeri basar → ajan modunda YAPISAL red. Kapi
    // baglama kontrolunu de tasiyor ve SIRA onemli: ajan reddi ONCE.
    gate(&ctx, agentmode::POLICY_REFUSE_AGENT, agent)?;

    let project = ctx.store_project("get").map_err(CmdError::Cli)?;

    let res =
        store::read(&project, std::slice::from_ref(&key.to_string())).map_err(CmdError::Cli)?;
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
        // The child's exit code is mirrored as is (see run_dr_bootstrap).
        execverb::ExitAction::Exit(code) => Err(CmdError::Exit(code as u8)),
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
        let _ = cli::build()
            .find_subcommand_mut("tofu")
            .unwrap()
            .print_help();
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

// --- `wapps whoami` ------------------------------------------------------------
//
// KAPISI YOK, ve bu bir bosluk degil bir karar: ne ajan guard'i, ne baglama
// kapisi, ne `Ctx::resolve`. `doctor` ve `secrets status` ile AYNI gerekce —
// DEGER BASMIYOR. Donen sey principal, grup ve grant ADLARIDIR; bir ajanin
// "neyi okuyabilirim" sorusunu deger gormeden cevaplamasi, o sorunun bir
// `secrets get` denemesine donusmemesinin tek yolu.
//
// KOK BAYRAKLARI ATIL: `--project` de `--config` de kabul edilir ve ciktiya
// HIC girmez (Go'da RunE ikisine de bakmiyor). `--config` + `--project`
// BIRLIKTE ise yine de reddedilir — o ret kokun kendisine ait ve whoami'nin
// YEREL `--project`i YOK, yani golgelenmiyor.
fn run_whoami() -> Result<(), CmdError> {
    let res = store::whoami().map_err(CmdError::Cli)?;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "principal:      {}", res.principal);
    // email ve common_name KOSULLU (Go: `if res.X != ""`), gerisi DAIMA
    // basiliyor — bos bir principal bile bir satir uretir.
    if !res.email.is_empty() {
        let _ = writeln!(out, "email:          {}", res.email);
    }
    if !res.common_name.is_empty() {
        let _ = writeln!(out, "common_name:    {}", res.common_name);
    }
    let _ = writeln!(out, "groups:         {}", join_or_dash(&res.groups));
    let _ = writeln!(out, "policy_version: {}", res.policy_version);
    let _ = writeln!(out, "root_admin:     {}", res.is_root_admin);
    if res.grants.is_empty() {
        let _ = writeln!(out, "grants:         (none)");
        return Ok(());
    }
    let _ = writeln!(out, "grants:");
    for g in &res.grants {
        // SECICI ONCELIGI Go'daki ATAMA SIRASI: group, sonra service EZER,
        // sonra aud EZER. Yani ucu birden dolu bir kuralda `aud:` kazanir ve
        // hicbiri dolu degilse secici BOS kalir (atlanmaz).
        let mut sel = g.group.clone();
        if !g.service.is_empty() {
            sel = format!("service:{}", g.service);
        }
        if !g.aud.is_empty() {
            sel = format!("aud:{}", g.aud);
        }
        // `%-28s`: SOLA yaslanmis, 28 karakterden KISA ise doldurulur, UZUN
        // ise KIRPILMAZ (sutun tasar). Rust'in `{:<28}` karsiligi ayni.
        let _ = writeln!(
            out,
            "  {:<28} projects={} keys={} verbs={}",
            sel,
            g.projects.join(","),
            g.keys.join(","),
            g.verbs.join(",")
        );
    }
    Ok(())
}

// --- `wapps login` ---------------------------------------------------------------
//
// ORACLE: cmd/login.go. `--check` wins over `--write` and runs in every mode
// (it prints no token bytes); the plain verb is TTY-only and is refused in
// agent mode BEFORE cloudflared is looked up.
fn run_login(check: bool, write: bool) -> Result<(), CmdError> {
    if check {
        return run_login_check();
    }
    agentmode::guard(agentmode::POLICY_TTY, agentmode::is_agent()).map_err(CmdError::Cli)?;

    // --write: the SSO runs against the WRITE (admin) app at <gate>/v1/admin
    // and the token goes under its own key, so the read session survives.
    let (gate, key, label) = if write {
        let gate = session::admin_gate_url();
        let label = format!("{gate} (admin: 15 min + WebAuthn)");
        (gate, session::admin_session_key(), label)
    } else {
        let host = session::gate_host();
        (session::gate_url(), host.clone(), host)
    };
    let mut out = std::io::stdout();
    let _ = writeln!(out, "Opening CF Access SSO for {label} via cloudflared…");
    // cloudflared writes to the same terminal: this line must land first.
    let _ = out.flush();

    // vars_os, not vars: Go passes os.Environ() through byte-for-byte, and
    // std::env::vars panics on a non-UTF-8 value.
    let base_env: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os().collect();
    let path_env = std::env::var("PATH").unwrap_or_default();
    let temp_base = loginverb::temp_base();
    let token = loginverb::cloudflared_login(&loginverb::CloudflaredRun {
        gate: &gate,
        path_env: &path_env,
        temp_base: &temp_base,
        base_env: &base_env,
        timeout: loginverb::LOGIN_TIMEOUT,
    })
    .map_err(CmdError::Cli)?;

    // Validate the SHAPE and that the claims really decode: a decorated or
    // broken stdout must not pass as a token and later become a bad header.
    if !loginverb::looks_like_jwt(&token) {
        return Err(CmdError::Cli(Error::new(
            Code::Internal,
            "cloudflared returned no usable token; re-run wapps login",
        )));
    }
    let claims = session::parse_claims(&token).map_err(|e| {
        CmdError::Cli(Error::new(
            Code::Internal,
            format!("cloudflared token did not parse as a JWT; re-run wapps login: {e}"),
        ))
    })?;
    session::save(
        &key,
        &session::State {
            token,
            expires_at: claims.exp,
        },
    )
    .map_err(|e| {
        CmdError::Cli(Error::new(
            Code::Internal,
            format!("cache session token: {e}"),
        ))
    })?;
    let _ = write!(out, "{}", loginverb::success_line(&claims, session::now()));
    Ok(())
}

// run_login_check, both sessions' subject + remaining TTL. A missing admin
// session is NOT an error; a missing or expired read session is.
fn run_login_check() -> Result<(), CmdError> {
    let read_host = session::gate_host();
    let Some(s) = session::load(&read_host) else {
        return Err(CmdError::Cli(Error::new(
            Code::SessionExpired,
            format!("no session cached for {read_host}"),
        )));
    };
    let now = session::now_unix();
    if s.expired(now) {
        return Err(CmdError::Cli(Error::new(
            Code::SessionExpired,
            format!("session for {read_host} has expired"),
        )));
    }
    let mut out = std::io::stdout();
    let _ = write!(
        out,
        "{}",
        loginverb::render_session("gate", &read_host, &s, now)
    );
    let _ = writeln!(out);
    match session::load(&session::admin_session_key()) {
        Some(a) if !a.expired(now) => {
            let target = session::admin_gate_url();
            let _ = write!(
                out,
                "{}",
                loginverb::render_session("admin", &target, &a, now)
            );
        }
        _ => {
            let _ = write!(out, "{}", loginverb::ADMIN_MISSING);
        }
    }
    Ok(())
}

// join_or_dash, Go'daki joinOrDash: BOS liste "-" olur, dolu liste ", " ile
// birlesir. Grant satirlarindaki `,` ile KARISTIRILMAMALI — o ayirici
// bosluksuz (Go: strings.Join(g.Projects, ",")).
fn join_or_dash(ss: &[String]) -> String {
    if ss.is_empty() {
        return "-".to_string();
    }
    ss.join(", ")
}

// --- `wapps token exchange` ----------------------------------------------------
//
// BU FIIL BIR SIR BASIYOR, ve estate'in kurali burada BIR ISTISNA ALMIYOR —
// yer degistiriyor: basilan jeton pipeline adiminin YAKALAMASI icin var, yani
// stdout ONUN kanali. Bu yuzden:
//   * jeton STDOUT'a HAM gidiyor (redaksiyon yok, ve olculuyor);
//   * metadata satiri STDERR'e gidiyor ki yakalanan degeri kirletmesin;
//   * jeton hicbir HATA metnine, loga ya da dosyaya girmiyor.
//
// KAPI SIRASI GO'DAN, ve olculdu: service-token cifti ONCE. Cift yokken
// eksik bir bayrak "needs --project" DEGIL "not set" verir.
//
// `--ttl` DOGRULANMIYOR ve `--verb` DE DOGRULANMIYOR: ikisi de oldugu gibi
// tel'e biniyor ve siniri GATE koyuyor (§5.3). Bu OLCULDU — istemcide bir
// tavan uydurmak, gate'in reddini olculemez kilardi.
fn run_token_exchange(
    project: Option<String>,
    keys: Vec<String>,
    verbs: Vec<String>,
    ttl: Option<String>,
) -> Result<(), CmdError> {
    // `--ttl` cobra'da AYRISTIRICIDA cozuluyor, yani bozuk bir deger RunE'ye
    // HIC girmiyor ve service-token kontrolunden de ONCE reddediliyor. Sira
    // burada da oyle: cozum en basta.
    let ttl_seconds = match ttl.as_deref() {
        None => 0,
        Some(raw) => gostrconv::parse_int_base0(raw).map_err(|e| {
            // cobra'nin sarmalayicisi: `invalid argument %q for %q flag: %v`.
            CmdError::Plain(format!(
                "invalid argument {} for {} flag: {}",
                go_quote(raw),
                go_quote("--ttl"),
                e.go_text(raw)
            ))
        })?,
    };

    if !service_creds_present() {
        return Err(CmdError::Cli(Error::new(
            Code::TokenExchangeFailed,
            "CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET not set",
        )));
    }
    let project = project.unwrap_or_default();
    // BOS bir `--key` bir anahtardir: kontrol SAYIYA bakiyor (Go:
    // `len(tokenKeys) == 0`), uzunluga DEGIL.
    if project.is_empty() || keys.is_empty() {
        return Err(CmdError::Cli(Error::new(
            Code::TokenExchangeFailed,
            "token exchange needs --project and at least one --key",
        )));
    }

    let (token, exp) =
        store::token_mint(&project, &keys, &verbs, ttl_seconds).map_err(CmdError::Cli)?;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{token}");
    // exp YOKSA satir HIC basilmaz — bos bir "expires at" satiri, sureyi
    // bilmedigini bilmeyen bir pipeline uretirdi.
    if exp > 0 {
        let mut errw = std::io::stderr();
        let _ = writeln!(
            errw,
            "token expires at {} (unix {exp})",
            gotime::rfc3339_utc(exp)
        );
    }
    Ok(())
}

// service_creds_present, CI service-token ciftinin IKISININ DE dolu olup
// olmadigini soyler (Go: lookupServiceCreds).
//
// TrimSpace GO'DAN: bosluktan ibaret bir cift "set edilmemis" sayilir. Bu bir
// nezaket degil bir kapi — CI'da bos bir degiskeni bosluga esitlemek yaygin
// bir kaza, ve o kazayi "kimlik var" diye okumak istegi aga cikarirdi.
//
// DEGERLERIN KENDISI OKUNMUYOR: yalnizca VARLIKLARI sorulur; header'lari
// kuran yer session::auth_headers.
fn service_creds_present() -> bool {
    let id = std::env::var("CF_ACCESS_CLIENT_ID").unwrap_or_default();
    let secret = std::env::var("CF_ACCESS_CLIENT_SECRET").unwrap_or_default();
    !id.trim().is_empty() && !secret.trim().is_empty()
}

// run_deploy, `wapps deploy <service>`. No agent guard and no binding gate,
// as in Go: the verb is for operators, CI and agents alike. The identity flags
// only decide which `.wapps.yaml` the credential fallback reads — exactly
// Go's StoreValues: `--config`, a registered `--project`, else ./.wapps.yaml
// (an unregistered `--project` is inert). The verb writes every line itself
// and owns its exit code (0..8), which leaves through CmdError::Exit.
fn run_deploy(
    config: Option<String>,
    project: Option<String>,
    opts: &deployverb::Options,
) -> Result<(), CmdError> {
    let ctx = Ctx::resolve(config.as_deref(), project.as_deref()).map_err(CmdError::Cli)?;
    let store = |keys: &[String]| -> (BTreeMap<String, String>, Option<String>) {
        // A config that fails to load is reported with config.Load's own text.
        let cfg = match ctx.load_or_none() {
            Ok(Some(cfg)) => cfg,
            Ok(None) => return (BTreeMap::new(), None),
            Err(e) => return (BTreeMap::new(), Some(e.message)),
        };
        let read = storevalues::store_values(
            Some(&cfg.project),
            keys,
            &|p| {
                Ok(store::keys(p)?
                    .keys
                    .into_iter()
                    .map(|k| k.key_name)
                    .collect())
            },
            &|p, want| Ok(store::read(p, want)?.values),
        );
        match read {
            Ok(values) => (values.unwrap_or_default(), None),
            Err(e) => (BTreeMap::new(), Some(e.to_string())),
        }
    };
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let code = deployverb::run(
        opts,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
        &env,
        &store,
    );
    match code {
        deployverb::EXIT_OK => Ok(()),
        code => Err(CmdError::Exit(code)),
    }
}

// --- `wapps skill` ---------------------------------------------------------------
//
// No gate at all, as in Go: no agent guard, no binding, no Ctx::resolve. The
// verb writes documentation, never a value, and the root's identity flags are
// inert (the corpus measures all four arms). `--config` + `--project` together
// is still refused, by the root, above.
fn run_skill(sm: &clap::ArgMatches) -> Result<(), CmdError> {
    let Some((leaf, lm)) = sm.subcommand() else {
        let _ = cli::build()
            .find_subcommand_mut("skill")
            .unwrap()
            .print_help();
        std::process::exit(0);
    };
    // cobra.NoArgs: an extra argument is an "unknown command".
    if let Some(extra) = lm
        .get_many::<String>("extra")
        .and_then(|mut v| v.next().cloned())
    {
        return Err(CmdError::Plain(format!(
            "unknown command {} for \"wapps skill {leaf}\"",
            go_quote(&extra)
        )));
    }
    let flag = |name: &str| lm.try_get_one::<bool>(name).ok().flatten() == Some(&true);
    let opts = skill::Options::from_flags(
        flag("local"),
        lm.try_get_one::<String>("dir").ok().flatten().cloned(),
        flag("copy"),
    );
    let mut out = std::io::stdout();
    match leaf {
        "install" => skill::run_install(&mut out, &opts),
        "status" => skill::run_status(&mut out),
        _ => skill::run_uninstall(&mut out, &opts),
    }
    .map_err(CmdError::Plain)
}
