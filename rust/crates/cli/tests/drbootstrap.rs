// dr bootstrap — `runDrBootstrap`in Rust karsiliginin OLCUSU.
//
// ORACLE: cmd/secrets/dr_bootstrap.go + dr_bootstrap_test.go (plan P1.3).
// Go'nun matrisi AYNEN yurunuyor: ajan reddi, skip-if-set, tam env adlari,
// preflight, --var birlesimi, scrub, epilogue, exit-kodu, sifir dosya.
//
// BU FIILIN SESSIZ ARIZA SINIFI ve neden bu dosyada IKI ayri scrub testi var:
// `bootstrap`in yanlis cevabi ile dogru cevabi AYNI GORUNUR. Bir apply
// basariyla biter, cikis kodu 0'dir, epilogue basilir — ve tek fark, cocugun
// echo'ladigi token'in transcript'te `***` mi yoksa ACIK METIN mi oldugudur.
// Operator bunu apply BASARILI oldugu icin okumaz bile. Ozellikle KALITILAN
// (skip-if-set) token: hicbir prompt gormedigi icin scrub kumesine
// eklenmesi KOLAYCA unutulabilir ve unutuldugunda HICBIR SEY dusmez.
// `an_inherited_token_echoed_by_the_child_cannot_leak` tam da bunu yuruyor.
use std::cell::RefCell;
use std::io::Write;
use wapps::cli::CmdError;
use wapps::clierr::Code;
use wapps::drverb;
use wapps::execverb::ExitAction;
use wapps::tofu;

// --- dikisler ---------------------------------------------------------------

/// ScriptedPrompt, Go'daki `scriptedPrompt` seam'i: prompt METNININ ilk
/// kelimesi env ADIDIR ("NAME — hint (Enter = skip): "), values'tan deger
/// doner (yoksa "" = skip) ve her cagriyi KAYDEDER.
struct ScriptedPrompt {
    values: Vec<(String, String)>,
    calls: RefCell<Vec<String>>,
    err: Option<String>,
    is_tty: bool,
}

impl ScriptedPrompt {
    fn new(values: Vec<(String, String)>) -> Self {
        ScriptedPrompt {
            values,
            calls: RefCell::new(Vec::new()),
            err: None,
            is_tty: true,
        }
    }
    fn call(&self, prompt: &str) -> Result<(String, bool), String> {
        let name = prompt
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        self.calls.borrow_mut().push(name.clone());
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        let v = self
            .values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        Ok((v, self.is_tty))
    }
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

/// FakeRunner, cocugu GERCEKTEN baslatmayan calistirici.
#[derive(Default)]
struct FakeRunner {
    code: i32,
    err: Option<String>,
    got_name: RefCell<String>,
    got_env: RefCell<Vec<String>>,
}

impl FakeRunner {
    fn run(
        &self,
        name: &str,
        _args: &[String],
        env: &[String],
        _o: &mut dyn Write,
        _e: &mut dyn Write,
    ) -> std::io::Result<i32> {
        *self.got_name.borrow_mut() = name.to_string();
        *self.got_env.borrow_mut() = env.to_vec();
        if let Some(m) = &self.err {
            return Err(std::io::Error::other(m.clone()));
        }
        Ok(self.code)
    }
}

fn promptable_names() -> Vec<String> {
    tofu::BOOTSTRAP_ENV_VARS
        .iter()
        .filter(|v| v.promptable())
        .map(|v| v.name.to_string())
        .collect()
}

/// full_prompt_values, her promptable girdiye BENZERSIZ sahte deger uretir.
/// Degerler scrub tabaninin (4 bayt) USTUNDE — altinda kalsalardi scrubber
/// onlari BILEREK atlardi ve scrub testleri kendi konularini olcmezdi.
fn full_prompt_values() -> Vec<(String, String)> {
    promptable_names()
        .into_iter()
        .map(|n| (n.clone(), format!("val-{}", n.to_lowercase())))
        .collect()
}

fn value_of(vals: &[(String, String)], name: &str) -> String {
    vals.iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .unwrap()
}

fn empty_lookup(_: &str) -> String {
    String::new()
}

// expect_ok / expect_err: `.expect()` `Debug` ISTER, ve onu almak icin
// uretimdeki `CmdError`/`ExitAction`a `#[derive(Debug)]` eklemek gerekirdi.
// Eklenmedi: test kolayligi icin uretim tipini genisletmek, testin kendi
// ihtiyacini uretim yuzeyine sizdirmaktir. Panik metni burada uretiliyor.
fn show(e: &CmdError) -> String {
    match e {
        CmdError::Cli(c) => c.to_string(),
        CmdError::Plain(m) => m.clone(),
        CmdError::Exit(code) => format!("exit {code}"),
    }
}

fn expect_ok(r: Result<ExitAction, CmdError>, what: &str) -> ExitAction {
    match r {
        Ok(a) => a,
        Err(e) => panic!("{what}: basarili bekleniyordu, hata geldi: {}", show(&e)),
    }
}

fn expect_err(r: Result<ExitAction, CmdError>, what: &str) -> CmdError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("{what}: hata bekleniyordu, BASARILI dondu"),
    }
}

/// as_cli, hatanin KODLU (clierr) bicimde geldigini iddia eder.
///
/// NEDEN AYRI IKI YARDIMCI: Go'da `dr bootstrap`in hatalari IKI FARKLI
/// SINIFTAN geliyor ve fark GOZLEMLENEBILIR. `clierr` olanlar insan modunda
/// "Error: CODE: mesaj" basiliyor; `fmt.Errorf` ile uretilen DUZ olanlar
/// (preflight ve runner hatasi) kod oneki OLMADAN "Error: mesaj" basiliyor.
/// Hepsini `clierr`e cevirmek derlenirdi, testler gecerdi ve insan yolunda
/// iki ikili SESSIZCE ayrisirdi.
fn as_cli(e: &CmdError) -> &wapps::clierr::Error {
    match e {
        CmdError::Cli(c) => c,
        CmdError::Plain(m) => panic!("kodlu hata bekleniyordu, DUZ geldi: {m}"),
        CmdError::Exit(code) => panic!("expected a coded error, got exit {code}"),
    }
}

/// as_plain, hatanin KODSUZ (duz) bicimde geldigini iddia eder.
fn as_plain(e: &CmdError) -> String {
    match e {
        CmdError::Plain(m) => m.clone(),
        CmdError::Cli(c) => panic!("DUZ hata bekleniyordu, kodlu geldi: {c}"),
        CmdError::Exit(code) => panic!("expected a plain error, got exit {code}"),
    }
}

// --- ajan reddi ---------------------------------------------------------------

/// Ajan modunda TEK BIR PROMPT bile atilmadan ve cocuk SPAWN EDILMEDEN reddedilir.
#[test]
fn agent_mode_refuses_before_any_prompt_or_spawn() {
    let p = ScriptedPrompt::new(full_prompt_values());
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    let err = expect_err(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            true, // is_agent
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "ajan modunda AGENT_MODE_REFUSED bekleniyor",
    );
    assert_eq!(as_cli(&err).code, Code::AgentModeRefused);
    assert!(
        p.calls().is_empty(),
        "ajan modunda prompt ASLA atesleMEMELI: {:?}",
        p.calls()
    );
    assert_eq!(
        *r.got_name.borrow(),
        "",
        "ajan modunda alt-surec ASLA spawn edilMEMELI"
    );
}

// --- katalog: tam adlar, sabit asla promptlanmaz -------------------------------

#[test]
fn every_promptable_catalog_name_is_prompted_in_order_and_injected() {
    let vals = full_prompt_values();
    let p = ScriptedPrompt::new(vals.clone());
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "bootstrap basarili olmali",
    );

    assert_eq!(
        p.calls(),
        promptable_names(),
        "prompt cagrilari katalog SIRASINDA olmali"
    );
    assert!(
        !p.calls().contains(&"AWS_REGION".to_string()),
        "SABIT deger ASLA promptlanmaz"
    );

    let env = r.got_env.borrow().clone();
    for (n, v) in &vals {
        assert!(env.contains(&format!("{n}={v}")), "cocuk env'inde {n} yok");
    }
    assert!(
        env.contains(&"AWS_REGION=auto".to_string()),
        "sabit AWS_REGION=auto enjekte edilmeli"
    );

    // Degerler wapps'in KENDI ciktisina ASLA yazilmaz (adlar serbest).
    let (so, se) = (
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&errw),
    );
    for (_, v) in &vals {
        assert!(
            !so.contains(v.as_str()) && !se.contains(v.as_str()),
            "sir DEGERI sizdi"
        );
    }
}

// --- skip-if-set ---------------------------------------------------------------

#[test]
fn an_already_set_var_is_inherited_not_prompted_and_not_reinjected() {
    let vals = full_prompt_values();
    let p = ScriptedPrompt::new(vals.clone());
    let r = FakeRunner::default();
    let lookup = |k: &str| {
        if k == "AWS_ACCESS_KEY_ID" {
            "from-shell-akid".to_string()
        } else {
            String::new()
        }
    };
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            true, // preflight ATLANDI: lookup sahte, gercek env'e dokunmuyoruz
            false,
            &mut out,
            &mut errw,
            &lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "bootstrap basarili olmali",
    );

    assert!(
        !p.calls().contains(&"AWS_ACCESS_KEY_ID".to_string()),
        "set olan degisken promptlanmaz"
    );
    let env = r.got_env.borrow().clone();
    let injected_again = format!("AWS_ACCESS_KEY_ID={}", value_of(&vals, "AWS_ACCESS_KEY_ID"));
    assert!(
        !env.contains(&injected_again),
        "set olan degisken YENIDEN enjekte edilmemeli"
    );

    let se = String::from_utf8_lossy(&errw).to_string();
    assert!(
        se.contains("AWS_ACCESS_KEY_ID: already set"),
        "atlama notu yok: {se}"
    );
    assert!(
        !se.contains("from-shell-akid"),
        "atlama notu DEGERI basmamali"
    );
}

// --- preflight ------------------------------------------------------------------

#[test]
fn preflight_failure_names_the_missing_var_and_spawns_nothing() {
    // TF_VAR_state_passphrase icin deger YOK -> prompt "" doner -> skip.
    let vals: Vec<(String, String)> = full_prompt_values()
        .into_iter()
        .filter(|(n, _)| n != "TF_VAR_state_passphrase")
        .collect();
    let p = ScriptedPrompt::new(vals);
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    let err = expect_err(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "eksik TF_VAR_state_passphrase icin preflight duSMELI",
    );
    // Go: `fmt.Errorf("dr bootstrap: %w", perr)` — KODSUZ.
    let msg = as_plain(&err);
    assert!(
        msg.contains("TF_VAR_state_passphrase"),
        "hata eksik ADI soylemeli: {msg}"
    );
    assert!(
        msg.starts_with("dr bootstrap: tofu preflight:"),
        "onek ayristi: {msg}"
    );
    assert_eq!(
        *r.got_name.borrow(),
        "",
        "preflight duserken alt-surec spawn EDILMEMELI"
    );
}

#[test]
fn skip_preflight_runs_the_command_even_with_an_incomplete_contract() {
    let vals: Vec<(String, String)> = full_prompt_values()
        .into_iter()
        .filter(|(n, _)| n != "TF_VAR_state_passphrase")
        .collect();
    let p = ScriptedPrompt::new(vals);
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["some-tool".into()],
            &[],
            true, // --skip-preflight
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "--skip-preflight ile calisMALI",
    );
    assert_eq!(*r.got_name.borrow(), "some-tool");
}

// --- --var birlesimi --------------------------------------------------------------

#[test]
fn an_extra_var_is_injected_and_a_catalog_overlap_is_prompted_exactly_once() {
    let mut vals = full_prompt_values();
    vals.push(("TF_VAR_extra_token".into(), "val-extra".into()));
    let p = ScriptedPrompt::new(vals);
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            // ikincisi katalogda ZATEN var
            &["TF_VAR_extra_token".into(), "TF_VAR_hcloud_token".into()],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "bootstrap basarili olmali",
    );

    assert!(
        r.got_env
            .borrow()
            .contains(&"TF_VAR_extra_token=val-extra".to_string()),
        "--var enjekte edilmeli"
    );
    let n = p
        .calls()
        .iter()
        .filter(|c| *c == "TF_VAR_hcloud_token")
        .count();
    assert_eq!(n, 1, "katalogla cakisan --var TAM BIR KEZ promptlanmali");
}

// --- scrub: SESSIZ ARIZA SINIFI ---------------------------------------------------

#[test]
fn a_prompted_token_echoed_by_the_child_cannot_leak() {
    let vals = full_prompt_values();
    let secret = value_of(&vals, "TF_VAR_cloudflare_api_token");
    let p = ScriptedPrompt::new(vals);
    let leaked = format!("using token {secret}\n");
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|_n, _a, _e, o, _er| {
                let _ = o.write_all(leaked.as_bytes());
                Ok(0)
            },
        ),
        "bootstrap basarili olmali",
    );
    let so = String::from_utf8_lossy(&out).to_string();
    assert!(!so.contains(&secret), "TOKEN TRANSCRIPT'E SIZDI: {so}");
    assert!(so.contains("***"), "redaksiyon *** bekleniyordu: {so}");
}

/// KALITILAN token da sizdiramaz. Bu testin dusurdugu sey bir "eksik ozellik"
/// degil: kalitilan degisken hic promptlanmadigi icin scrub kumesine
/// eklenmesi unutulursa HER SEY calisir gorunur — apply basarili biter, cikis
/// kodu 0'dir — ve tek fark token'in ACIK METIN olmasidir.
#[test]
fn an_inherited_token_echoed_by_the_child_cannot_leak() {
    const INHERITED: &str = "hcloudtok_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    let p = ScriptedPrompt::new(full_prompt_values());
    let lookup = |k: &str| {
        if k == "TF_VAR_hcloud_token" {
            INHERITED.to_string()
        } else {
            String::new()
        }
    };
    let leaked = format!("inherited token {INHERITED}\n");
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            true, // preflight ATLANDI (sahte lookup)
            false,
            &mut out,
            &mut errw,
            &lookup,
            &|s| p.call(s),
            &|_n, _a, _e, o, _er| {
                let _ = o.write_all(leaked.as_bytes());
                Ok(0)
            },
        ),
        "bootstrap basarili olmali",
    );
    let so = String::from_utf8_lossy(&out).to_string();
    assert!(!so.contains(INHERITED), "KALITILAN TOKEN SIZDI: {so}");
    assert!(so.contains("***"), "redaksiyon *** bekleniyordu: {so}");
}

// --- non-TTY uyarisi: URETIMDEN ULASILAMAYAN bir dal ----------------------------
//
// BU TEST BIR MUTASYON BULGUSUNUN SONUCUDUR. Uyariyi TAMAMEN silen bir
// mutasyon (M8) denendi ve HICBIR SEY dusmedi: ne 13 iddia, ne 434 vakalik
// differential. Yani bu dal OLCULMEMISTI.
//
// Ve olculememesinin sebebi yapisal: dalin kosulu `is_tty == false`, ama
// `agentmode::is_agent()` non-TTY stdin'i DAIMA ajan sayiyor ve `POLICY_TTY`
// kapisi tek bir prompt atilmadan reddediyor. `WAPPS_AGENT_MODE=0` override'i
// de YALNIZCA TTY'de onurlandiriliyor. Iki ikilide de OLCULDU: boru ile
// beslenen bir cagri AGENT_MODE_REFUSED aliyor, prompt'a HIC varmiyor.
//
// Yani bu, Go'dan SADAKATLE portlanmis OLU BIR DALDIR ve differential ona
// yapisal olarak KOR — pty harness'inin stdin'i her zaman bir TTY. Silinmedi
// (oracle tasiyor, ve `dr bootstrap` baska bir politikaya tasinirsa yeniden
// canlanir), ama METNI burada, DIKIS uzerinden pinleniyor: artik en azindan
// bir sey onu tutuyor.
#[test]
fn a_non_tty_prompt_warns_once_about_shell_history() {
    let mut p = ScriptedPrompt::new(full_prompt_values());
    p.is_tty = false;
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "bootstrap basarili olmali",
    );
    let se = String::from_utf8_lossy(&errw).to_string();
    assert!(
        se.contains("stdin is not a TTY"),
        "non-TTY uyarisi yok:\n{se}"
    );
    // TEK KEZ: sekiz promptun her birinde tekrarlanmaz.
    assert_eq!(
        se.matches("stdin is not a TTY").count(),
        1,
        "uyari TAM BIR KEZ basilmali"
    );
}

// --- epilogue ---------------------------------------------------------------------

#[test]
fn the_burn_epilogue_prints_all_three_classes_on_success() {
    let p = ScriptedPrompt::new(full_prompt_values());
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "bootstrap basarili olmali",
    );
    let se = String::from_utf8_lossy(&errw).to_string();
    for want in [
        "BURN NOW",
        "BURN AFTER",
        "DO NOT BURN",
        "unset TF_VAR_state_passphrase",
        "NOT the TF_ENCRYPTION",
        "RE-SEAL",
    ] {
        assert!(se.contains(want), "epilogue'da {want:?} yok:\n{se}");
    }
}

/// Cocuk BASLAYAMADIYSA epilogue BASILMAZ: is bitmedi, burn talimati erken
/// verilmez (§3.3 "mint-use-burn: is biter bitmez").
#[test]
fn no_burn_epilogue_when_the_command_failed_to_run() {
    let p = ScriptedPrompt::new(full_prompt_values());
    let r = FakeRunner {
        err: Some("spawn failed".into()),
        ..Default::default()
    };
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    let err = expect_err(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "runner hatasi yayilMALI",
    );
    // Go: runWithInjectedEnv -> `fmt.Errorf("exec: %w", runErr)` — KODSUZ.
    let msg = as_plain(&err);
    assert!(
        msg.contains("spawn failed"),
        "runner hatasi yayilmali: {msg}"
    );
    let se = String::from_utf8_lossy(&errw).to_string();
    assert!(
        !se.contains("BURN NOW"),
        "komut calismadiginda epilogue BASILMAMALI"
    );
}

#[test]
fn a_prompt_error_names_the_var_and_spawns_nothing() {
    let mut p = ScriptedPrompt::new(full_prompt_values());
    p.err = Some("tty closed".into());
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    let err = expect_err(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "prompt hatasi bekleniyor",
    );
    let e = as_cli(&err);
    assert_eq!(e.code, Code::Internal);
    assert!(
        e.message.contains("AWS_ACCESS_KEY_ID"),
        "hata OKUNAN degiskeni soylemeli: {e}"
    );
    assert!(
        e.message.contains("tty closed"),
        "alttaki hata metni korunmali: {e}"
    );
    assert_eq!(
        *r.got_name.borrow(),
        "",
        "prompt hatasindan sonra spawn EDILMEMELI"
    );
}

// --- exit-kodu ---------------------------------------------------------------------

/// Sifir-disi cocuk cikis kodu cagirana AYNEN dondurulur (Go'da os.Exit;
/// Rust'ta ExitAction::Exit — surecten cikmak main'in isi).
#[test]
fn a_nonzero_child_exit_code_is_handed_back_to_the_caller() {
    let p = ScriptedPrompt::new(full_prompt_values());
    let r = FakeRunner {
        code: 7,
        ..Default::default()
    };
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    let action = expect_ok(
        drverb::run_bootstrap_core(
            &["tofu".into(), "apply".into()],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "sifir-disi cikis bir HATA degil",
    );
    assert!(
        matches!(action, ExitAction::Exit(7)),
        "cikis kodu 7 AYNEN yansimali"
    );
    let se = String::from_utf8_lossy(&errw).to_string();
    assert!(
        !se.contains("BURN NOW"),
        "basarisiz apply'da epilogue BASILMAMALI"
    );
}

// --- arite ---------------------------------------------------------------------------

#[test]
fn empty_args_error_without_prompting() {
    let p = ScriptedPrompt::new(full_prompt_values());
    let r = FakeRunner::default();
    let (mut out, mut errw) = (Vec::new(), Vec::new());
    let err = expect_err(
        drverb::run_bootstrap_core(
            &[],
            &[],
            false,
            false,
            &mut out,
            &mut errw,
            &empty_lookup,
            &|s| p.call(s),
            &|n, a, e, o, er| r.run(n, a, e, o, er),
        ),
        "komutsuz cagri hata vermeli",
    );
    assert_eq!(as_cli(&err).code, Code::Internal);
    assert!(
        p.calls().is_empty(),
        "komut yokken prompt atesleMEMELI: {:?}",
        p.calls()
    );
}
