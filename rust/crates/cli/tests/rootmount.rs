// KOKE MOUNT'LU FIILLERIN KENDI KAPILARI — ve neden bu bir IDDIA testi.
//
// `wapps rotate skip` KOKE mount'lu (`rootCmd.AddCommand(RotateCmd)`), yani
// `SecretsCmd.PersistentPreRunE` — `agentPolicy` tablosunu okuyan ve HER
// secrets fiilini gate'leyen hook — bu komut icin HIC kosmuyor. Onu ajandan
// koruyan TEK sey `RunE`nin ICINE ELLE yazilmis `is_agent()` kontrolu.
//
// NEDEN BU DOSYA VAR: o kontrol SILINEBILIR gorunuyor. Komut eskiden yetkili
// GORUNEN bir `Annotations: {wapps_agent_policy: refuse_agent}` da tasiyordu.
// Annotation OLUYDU — `wapps_agent_policy`nin uretim kodunda SIFIR okuyucusu
// vardi — ama onu goren biri makul bir cikarim yapardi: "annotation zaten
// reddediyor, bu kontrol fazladan". Annotation'i silmek HICBIR seyi
// degistirmezdi; ELLE yazilmis kontrolu silmek kapiyi ACARDI. Farki bugun
// hicbir sey yazmiyordu. Artik bu test yaziyor.
//
// NEDEN IDDIA, KARSILASTIRMA DEGIL: pty differential iki ikilinin PAYLASTIGI
// bir kusuru GOREMEZ — olctugu sey "ikisi ayni mi", "ikisi dogru mu" degil.
// Kontrolu iki tarafta da silmek differential'i YESIL birakirdi. O yuzden
// asagidaki test her ikiliyi AYRI AYRI ele aliyor ve BEKLENEN kodu ADIYLA
// soyluyor; iki ikiliyi birbiriyle KARSILASTIRMIYOR.
//
// Go karsiligi: cmd/secrets/rotate_skip_test.go.
//
// OLCULDU ve BIR SONRAKI KALEMIN TOHUMU: koke mount'lu UC fiil, UC FARKLI
// davranis. `tofu` kapinin TAMAMINI elle yeniden uyguluyor (guard + binding),
// `rotate skip` YALNIZCA ajan reddini, `doctor` HICBIR SEY. "Koke mount'lu"
// tek basina hicbir sey soylemiyor. Bu tur COZULMEDI; olcum
// `the_three_root_mounted_verbs_do_not_share_a_gate`de duruyor.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

// scratch, depo AGACININ DISINDA bir calisma dizini verir. Depo agacinin
// icine duserse bu deponun binding testleri dokunulmamis bir agacta bile
// kirilir — olculmus bir tuzak.
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-rootmount-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch olusturulamadi");
    assert!(
        !d.starts_with(repo_root()),
        "scratch dizini depo agacinin ICINDE ({}); binding testleri kirilir",
        d.display()
    );
    d
}

fn go_oracle(work: &Path) -> PathBuf {
    let bin = work.join("wapps-go");
    let out = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./main.go")
        .current_dir(repo_root())
        .output()
        .expect("go build calistirilamadi");
    assert!(
        out.status.success(),
        "go build (oracle) basarisiz:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

// run_agent, ikiliyi AJAN modunda kosar.
//
// stdin BORU (Stdio::null) → `is_agent()` non-TTY stdin'i DAIMA ajan sayiyor,
// yani ajan dali boru uzerinden ERISILEBILIR. (Tersi gecerli DEGIL: INSAN
// dali boru uzerinden hic kosmaz, ve differential o yuzden pty kullaniyor.
// Burada olculen dal ajan dali oldugu icin boru DOGRU arac.)
fn run_agent(bin: &Path, args: &[&str], work: &Path) -> (String, i32) {
    let out = Command::new(bin)
        .args(args)
        .current_dir(work)
        .env("CLAUDECODE", "1")
        .env("XDG_CONFIG_HOME", work.join("xdg"))
        .env("WAPPS_SESSION_TOKEN", "")
        .env("CF_ACCESS_CLIENT_ID", "")
        .env("CF_ACCESS_CLIENT_SECRET", "")
        // HOME is inherited here, and the skill auto-refresh runs after every
        // command, agent mode included: without the opt-out both binaries
        // could rewrite the developer's real ~/.config/wapps/skills.
        .env("WAPPS_NO_UPDATE_CHECK", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("ikili calistirilamadi");
    (
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn rotate_skip_refuses_an_agent_in_both_binaries() {
    let work = scratch("skip");
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));

    for (side, bin) in [("go", &go), ("rust", &rs)] {
        let (stderr, code) = run_agent(
            bin,
            &[
                "rotate",
                "skip",
                "run-1",
                "SOME_KEY",
                "--reason",
                "value is a public constant",
            ],
            &work,
        );
        // IDDIA: beklenen kod ADIYLA yaziliyor. Diger ikiliye BAKILMIYOR.
        assert!(
            stderr.contains("AGENT_MODE_REFUSED"),
            "[{side}] `rotate skip` bir ajani REDDETMELI. Bu fiil KOKE mount'lu, \
             yani PersistentPreRunE kosmuyor ve onu koruyan TEK sey RunE'nin \
             icindeki elle yazilmis is_agent() kontrolu. O kontrol silindiyse \
             `wapps rotate skip` ajanlara ACILMIS demektir.\nolculen stderr: {stderr:?}"
        );
        assert_eq!(code, 1, "[{side}] ret cikis kodu 1 olmali");
        // Ret AJAN kapisindan gelmeli, "motor hazir degil"den DEGIL: ikisi de
        // sifirdan farkli cikiyor, yani kod tek basina ayirt etmiyor.
        assert!(
            !stderr.contains("ACTION_UNAVAILABLE"),
            "[{side}] ajan kapisi ACTION_UNAVAILABLE'a DUSMUS — kapi asilmis.\n{stderr:?}"
        );
    }
}

// the_three_root_mounted_verbs_do_not_share_a_gate, "koke mount'lu"nun tek
// basina HICBIR SEY soylemedigini olcer.
//
// Bu bir COZUM degil, bir OLCUM: uc fiil de PersistentPreRunE'un disinda, ama
// ucu de FARKLI davraniyor. Birinden digerini tahmin eden bir okuyucu yanilir.
// Tur cozulunce bu test tutarliligi ifade edecek sekilde degisir; bugun
// FARKLILIGI pinliyor ki fark SESSIZCE kaymasin.
#[test]
fn the_three_root_mounted_verbs_do_not_share_a_gate() {
    let work = scratch("three");
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));

    for (side, bin) in [("go", &go), ("rust", &rs)] {
        // `rotate skip`: ajan REDDEDILIR (elle yazilmis kontrol).
        let (s, _) = run_agent(bin, &["rotate", "skip", "r", "K", "--reason", "x"], &work);
        assert!(
            s.contains("AGENT_MODE_REFUSED"),
            "[{side}] rotate skip: {s:?}"
        );

        // `tofu`: ajan SERBEST (PolicyAllow) ama BAGLAMA kapisi elle yeniden
        // uygulanmis → pinsiz bir agacta BINDING_UNPINNED ile duser. Yani
        // `rotate skip`ten FARKLI bir kapi, ve o kapi ajan reddi DEGIL.
        let (s, _) = run_agent(bin, &["tofu", "plan"], &work);
        assert!(
            !s.contains("AGENT_MODE_REFUSED"),
            "[{side}] tofu ajani REDDETMEMELI (PolicyAllow): {s:?}"
        );

        // `doctor`: HICBIR kapi yok — ajan modunda KOSAR.
        //
        // DIKKAT, olculdu: bos bir scratch dizininde doctor 1 ile cikiyor ama
        // bu bir KAPI DEGIL — kendi kontrollerinin basarisiz olmasi
        // ("doctor reported failures", INTERNAL). Yani cikis kodu tek basina
        // "gate'lendi mi" sorusunu AYIRT ETMIYOR; ayirt eden sey KOD.
        // Ilk yazimda burasi `code == 0` bekliyordu ve bu YANLISTI: varsayim
        // olculmeden yazilmisti.
        let (s, _) = run_agent(bin, &["doctor"], &work);
        assert!(
            !s.contains("AGENT_MODE_REFUSED") && !s.contains("BINDING_UNPINNED"),
            "[{side}] doctor'un ajan/baglama kapisi YOK; biri eklendiyse bu \
             dosyanin ust yorumu artik yanlis: {s:?}"
        );
    }
}
