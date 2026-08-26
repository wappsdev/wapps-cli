// TESHIS CIKTISI BIR KIMLIK BILGISI TASIMAZ — ve bu test DIFFERENTIAL'DA
// OLAMAZ.
//
// Sebep tek cumlede: differential IKI IKILIYI KARSILASTIRIYOR. Ikisi de ayni
// jetonu sizdirsaydi baytlar esit olurdu, vaka YESIL gecerdi ve olculen sey
// "ikisi de ayni sekilde sizdiriyor" olurdu. Bir sizinti testi bir
// KARSILASTIRMA degil bir IDDIA olmak zorunda, ve iddia IKI ikili icin de ayri
// ayri kosuyor: Go tarafi ORACLE oldugu icin onun da temiz oldugu KANITLANMALI,
// yoksa "Go da boyle yapiyor" savunmasi bir sizintiyi mesrulastirirdi.
//
// `doctor` NEDEN bu testi hak ediyor: fiil bir CF Access oturum jetonunu
// (WAPPS_SESSION_TOKEN / session/<host>.json), bir CI service-token ciftini ve
// bir makine jetonunu OKUYOR. Ciktisi bir OPERATOR ARAYUZU ve operatorler
// teshis ciktisini issue'lara, sohbetlere ve CI loglarina YAPISTIRIR. Sizan
// bir jeton oraya gider.
//
// Buradaki degerlerin hicbiri gercek bir sir DEGIL: hepsi "canary" onekli
// uydurma dizeler ve gercek bir gate'e HIC baglanilmiyor.
use std::path::{Path, PathBuf};
use std::process::Command;

// KANARYALAR: her biri farkli bir kimlik yuzeyinden geliyor. Ayirt edici
// olmalari sart — ciktida rastlantiyla bulunacak bir dize olmamalilar.
const CANARIES: &[(&str, &str)] = &[
    ("WAPPS_SESSION_TOKEN", "canary-session-3f9a-not-a-real-secret"),
    ("CF_ACCESS_CLIENT_ID", "canary-clientid-7c21-not-a-real-secret"),
    ("CF_ACCESS_CLIENT_SECRET", "canary-clientsecret-b48e-not-a-real-secret"),
    ("WAPPS_MACHINE_TOKEN", "canary-machine-d17f-not-a-real-secret"),
    ("TF_VAR_state_passphrase", "canary-passphrase-a6b0-not-a-real-secret"),
    ("AWS_SECRET_ACCESS_KEY", "canary-awssecret-e52c-not-a-real-secret"),
    ("AWS_ACCESS_KEY_ID", "canary-awskeyid-91d3-not-a-real-secret"),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-doctorleak-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("scratch olusturulamadi");
    assert!(
        !d.starts_with(repo_root()),
        "scratch dizini depo agacinin ICINDE ({})",
        d.display()
    );
    d
}

// observe, bir ikiliyi verilen `--for` modunda kosar ve stdout+stderr'i tek
// bir dizede birlestirir. Ikisi de operatorun GORDUGU sey, o yuzden ikisi de
// aranıyor.
fn observe(bin: &Path, work: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", work)
        .env("XDG_CONFIG_HOME", work.join("xdgcfg"))
        .env("WAPPS_NO_UPDATE_CHECK", "1")
        // Ag'a CIKILMASIN: ulasilamayan bir taban, probu tasima hatasina
        // dusurur ve o dal da ciktinin bir parcasi (URL'i basiyor).
        .env("COOLIFY_URL", "http://127.0.0.1:1")
        .env("WAPPS_SECRETS_GATE", "http://127.0.0.1:1")
        // Sure BILINEN bir oturum: "canli (TTL)" dali da gezilsin.
        .env("WAPPS_SESSION_EXPIRES", "4102444800");
    for (k, v) in CANARIES {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("{} kosturulamadi: {e}", bin.display()));
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_no_canary(text: &str, side: &str, args: &[&str]) {
    for (name, value) in CANARIES {
        assert!(
            !text.contains(value),
            "[{side}] `wapps {}` ciktisi {name} DEGERINI sizdirdi.\n\
             Teshis ciktisi bir operator arayuzudur ve issue'lara/CI loglarina yapistirilir;\n\
             oraya bir kimlik bilgisi giremez.\n--- cikti ---\n{text}",
            args.join(" ")
        );
    }
}

// Uc mod da ayri ayri geziliyor: tam batarya (oturum satirlari + service-token
// yolu), `--for tofu` (env kontrati — DEGERLERE bakiyor, o yuzden en riskli
// dal), ve bilinmeyen mod (kullanici girdisini mesaja gomen dal).
const MODES: &[&[&str]] = &[
    &["doctor"],
    &["doctor", "--for", "all"],
    &["doctor", "--for", "tofu"],
    &["doctor", "--for", "wat"],
];

#[test]
fn neither_binary_prints_a_credential_it_reads() {
    let root = repo_root();
    let work = scratch();
    std::fs::create_dir_all(work.join("xdgcfg")).expect("xdg olusturulamadi");

    // ORACLE'I DA SINA: Go tarafi bu portun referansi, ve bir sizinti orada da
    // olsaydi "Go da boyle yapiyor" bir savunma OLMAZDI — bir BULGU olurdu.
    let go_bin = work.join("wapps-go");
    let built = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&go_bin)
        .arg("./main.go")
        .current_dir(&root)
        .output()
        .expect("go build kosturulamadi");
    assert!(
        built.status.success(),
        "go build (oracle) basarisiz:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );

    for args in MODES {
        assert_no_canary(&observe(&go_bin, &work, args), "go", args);
        assert_no_canary(
            &observe(Path::new(env!("CARGO_BIN_EXE_wapps")), &work, args),
            "rust",
            args,
        );
    }

    // Olcumun GERCEKTEN bir sey gezdiginin kaniti: bos bir cikti da "sizinti
    // yok" derdi. Tam batarya en az bir teshis satiri basmis olmali.
    let text = observe(Path::new(env!("CARGO_BIN_EXE_wapps")), &work, &["doctor"]);
    assert!(
        text.contains("secrets-gate session"),
        "doctor bir oturum satiri basmali; aksi halde bu test BOS gezmis olur:\n{text}"
    );
    // ...ve o satir jetonun VARLIGINI bildirmeli, KENDISINI degil.
    assert!(
        text.contains("session live"),
        "gecerli bir oturum 'live' olarak raporlanmali:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&work);
}
