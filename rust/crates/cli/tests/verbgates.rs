// exec/apply'in NEDEN bu dilimde portlanmadigini OLCEN pin.
//
// Bu dilim `secrets set`i portladi. `secrets exec` ve `secrets apply` KASITLI
// olarak portlanmadi ve Rust komut agacina EKLENMEDI. Sebep bir gorus degil,
// asagida olculen iki kapi:
//
//   1. --project bu iki verb icin config gereksinimini ATLATMIYOR. get/set
//      Go'da storeProject kullaniyor (proje ADI yeter, yerel dosya gerekmez);
//      exec/apply requireStoreConfig kullaniyor ve .wapps.yaml SART.
//   2. .wapps.yaml varken --project verilmezse repo->proje baglamasi
//      ETKILESIMLI onay istiyor.
//
// Yani bu iki verb'un onunde IKI portlanmamis altsistem duruyor: .wapps.yaml
// yukleme + dogrulama (surum/backend matrisi, targets ve sources dogrulamasi —
// ve bir YAML ayristiricisi, yani bagimlilik politikasi karari) ve baglama pin
// defteri. Yarim portlanmis bir verb, portlanmamis bir verb'den KOTUDUR:
// sahada kurulu bir ikili var.
//
// Bu test yalnizca GO ikilisini olcer; kanitladigi sey sonraki dilimin ON
// KOSULU. Go tarafinda o kapilar kalkarsa test kirilir ve plani yazan kisi
// durumun degistigini gorur.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-verbgates-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("scratch olusturulamadi");
    assert!(
        !d.starts_with(repo_root()),
        "scratch dizini depo agacinin ICINDE ({}); binding testleri kirilir",
        d.display()
    );
    d
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what} calistirilamadi: {e}"));
    assert!(
        out.status.success(),
        "{what} basarisiz (exit {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

// stderr_of, olcum JSON'undan bir gozlemin stderr'ini cikarir (serde_json ile).
fn stderr_of(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|o| o.get("stderr"))
        .and_then(|s| s.as_str())
        .unwrap_or_else(|| panic!("{key} gozlemi yok"))
        .to_string()
}

#[test]
fn exec_and_apply_are_still_gated_behind_unported_subsystems() {
    let root = repo_root();
    let work = scratch();
    let pty_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty");

    let go_bin = work.join("wapps-go");
    run(
        Command::new("go").arg("build").arg("-o").arg(&go_bin).arg("./main.go").current_dir(&root),
        "go build (oracle)",
    );

    let out = work.join("gates.json");
    run(
        Command::new("python3")
            .arg(pty_dir.join("verbgates.py"))
            .arg(&go_bin)
            .arg(&out)
            .arg(&work),
        "verb kapisi olcumu",
    );
    let raw = std::fs::read_to_string(&out).expect("olcum okunamadi");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("olcum cozulemedi");

    for verb in ["exec", "apply"] {
        // KAPI 1: --project config gereksinimini atlatmiyor.
        let s = stderr_of(&v, &format!("{verb}_project_flag_no_config"));
        assert!(
            s.contains(&format!("{verb}: no .wapps.yaml found")),
            "{verb}: --project ile config kapisi asilmis gorunuyor — bu dilimin \
             premisi degisti, exec/apply artik config'siz portlanabilir olabilir.\n\
             olculen stderr: {s:?}"
        );

        // KAPI 2: config var, --project yok -> ETKILESIMLI baglama onayi.
        let s = stderr_of(&v, &format!("{verb}_config_no_project"));
        assert!(
            s.contains("not bound to a project yet") && s.contains("Bind them?"),
            "{verb}: baglama onayi artik istenmiyor — baglama altsistemi \
             degismis olabilir.\nolculen stderr: {s:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&work);
}
