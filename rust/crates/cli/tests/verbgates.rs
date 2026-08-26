// exec/apply'in onundeki IKI KAPI — artik IKI IKILIDE de.
//
// TARIHCE, cunku bu dosyanin ANLAMI degisti: onceki dilim bu testi
// "exec/apply NEDEN portlanmadi"yi olcmek icin yazmisti. Onlerinde iki
// portlanmamis altsistem duruyordu:
//
//   1. `--project` bu iki verb icin config gereksinimini ATLATMIYOR. get/set
//      Go'da storeProject kullaniyor (proje ADI yeter); exec/apply
//      requireStoreConfig kullaniyor ve `.wapps.yaml` SART.
//   2. `.wapps.yaml` varken `--project` verilmezse depo→proje baglamasi
//      ETKILESIMLI onay istiyor.
//
// Bu dilim iki altsistemi de indirdi (wappsyaml, binding) ve verb'leri
// bagladi. Test artik "portlanmadi"yi degil, KAPILARIN IKI IKILIDE DE AYNI
// OLDUGUNU olcuyor — yani Go'nun kapisi kalkarsa VEYA Rust'inki ayrisirsa
// kirilir.
//
// Kapilarin BAYT duzeyindeki karsilastirmasi differential'da
// (human/agent_exec_project_flag_no_config, *_config_unpinned,
// human_exec_binding_declined/accepted). Buradaki test, o vakalarin
// olculmesinden BAGIMSIZ olarak kapinin KENDISINI adlandirir: differential'in
// vaka listesinden biri silinse bu test yine de duser.
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

fn stderr_of(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|o| o.get("stderr"))
        .and_then(|s| s.as_str())
        .unwrap_or_else(|| panic!("{key} gozlemi yok"))
        .to_string()
}

// measure, verilen ikiliyi kapi olcum betiginden gecirir.
fn measure(bin: &Path, work: &Path, out: &Path) -> serde_json::Value {
    let pty_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty");
    run(
        Command::new("python3")
            .arg(pty_dir.join("verbgates.py"))
            .arg(bin)
            .arg(out)
            .arg(work),
        "verb kapisi olcumu",
    );
    let raw = std::fs::read_to_string(out).expect("olcum okunamadi");
    serde_json::from_str(&raw).expect("olcum cozulemedi")
}

// assert_gates, bir olcum uzerinde IKI kapiyi da dogrular.
fn assert_gates(v: &serde_json::Value, side: &str) {
    for verb in ["exec", "apply"] {
        // KAPI 1: --project config gereksinimini ATLATMIYOR.
        let s = stderr_of(v, &format!("{verb}_project_flag_no_config"));
        assert!(
            s.contains(&format!("{verb}: no .wapps.yaml found")),
            "[{side}] {verb}: --project ile config kapisi asilmis gorunuyor.\n\
             olculen stderr: {s:?}"
        );

        // KAPI 2: config var, --project yok -> ETKILESIMLI baglama onayi.
        let s = stderr_of(v, &format!("{verb}_config_no_project"));
        assert!(
            s.contains("not bound to a project yet") && s.contains("Bind them?"),
            "[{side}] {verb}: baglama onayi artik istenmiyor.\nolculen stderr: {s:?}"
        );
    }
}

#[test]
fn both_binaries_gate_exec_and_apply_the_same_way() {
    let root = repo_root();
    let work = scratch();

    // Oracle'i kaynaktan derle — sahadaki sozlesme Go'nun BUGUNKU davranisi.
    let go_bin = work.join("wapps-go");
    run(
        Command::new("go").arg("build").arg("-o").arg(&go_bin).arg("./main.go").current_dir(&root),
        "go build (oracle)",
    );

    let go = measure(&go_bin, &work, &work.join("gates-go.json"));
    assert_gates(&go, "go");

    // Ayni kapilar PORTLANMIS ikilide de duruyor mu. Bu satir, bu dilimin
    // getirdigi sey: onceki dilimde olculecek bir Rust tarafi YOKTU.
    let rs = measure(Path::new(env!("CARGO_BIN_EXE_wapps")), &work, &work.join("gates-rs.json"));
    assert_gates(&rs, "rust");

    let _ = std::fs::remove_dir_all(&work);
}
