// HER FIILIN AJAN-MODU POLITIKASI — ve bu dosyanin differential'dan AYRI
// durmasinin sebebi.
//
// Differential vakalari BAYT karsilastiriyor: "iki ikili ayni seyi yapiyor
// mu?" Bu dosya baska bir soru soruyor: "yaptiklari sey DOGRU MU?" Bir vaka
// listesinden silinirse differential yine yesil kalir (yalnizca sayac duser);
// buradaki iddialar kapinin KENDISINI adlandiriyor, yani Go'nun politikasi
// degisirse VEYA Rust ayrisirsa kirilir.
//
// Olculen tablo (kaynagi: cmd/secrets/agentgate.go agentPolicy + bindingExempt,
// ve cmd/secrets/projects.go'nun kok mount'u):
//
//   fiil            ajan politikasi   baglama kapisi
//   ------------    ---------------   -----------------------
//   list            allow             VAR
//   status          allow             MUAF
//   rm              refuse_agent      (erisilemez: kapi 1 once reddediyor)
//   projects list   allow             YOK — kok mount
//   projects rm     control           YOK — kok mount
//   init            allow             VAR, ve YAZIMDAN ONCE
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
    let d = std::env::temp_dir().join(format!("wapps-verbpolicy-{}", std::process::id()));
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

fn measure(bin: &Path, work: &Path, out: &Path) -> serde_json::Value {
    let pty_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty");
    run(
        Command::new("python3")
            .arg(pty_dir.join("verbpolicy.py"))
            .arg(bin)
            .arg(out)
            .arg(work),
        "fiil politikasi olcumu",
    );
    serde_json::from_str(&std::fs::read_to_string(out).expect("olcum okunamadi"))
        .expect("olcum cozulemedi")
}

fn obs<'a>(v: &'a serde_json::Value, key: &str) -> (&'a str, i64) {
    let o = v.get(key).unwrap_or_else(|| panic!("{key} gozlemi yok"));
    (
        o.get("stderr").and_then(|s| s.as_str()).unwrap_or(""),
        o.get("exit").and_then(|c| c.as_i64()).unwrap_or(-1),
    )
}

fn assert_policies(v: &serde_json::Value, side: &str) {
    // list: `allow`, ama baglama kapisi VAR → ciplak --project + ajan
    // fail-closed.
    let (err, code) = obs(v, "secrets_list");
    assert!(
        err.contains("BINDING_UNPINNED") && code == 1,
        "[{side}] secrets list ajan modunda baglama kapisina takilmali.\nstderr: {err:?}"
    );

    // status: `allow` VE baglama-MUAF → pinlenmemis bir config'in yaninda bile
    // basarili. "Her modda guvenli" vaadi tam olarak bu.
    let (err, code) = obs(v, "secrets_status");
    assert!(
        code == 0,
        "[{side}] secrets status HICBIR kosulda hard-fail etmemeli.\nstderr: {err:?}"
    );

    // rm: `refuse_agent` — silme geri alinamaz.
    let (err, code) = obs(v, "secrets_rm");
    assert!(
        err.contains("AGENT_MODE_REFUSED") && code == 1,
        "[{side}] secrets rm ajan modunda YAPISAL olarak reddedilmeli.\nstderr: {err:?}"
    );

    // projects list: KOK mount → baglama kapisi HIC yok. Bir ustteki
    // secrets_list ile AYNI bayrak, FARKLI sonuc: carpici olan bu.
    let (err, code) = obs(v, "projects_list");
    assert!(
        code == 0,
        "[{side}] projects list kokte mount'lu; baglama kapisi KOSMAMALI.\nstderr: {err:?}"
    );

    // projects rm: kontrol duzlemi — rm'in AGENT_MODE_REFUSED'i DEGIL.
    let (err, code) = obs(v, "projects_rm");
    assert!(
        err.contains("CONTROL_PLANE_REQUIRED") && code == 1,
        "[{side}] projects rm ajan modunda CONTROL_PLANE_REQUIRED almali.\nstderr: {err:?}"
    );

    // init: baglama kapisi YAZIMDAN ONCE ates ediyor.
    let (err, code) = obs(v, "secrets_init");
    assert!(
        err.contains("BINDING_UNPINNED") && code == 1,
        "[{side}] secrets init YAZMADAN once baglama kapisina takilmali.\nstderr: {err:?}"
    );
}

#[test]
fn both_binaries_apply_the_same_per_verb_agent_policy() {
    let root = repo_root();
    let work = scratch();

    // Oracle'i kaynaktan derle — sahadaki sozlesme Go'nun BUGUNKU davranisi.
    let go_bin = work.join("wapps-go");
    run(
        Command::new("go").arg("build").arg("-o").arg(&go_bin).arg("./main.go").current_dir(&root),
        "go build (oracle)",
    );

    let go = measure(&go_bin, &work, &work.join("policy-go.json"));
    assert_policies(&go, "go");

    let rs = measure(Path::new(env!("CARGO_BIN_EXE_wapps")), &work, &work.join("policy-rs.json"));
    assert_policies(&rs, "rust");

    let _ = std::fs::remove_dir_all(&work);
}
