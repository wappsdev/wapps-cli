// pty DIFFERENTIAL: Go ikilisi ORACLE, olcum BAYT duzeyinde.
//
// NEDEN pty, BORU DEGIL — ve bu bir uslup tercihi degil, olcumun gecerliligi:
// agentmode::is_agent() stdin'in TTY olusuna bakiyor ve non-TTY stdin'i DAIMA
// ajan sayiyor. Yani boru ile kosan bir differential insan yolunu HIC
// calistiramaz; o yolun tamami olculmemis kalir ve port yesil GORUNUR. Uc ayri
// pty aciliyor (stdin/stdout/stderr): stdin TTY olsun diye, ve stdout ile
// stderr tek pty'de karisip bayt-bayt ayristirilamaz hale gelmesin diye.
//
// Gate SAHTE ve yereldir; gercek bir gate'e HIC baglanilmaz ve testte gecen
// hicbir deger gercek bir sir DEGILDIR.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // rust/crates/cli -> rust/crates -> rust -> depo koku
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

// scratch, depo AGACININ DISINDA bir calisma dizini verir. Bu kritik: scratch
// bir git worktree'nin icine duserse bu deponun binding testleri dokunulmamis
// bir agacta bile kiriliyor.
fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-pty-diff-{}", std::process::id()));
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

#[test]
fn go_and_rust_agree_byte_for_byte_under_a_pty() {
    let root = repo_root();
    let work = scratch();
    let pty_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty");

    // Oracle'i kaynaktan derle — sahadaki sozlesme Go'nun BUGUNKU davranisi.
    let go_bin = work.join("wapps-go");
    run(
        Command::new("go").arg("build").arg("-o").arg(&go_bin).arg("./main.go").current_dir(&root),
        "go build (oracle)",
    );

    let go_json = work.join("go-probe.json");
    let rs_json = work.join("rs-probe.json");
    for (bin, out) in [(go_bin.as_path(), &go_json), (Path::new(env!("CARGO_BIN_EXE_wapps")), &rs_json)]
    {
        run(
            Command::new("python3")
                .arg(pty_dir.join("probe.py"))
                .arg(bin)
                .arg(out)
                .arg(&work),
            &format!("pty probe ({})", bin.display()),
        );
    }

    let report = run(
        Command::new("python3").arg(pty_dir.join("diff.py")).arg(&go_json).arg(&rs_json),
        "bayt karsilastirmasi",
    );
    // Karsilastirmanin GERCEKTEN vaka gezdiginin kaniti: bos bir kume de
    // "fark yok" derdi. Taban 32 → 60 (`secrets set`) → 102 (`exec`/`apply`)
    // → 165: `list`, `status`, `rm`, `projects` ve `init` 63 vaka ekledi.
    // → 176: `trust-repo` 11 vaka ekledi.
    // → 194: `env` 18 vaka ekledi.
    // → 211: `import-env` 17 vaka ekledi.
    // → 244: `policy` (show/set/lint) 33 vaka ekledi.
    // → 257: `tofu` 13 vaka ekledi.
    // → 272: `rotate-plan` 15 vaka ekledi.
    //
    // Eklenen vakalarin AGIRLIK MERKEZI su soru: her fiilin ajan-modu
    // politikasi ne, ve kapi sirasi ne? Cevap fiil basina FARKLI (bkz.
    // cases.py'deki tablo) ve hicbiri digerinden tahmin edilemiyor —
    // `projects list` kokte mount'lu oldugu icin baglama kapisi HIC kosmuyor,
    // `rm`de arite ajan kapisindan ONCE kosuyor, `init`in kapisi YAZIMDAN once.
    //
    // Karsilastirilan alan sayisi da arttI: cikti/cikis/epoch-pini/repo-pins'e
    // ek olarak yazilan dosyalarin icerigi + modu — ve artik `.wapps.yaml`in
    // KENDISI de (init'in URETTIGI dosya o).
    let equal: usize = report
        .rsplit("EQUAL=")
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(equal >= 272, "differential yalnizca {equal} vaka gezdi:\n{report}");
    let _ = std::fs::remove_dir_all(&work);
}
