// YANKISIZ OKUMA gate'i: `secrets set`in degeri terminale dusurmedigini olcer.
//
// Bu dosya bir MUTASYON BULGUSUNUN sonucudur, bastan tasarlanmis bir test
// degil. differential.rs'in 60 vakasi `set`in prompt yolunu geziyor ama ECHO
// bitini OLCMUYOR: ptyrun.py uc slave'in de ECHO'sunu spawn'dan once kapatiyor
// ve stdin master'ini hic okumuyor. ECHO kapatmasini tamamen SILEN bir mutasyon
// denendi ve differential YESIL kaldi (EQUAL=60 DIFFERENT=0) — yani o yuzey
// olculmemisti. Bu test onu olcer: stdin pty'sinde ECHO ACIK biraklyor, yani
// degeri gizlemek tamamen ikilinin isi.
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
    let d = std::env::temp_dir().join(format!("wapps-noecho-{}", std::process::id()));
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

fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":");
    let i = json.find(&pat).unwrap_or_else(|| panic!("{key} yok: {json}")) + pat.len();
    let rest = json[i..].trim_start();
    let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

#[test]
fn set_never_echoes_the_typed_value_to_the_terminal() {
    let root = repo_root();
    let work = scratch();
    let pty_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty");

    let go_bin = work.join("wapps-go");
    run(
        Command::new("go").arg("build").arg("-o").arg(&go_bin).arg("./main.go").current_dir(&root),
        "go build (oracle)",
    );

    let mut seen = Vec::new();
    for (label, bin) in
        [("go", go_bin.as_path()), ("rust", Path::new(env!("CARGO_BIN_EXE_wapps")))]
    {
        let out = work.join(format!("{label}.json"));
        run(
            Command::new("python3")
                .arg(pty_dir.join("noecho.py"))
                .arg(bin)
                .arg(&out)
                .arg(&work),
            &format!("noecho olcumu ({label})"),
        );
        let raw = std::fs::read_to_string(&out).expect("olcum okunamadi");
        let echo_off = field(&raw, "echo_off").to_string();
        let echoed = field(&raw, "stdin_echo_hex").to_string();
        let code = field(&raw, "exit").to_string();

        // 1) Deger okunmadan ONCE ECHO kapatilmis olmali.
        assert_eq!(
            echo_off, "true",
            "{label}: deger okunmadan once ECHO kapatilmadi — yazilan sir terminale duser"
        );
        // 2) Terminal yazilan baytlardan HICBIRINI geri yankilamamis olmali.
        assert!(
            echoed.is_empty(),
            "{label}: terminal {} bayt geri yankiladi; yazilan deger transcript'e dustu",
            echoed.len() / 2
        );
        seen.push((echo_off, echoed, code));
    }

    // 3) Ve iki ikili bu yuzeyde AYNI davranmali (Go oracle).
    assert_eq!(seen[0], seen[1], "go ve rust yankisiz-okuma yuzeyinde ayrisiyor");
    let _ = std::fs::remove_dir_all(&work);
}
