// BASILAN JETON: NEREYE GITTIGI ve NEREYE GITMEDIGI.
//
// `token exchange` bu portun BIR SIR BASAN tek fiili, ve bu testin
// differential'da OLAMAYACAK bir sebebi var — `doctorleak.rs` ile aynisi: iki
// ikili de jetonu ayni sekilde bozsaydi (ya da ayni sekilde sizdirsaydi)
// baytlar ESIT olurdu, vaka yesil gecerdi ve olculen sey "ikisi de ayni sekilde
// yanlis" olurdu. Bir sizinti/bozulma testi bir KARSILASTIRMA degil bir IDDIA
// olmak zorunda.
//
// UC IDDIA VE UCU DE AYRI:
//
//  1. JETON HAM BASILIYOR. Fiilin var olma sebebi bu: pipeline adimi stdout'u
//     YAKALIYOR ve `WAPPS_MACHINE_TOKEN`e koyuyor. Redakte edilmis bir jeton
//     sessizce ise yaramaz bir jetondur.
//
//  2. BASILAN SEY GERCEKTEN REDAKSIYON YEMI. Bu satir olmadan (1) bos bir
//     iddia olurdu: "bozulmadi" demek, ancak "bozulacak SEKILDE" oldugu
//     olculunce bir sey ifade eder. `safelog::redact_patterns` bu baytlari
//     `[REDACTED]` yapiyor, `scrubber::is_scrubbable` de onlari redakte
//     edilebilir kabul ediyor — yani jeton, bu ikilinin BASKA yuzeylerde
//     maskeledigi sinifin tam ortasinda.
//
//  3. JETON STDERR'E HIC GIRMIYOR. Metadata satiri stderr'e gidiyor ve orada
//     yalnizca ZAMAN var; jetonun kendisi ne oraya, ne bir hata metnine, ne
//     bir dosyaya. Hata dalinda da ayni: gate reddi jetonu tasimaz.
//
// GERCEK SIR YOK: sahte gate'in urettigi "jeton" uydurma bir test dizesidir ve
// gercek bir gate'e HIC baglanilmaz.
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
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
    let d = std::env::temp_dir().join(format!("wapps-tokenleak-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("scratch olusturulamadi");
    assert!(
        !d.starts_with(repo_root()),
        "scratch dizini depo agacinin ICINDE ({})",
        d.display()
    );
    d
}

// MINTED, sahte gate'in dondugu jeton. JWT-BICIMLI ve bu bir susleme DEGIL:
// safelog'un JWT deseni (`{8,}\.{8,}\.{8,}`) tam olarak bu sekli yakaliyor.
const MINTED: &str =
    "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3Qta2lkIn0.eyJwcm9qZWN0IjoidGVzdHByb2oifQ.c2lnbmF0dXJlLXBsYWNlaG9sZGVy";

// EXP, metadata satirinin zaman damgasi.
const EXP: i64 = 1793318400;

// gate, TEK bir `POST /v1/token` istegine cevap veren en kucuk sunucudur.
//
// NEDEN `fakegate.py` DEGIL: bu test bir KARSILASTIRMA degil bir IDDIA, yani
// differential harness'inin senaryo makinesine ihtiyaci yok. Tek istegi
// burada karsilamak, testin kendi jeton baytlarini SABITLEMESINI de sagliyor —
// yukaridaki `MINTED` sabiti hem gate'in yaniti hem iddianin girdisi.
fn gate(body: String) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("port alinamadi");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        serve_one(stream, &body);
    });
    (port, handle)
}

fn serve_one(mut stream: TcpStream, body: &str) {
    let mut reader = BufReader::new(stream.try_clone().expect("stream klonlanamadi"));
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    // Govde OKUNUYOR ama SAKLANMIYOR — istemci yazimi tamamlayabilsin diye.
    let mut sink = vec![0u8; len];
    use std::io::Read;
    let _ = reader.read_exact(&mut sink);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn exchange(bin: &Path, work: &Path, port: u16) -> (String, String, bool) {
    let out = Command::new(bin)
        .args(["token", "exchange", "--project", "testproj", "--key", "K"])
        .current_dir(work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", work)
        .env("XDG_CONFIG_HOME", work.join("xdgcfg"))
        .env("WAPPS_NO_UPDATE_CHECK", "1")
        .env("WAPPS_SECRETS_GATE", format!("http://127.0.0.1:{port}"))
        .env("CF_ACCESS_CLIENT_ID", "canary-clientid-not-a-real-secret")
        .env(
            "CF_ACCESS_CLIENT_SECRET",
            "canary-clientsecret-not-a-real-secret",
        )
        .output()
        .unwrap_or_else(|e| panic!("{} kosturulamadi: {e}", bin.display()));
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

// IDDIA 2 — ONCE, cunku digerlerinin ANLAMI buna bagli. Bu iddia AG'A
// CIKMIYOR: yalnizca baytlarin sinifini olcuyor.
#[test]
fn the_minted_token_is_exactly_the_shape_this_binary_redacts_elsewhere() {
    assert_eq!(
        wapps::safelog::redact_patterns(MINTED),
        "[REDACTED]",
        "jeton, safelog'un JWT desenine UYMALI — uymazsa 'redakte edilmedi' \
         iddiasi bos bir iddia olur"
    );
    assert!(
        wapps::scrubber::is_scrubbable(MINTED),
        "jeton, exec scrubber'inin redakte edilebilir saydigi sinifta OLMALI"
    );
    // ...ve zarf yolu onu GERCEKTEN maskeliyor: mesaja giren bir jeton
    // `[REDACTED]` olarak cikar. Yani asagidaki "stdout ham" iddiasi bir
    // ihmal degil, YOLA OZGU bir karar.
    let e = wapps::clierr::Error::new(wapps::clierr::Code::Internal, format!("oops {MINTED}"));
    let mut buf = Vec::new();
    wapps::clierr::emit(&mut buf, &e);
    let envelope = String::from_utf8(buf).unwrap();
    assert!(
        !envelope.contains(MINTED),
        "zarf yolu jetonu maskelemeli: {envelope}"
    );
    assert!(
        envelope.contains("[REDACTED]"),
        "zarf yolu [REDACTED] basmali: {envelope}"
    );
}

// IDDIA 1 ve 3, IKI IKILI ICIN DE. Oracle da sinaniyor: Go tarafi jetonu
// bozsaydi ya da stderr'e dusurseydi bu bir savunma degil bir BULGU olurdu.
#[test]
fn both_binaries_print_the_token_raw_on_stdout_and_never_on_stderr() {
    let root = repo_root();
    let work = scratch();
    std::fs::create_dir_all(work.join("xdgcfg")).expect("xdg olusturulamadi");

    let go_bin = work.join("wapps-go");
    let built = Command::new("go")
        .args(["build", "-o"])
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

    let body = format!(r#"{{"token":"{MINTED}","exp":{EXP}}}"#);
    for (side, bin) in [
        ("go", go_bin.as_path()),
        ("rust", Path::new(env!("CARGO_BIN_EXE_wapps"))),
    ] {
        let (port, server) = gate(body.clone());
        let (stdout, stderr, ok) = exchange(bin, &work, port);
        let _ = server.join();

        assert!(ok, "[{side}] mint basarisiz olmamaliydi\nstderr: {stderr}");
        // (1) HAM ve TEK BASINA: sonda tek bir newline, baska hicbir sey.
        assert_eq!(
            stdout,
            format!("{MINTED}\n"),
            "[{side}] stdout jetonu HAM ve yalniz basina tasimali"
        );
        // (3) stderr jetonu TASIMAZ — ama BOS da degil: metadata satiri orada.
        assert!(
            !stderr.contains(MINTED),
            "[{side}] jeton stderr'e sizdi:\n{stderr}"
        );
        assert_eq!(
            stderr,
            format!("token expires at 2026-10-30T00:00:00Z (unix {EXP})\n"),
            "[{side}] stderr yalnizca zaman metadatasini tasimali"
        );
    }

    let _ = std::fs::remove_dir_all(&work);
}
