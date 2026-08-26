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
    // → 282: `rotate skip` 10 vaka ekledi.
    // → 298: `doctor` 16 vaka ekledi.
    // → 300: `env --write`in atomicfile'a gecisi 2 vaka ekledi.
    // → 302: `set`in epoch pini 2 vaka ekledi (biri YENIDEN ADLANDIRILDI:
    //        human_set_leaves_pin_alone -> human_set_advances_the_pin, cunku
    //        pinlenen davranis YANLIS olcuye dayaniyordu).
    // → 305: `set`in config kolu 3 vaka ekledi. O kol HIC gezilmemisti; vakalar
    //        duzeltmeden ONCE DIFFERENT=3 raporladi (Go BINDING_UNPINNED,
    //        Rust NOT_FOUND) — yani bu uc vaka, epoch vakalarinin AKSINE,
    //        karsilastirma uzerinden GERCEKTEN bir kusur buldu.
    // → 311: `get`in config kolu 6 vaka ekledi ve AYNI hikaye tekrar etti:
    //        `get`in 21 vakasinin TAMAMI `--project testproj` geciriyordu,
    //        yani yapilandirma kolu hic gezilmemisti. Alti vakanin UCU
    //        duzeltmeden ONCE DIFFERENT=3 raporladi. Kalan uc vaka SIRA
    //        pinidir (ajan reddi baglama kapisindan once, config yoksa
    //        NOT_FOUND) ve ONCE de SONRA da esitti.
    //
    //        AYNI KOR NOKTA IKI KEZ CIKTI (once `set`, sonra `get`), ve
    //        sebebi yapisal: bir fiil icin YARDIMCI yazan (burada `h`/`a`/
    //        `hp`, hepsi `P = --project testproj` ekliyor) o fiilin
    //        yardimcisiz kolunu bir daha HIC gezmiyor. Yeni bir fiil
    //        portlanirken sorulacak soru: bu fiilin vakalarindan KACI
    //        `--project`siz?
    //
    //        `--config` de bu turda ILK KEZ olculdu: 309 vakalik korpusta
    //        o bayragin TEK bir vakasi yoktu ve Rust'in run_get'i onu hic
    //        almiyordu (sessizce yere dusuyordu).
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
    // → 339: `dr` 28 vaka ekledi (verify/split/combine). Yirmi yedisi
    //        `--project` GECMIYOR — bilerek: `dr` kokte mount'lu, Ctx hic
    //        cozulmuyor, yani bu fiilin GERCEK kolu bayraksiz olan. Bir
    //        `--project` yardimcisi yazmak, `set` ve `get`te iki kez cikan
    //        kor noktayi UCUNCU kez uretirdi. Bayragin ATIL oldugu ayrica
    //        olculuyor (dr_verify_project_flag_is_inert).
    //
    //        `dr split`in BASARILI yolu korpusta YOK ve olamaz: cikti RNG'ye
    //        bagli. Onun olcusu bir KARSILASTIRMA degil bir IDDIA —
    //        tests/cryptoid.rs frozen `rng_pattern_hex` ile paylari
    //        BAYT BAYT pinliyor. Ayni sebeple `dr`in kripto cekirdeginin
    //        tamami (HKDF, kid, GF(2^8)) iddia tarafinda olculuyor:
    //        differential iki ikilinin PAYLASTIGI bir kusuru goremez.
    //
    //        BU ESIK KORPUS BOYUYLA AYNI DEGIL, ve fark olculdu: `EXCLUDED`
    //        DORT ad tasiyor (ikisi cases.py'deki baslik yorumunda yazili,
    //        ikisi — human_policy_lint_broken_json ve
    //        human_rotate_plan_bad_since — sonradan eklenmis ve yoruma
    //        islenmemis). ESIK METINDEN DEGIL OLCULEREK alinmali:
    //            python3 -c "from cases import CASES,EXCLUDED; \
    //                        print(len({c[0] for c in CASES})-len(EXCLUDED))"
    //        343-4 = 339 idi; `dr restore`un 15 vakasi + kid kapatmasinin 4
    //        vakasiyla, ve sifir-girdili manifest vakasiyla 363-4 = 359.
    //
    //        `dr` vakalari korpusa girerken IKI GERCEK AYRISMA buldu ve
    //        ikisi de ayni kokten geliyordu: port dosya hatalarini Rust'in
    //        kendi dizesiyle basiyordu ("No such file or directory (os error
    //        2)") — Go ise *os.PathError metnini ("open <yol>: no such file
    //        or directory"). Duzeltme drverb.rs'i ZATEN VAR OLAN goerr'e
    //        bagladi; yeni bir metin UYDURULMADI.
    let equal: usize = report
        .rsplit("EQUAL=")
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(equal >= 359, "differential yalnizca {equal} vaka gezdi:\n{report}");
    let _ = std::fs::remove_dir_all(&work);
}
