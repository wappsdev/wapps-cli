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

// Harness'in olcum YAPMADIGINI soyleyen cikis kodu. 0 (gecti) ve cargo'nun
// test basarisizligi olan 101'den AYRI olmasi sart: bir okuyucu "ikililer
// ayristi" ile "olcum hic yapilmadi"yi ayirt edebilmeli. cargo'nun bu kodu
// oldugu gibi ilettigi OLCULDU.
const EXIT_NOT_MEASURED: i32 = 97;

// scratch, HICBIR GIT DEPOSUNUN ICINDE OLMAYAN bir calisma dizini verir.
//
// BU BIR USLUP DEGIL, OLCUMUN HUKMU: ayni agacta, ayni commit'te, tek fark
// `TMPDIR` olan iki kosum TERS KARAR verdi — depo-disi TMPDIR'la exit 0 ve
// 121 sn, broker harness'inin verdigi (bir git worktree'sinin ICINDEKI)
// TMPDIR'la exit 101, 26 zaman asimi ve 954 sn. Sebep: baglama kimligi git'e
// soruluyor, git calisma dizininden YUKARI CIKIP cevreleyen depoyu buluyor,
// tohumlanan pinler tutmuyor ve on uc vaka onay isteminde SIGKILL yiyor.
//
// ESKI KORUMA IKI YERDEN DE YETMIYORDU ve ikisi de OLCULEREK elendi:
//   * buradaki `!d.starts_with(repo_root())` iddiasi yalnizca BU depoyu
//     taniyordu; cagiranin TMPDIR'i BASKA bir deponun icindeyse sessizce
//     geciyordu — tuzagin yurudugu delik tam olarak buydu;
//   * probe.py'nin `GIT_CEILING_DIRECTORIES=<workdir>`'i yalnizca workdir'in
//     GERCEK ALTINDAKI dizinleri koruyordu (git tavani OZ ATA olarak arar),
//     yani vakayi workdir'in KENDISINDE kosan cogunluk korumasizdi.
//
// Yerine tek hukum: dizini harness SECER (cagiranin TMPDIR'i bir ONERIDIR,
// depo icindeyse atlanir) ve secim `git`e SORULARAK dogrulanir. Hicbir aday
// uymuyorsa olcum yapilmaz ve harness 97 ile patlar.
fn scratch() -> PathBuf {
    let out = Command::new("python3")
        .arg(pty_dir().join("workdir.py"))
        .arg(format!("wapps-pty-diff-{}", std::process::id()))
        .output()
        .expect("workdir.py calistirilamadi");
    exit_if_not_measured(&out, "workdir.py");
    assert!(
        out.status.success(),
        "workdir.py basarisiz (exit {:?})\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let d = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    assert!(
        d.is_dir(),
        "workdir.py var olmayan bir dizin verdi: {}",
        d.display()
    );
    d
}

fn pty_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty")
}

// Bir alt surec "olcum yapilmadi" dediyse (97) bu testin FAIL etmesi yaniltici
// olurdu: fail "ikililer ayristi" diye okunur. Kod OLDUGU GIBI disari tasiniyor.
//
// Mesaj `eprintln!` ile YAZILMIYOR ve bunun sebebi olculdu: libtest o makroyu
// YAKALIYOR, ve surec `exit` ile bittigi icin yakalanan tampon HIC basilmiyordu
// — geriye yalnizca ciplak bir 97 kaliyordu. Sebebini soylemeyen bir patlama,
// yerini aldigi sessiz arizadan cok da iyi degildir. Dogrudan fd 2'ye yaziliyor.
fn exit_if_not_measured(out: &std::process::Output, what: &str) {
    if out.status.code() == Some(EXIT_NOT_MEASURED) {
        use std::io::Write;
        let mut err = std::io::stderr();
        let _ = err.write_all(&out.stderr);
        let _ = writeln!(
            err,
            "differential: {what} olcumu REDDETTI (exit {EXIT_NOT_MEASURED}) — \
             bu bir AYRISMA DEGIL, olcumun HIC yapilmadigi anlamina gelir."
        );
        let _ = err.flush();
        std::process::exit(EXIT_NOT_MEASURED);
    }
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{what} calistirilamadi: {e}"));
    exit_if_not_measured(&out, what);
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
    let pty_dir = pty_dir();

    // Oracle'i kaynaktan derle — sahadaki sozlesme Go'nun BUGUNKU davranisi.
    let go_bin = work.join("wapps-go");
    run(
        Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&go_bin)
            .arg("./main.go")
            .current_dir(&root),
        "go build (oracle)",
    );

    let go_json = work.join("go-probe.json");
    let rs_json = work.join("rs-probe.json");
    for (bin, out) in [
        (go_bin.as_path(), &go_json),
        (Path::new(env!("CARGO_BIN_EXE_wapps")), &rs_json),
    ] {
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
        Command::new("python3")
            .arg(pty_dir.join("diff.py"))
            .arg(&go_json)
            .arg(&rs_json),
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
    // → 413: BU TURDA 54 VAKA EKLENDI VE HICBIRI AYRISMA BULMADI. Bu bir
    //        SONUC, bir bosluk degil — ve olcum su sirayla, her grup
    //        YAZILMADAN ONCE ve SONRA yapildi:
    //
    //          taban                        EQUAL=359 DIFFERENT=0
    //          +23 `--config` kolu vakasi   EQUAL=382 DIFFERENT=0
    //          +19 baglama-durumu vakasi    EQUAL=401 DIFFERENT=0
    //          +12 kol-boslugu vakasi       EQUAL=413 DIFFERENT=0
    //          +4  BESINCI DURUM vakasi     EQUAL=413 DIFFERENT=2  <-- AYRISMA
    //          duzeltmeden sonra            EQUAL=417 DIFFERENT=0
    //          +2  KISA BICIM (-p/-c)        EQUAL=419 DIFFERENT=0
    //          +15 `dr bootstrap`             EQUAL=434 DIFFERENT=0
    //          +1  BESINCI DURUM (`dr bootstrap`) EQUAL=435 DIFFERENT=0
    //          +16 `dr accept-epoch-reset`      EQUAL=451 DIFFERENT=0
    //          +6  YEREL `--project` GOLGESI     EQUAL=457 DIFFERENT=0
    //
    // IKI GRUP DA KIRMIZI GORULEREK yazildi, ve bu iki ayri kosum:
    //
    //   * on alti seremoni vakasi fiil PORTLANMADAN once eklendi ve kosum
    //     EQUAL=435 DIFFERENT=16 verdi — yani on altisi da GERCEKTEN yeni bir
    //     kod yolu olcuyor, ve eski 435'in HICBIRI sahte gate'in yeni
    //     rotasindan (`/v1/audit/head`) ya da yeni basligindan
    //     (`X-Wapps-Intent`) etkilenmedi;
    //   * alti golge vakasi, duzeltmesi DEVRE DISI birakilmis bir ikiliyle
    //     ayri ayri kosuldu ve DORDU ayristi (ikisi `accept-epoch-reset`,
    //     IKISI `dr restore` — yani ayrisma bu dilimin GETIRDIGI bir sey
    //     degil, `dr restore`da olculmeden duruyordu). Kalan ikisi duzeltme
    //     OLMADAN da esitti ve bilerek oyle: biri oncelik (`sonuncu kazanir`)
    //     nobetcisi, digeri KONTROL — yerel `--project`i OLMAYAN `dr
    //     verify`de karsilikli dislama SURMELI. Kontrol olmasa duzeltme
    //     kurali topyekun kaldirabilir ve gate yine yesil kalirdi.
    //
    // ESIK ARTIK IKI SEYI BIRDEN TUTUYOR, cunku EQUAL'in ANLAMI degisti:
    // zaman asimina ugramis (ya da hicbir sey gozlemlemeyen) bir vaka EQUAL'e
    // SAYILMIYOR. Eskiden sayiliyordu ve bu bir kez gercekten yanilttı —
    // "EQUAL=419 DIFFERENT=0 UNSOUND=26" satirini okuyan biri 419 vakanin
    // karsilastirildigini sanmisti, oysa on ucu yalnizca 30 sn'lik bir
    // timeout olcmustu. Artik oyle bir kosumda EQUAL bu esigin ALTINA duser,
    // yani asagidaki iddia sessiz timeout'lari da yakalar.
    //
    // → 511: `whoami` (14) + `token exchange` (37) + golgenin KISA-BICIM yuzu
    //        (3) 54 vaka ekledi. KIRKSEKIZI FIIL YAZILMADAN ONCE KIRMIZI
    //        GORULDU; kalan alti vaka SONRADAN bulunan iki ayrismayi
    //        kapatiyor ve IKISI DE once DIFFERENT olarak GORULDU
    //        (`-` ile baslayan degerler, ve ArbitraryArgs).
    //        Kirmizi kosum tek basina uc sey kanitladi:
    //
    //          taban                          EQUAL=457 DIFFERENT=0
    //          +49 vaka, fiil YOKKEN          EQUAL=458 DIFFERENT=48
    //          fiiller + duzeltmeler sonrasi  EQUAL=506 DIFFERENT=0
    //          +3 `-` ile baslayan deger      EQUAL=509 DIFFERENT=0
    //
    //        1. 48 vaka GERCEKTEN yeni bir kod yolu geziyor;
    //        2. eski 457'nin HICBIRI zenginlestirilen `/v1/whoami` govdesinden
    //           ya da yeni `POST /v1/token` rotasindan etkilenmedi (458 = 457
    //           + kirmizi kosumda ZATEN yesil olan tek yeni vaka);
    //        3. o TEK yesil vaka bir KONTROL:
    //           `agent_dr_verify_still_accepts_the_short_project_form` —
    //           yerel `--project`i OLMAYAN bir yaprakta `-p` iki ikilide de
    //           calisiyor, yani asagidaki golge duzeltmesi kurali topyekun
    //           kaldirmiyor.
    //
    //        UC AYRISMA BULUNDU ve ucu de bu dilimin GETIRDIGI seyler DEGIL;
    //        olculmedikleri icin duruyorlardi:
    //
    //          * `safe_code` Go'nun `safeCode`u DEGILDI (bos kod "unknown"
    //            olmali, sinif disi baytlar ATILMALI, kirpma 48 bayt). Korpustaki
    //            her hata govdesi temiz bir SCREAMING_SNAKE kodu tasidigi icin
    //            hicbir vaka bunu gormemisti; `whoami`nin 403 ve `token
    //            exchange`in 400 dallari BOS bir kod gorebiliyor. Duzeltme
    //            BUTUN rotalarin hata yolunu etkiliyor ve eski 457 vaka
    //            duzeltmeden SONRA da esit kaldi.
    //          * GOLGENIN KISA-BICIM YUZU: yerel `--project` tasiyan bir
    //            yaprakta cobra kokun `-p`sini de KALDIRIYOR ("unknown
    //            shorthand flag: 'p' in -p"). Bu, ust dilimin kapattigi
    //            tuzagin DORDUNCU yuzuydu ve `dr restore` ile
    //            `dr accept-epoch-reset`te de vardi — o yuzden vakalari
    //            burada, bu dilimde.
    //          * `-` ILE BASLAYAN DEGERLER: pflag bosluklu bir uzun bayraktan
    //            sonraki jetonu KOSULSUZ deger sayiyor. `token exchange`in
    //            dort bayragi da isaretlendi; deponun DIGER deger alan
    //            bayraklarinda ayni fark DURUYOR (olculdu: `dr restore
    //            --snapshot -x`) ve bu dilim o ekseni acmiyor, adlandiriyor.
    //          * ARBITRARYARGS: `whoami` de `token exchange` de cobra'da
    //            `Args` TASIMIYOR, yani fazladan bir arguman SESSIZCE
    //            yutuluyor. `whoami` ilk turda dogru yazilmisti, `token
    //            exchange` yazilmamisti ve DIFFERENT olarak goruldu — ikisi
    //            de artik korpusta, cunku "ayni desen" varsaymak bu dosyanin
    //            defalarca dustugu tuzak.
    //
    // TABAN 434'E CIKARILDI ve bunun bir sebebi var: bu iddia korpusun
    // BUYUKLUGUNU tutan TEK mekanizma. Taban eskisi gibi 419'da biraksaydi,
    // `dr bootstrap`in on bes vakasinin TAMAMI korpustan sessizce dusebilir
    // ve gate YINE YESIL kalirdi. Canli vaka sayisi (CASES - EXCLUDED)
    // OLCULDU: 515 - 4 = 511, yani bu esik "en az" degil TAM sayidir.
    //
    //        `set` ve `get`te iki kez cikan kor nokta UCUNCU KEZ CIKMADI:
    //        `--config` kalan ON BIR `Ctx::resolve` fiilinin (list/status/rm/
    //        projects list/import-env/env/trust-repo/init/set/exec/apply)
    //        hepsinde iki ikilide de AYNI davraniyor.
    //
    //        BRIEF'IN VERDIGI SEBEP OLCULDU VE YANLIS CIKTI. Iddia "korpustaki
    //        her vaka `--project` geciren bir yardimcidan doguyor"du. Olcum:
    //        359 vakanin 119'u `--project`, 1'i `--config`, 239'u HICBIR
    //        kimlik bayragi gecirmiyordu; korpus elemanlarinin 199'u SATIR ICI
    //        TUPLE, 164'u yardimci cagrisi; ve `P` ekleyen yardimcilarin IKISI
    //        (`e_h`, `e_a`) HIC CAGRILMIYOR. Yani yardimci kalibini
    //        degistirmek korpusun yarisina bile dokunmazdi — `exec`in sekiz
    //        `--project` vakasi elle `P` yazan satir ici tuple'lardir.
    //
    //        Gercek bosluk SAYIMDA: bir fiilin kimlik kollarindan kacinin
    //        gezildigi hic sayilmiyordu. cases.py artik bunu IMPORT ANINDA
    //        sart kosuyor (`_armcheck`), ve mekanizmanin kendisi
    //        tests/armcheck.rs'te MUTASYONLA sinaniyor.
    //
    //        IKINCI BOSLUK DA KAPANDI: probe.py `repo-pins.json`
    //        TOHUMLAYABILIYOR (7. vaka elemani; parmak izi = sha256(config
    //        kokunun mutlak yolu), bicim Go'nun MarshalIndent'i ve bayt
    //        esitligi Go ikilisinin urettigi dosyayla OLCULDU). Bu olmadan
    //        `bindPrompt`in UYUSMAZLIK dali ("baska projeye pinli") hicbir
    //        fiil icin gezilemiyordu; "ZATEN PINLI, sormadan gec" dali da
    //        oyle — ve o dal bir AJANIN gercekten calistigi TEK yol.
    //
    //        UC ASIMETRI DE BURADA PINLENDI. UCU DE IKI IKILIDE AYNI, yani
    //        differential onlari BULAMAZDI (paylasilan kusur kor noktasi);
    //        ciktiya ELLE bakilarak goruldular:
    //          * `secrets init` `--config`i YAZMA yolunda kullanmiyor (sablon
    //            CWD'ye dusuyor) ama BAGLAMA kapisinda kullaniyor;
    //          * `import-env <dosya>` yolu CWD'ye gore cozuluyor;
    //          * `env --write <yol>` CWD'ye gore, ama `apply`in `targets`i
    //            CONFIG KOKUNE gore cozuluyor.
    //
    //        VE BIR AYRISMA GERCEKTEN CIKTI — ama ARANAN eksende degil.
    //        `--config` kolu on bir fiilde de temizdi; ayrisma, DORT KOLLU
    //        taksonominin KENDI kor noktasindan cikti: `--config` ile
    //        `--project` BIRLIKTE verildiginde. O durumun taksonomide adi
    //        yoktu ve korpusta tek ornegi de yoktu.
    //
    //          Go   -> "--config and --project are mutually exclusive"
    //          Rust -> clap'in `conflicts_with` cumlesi
    //
    //        Duzeltme UC olcumden dogdu (hicbiri tahmin degil): ret
    //        `Ctx::resolve`e ait DEGIL (Go'da root'un PersistentPreRunE'unda,
    //        yani `doctor`/`dr`/`policy`/`rotate skip`/`projects rm` de
    //        aliyor); `tofu` ISTISNA (DisableFlagParsing → bayraklar atil);
    //        ve hata DUZ (`Plain`), yani insan yolunda kod oneki/kurtarma
    //        satiri YOK. Ucuncusu ilk turda kacirildi ve DIFFERENT=1 olarak
    //        geri geldi.
    //
    //        Ayrisma tests/identityflags.rs'te IDDIA olarak da duruyor:
    //        duzeltmeden sonra DIFFERENT 0'a doner ve karsilastirmada kanit
    //        KALMAZ.
    // Ozet satiri GECEN kosumda da gorunsun (`-- --nocapture`): "EQUAL=n
    // DIFFERENT=0 UNSOUND=0" tek basina okunabilir bir kanittir, ve UNSOUND
    // artik EQUAL'e SAYILMADIGI icin bir zaman asimi bu satiri sessizce
    // suslemez — esigi DUSURUR.
    for line in report
        .lines()
        .filter(|l| l.starts_with("EQUAL=") || l.starts_with("UYARI:"))
    {
        println!("{line}");
    }
    let equal: usize = report
        .rsplit("EQUAL=")
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // `wapps skill` raised the floor to the live count it measured: 612
    // (569 + 43); `coolify update-env`/`set-labels` added 66 more, landed in
    // parallel, so the floor is their sum: 678. The floor had stayed at 511
    // through login and sync. `coolify deploy-app`/`deploy-app-git`/
    // `import-app` added 93: 771. `secrets sync --target=coolify` added 50:
    // 821.
    assert!(
        equal >= 821,
        "differential yalnizca {equal} vaka gezdi:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&work);
}
