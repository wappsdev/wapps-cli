// `wapps dr` verb katmani — IDDIA testleri (differential'in goremedigi yerler).
//
// IS BOLUMU, ve bu tabloyu okumadan bu dosyaya vaka EKLENMEMELI:
//
//   OLCU              NE KAPATIR                         NE KAPATMAZ
//   ----------------  ---------------------------------  ---------------------
//   IDDIA (bu dosya)  iki ikilinin PAYLASTIGI kusur;      Go'nun bugunku
//   + tests/cryptoid  dosya sozlesmeleri (O_EXCL, 0600);  ciktisiyla bayt
//                     kripto cekirdegi (frozen vektor)    esitligi
//   KARSILASTIRMA     Go ile bayt esitligi: cikti, cikis  IKISININ DE ayni
//   (pty differential) kodu, yazilan dosya+mod            sekilde yanlis oldugu
//                                                        seyler
//
// `dr`de bu ayrim ozellikle kritik: `split` differential'lanAMAZ (RNG ->
// cikti her kosumda farkli), yani onun TEK olcusu bu dosyadaki iddialar.
use std::path::{Path, PathBuf};
use wapps::drverb;

fn tmpdir(name: &str) -> PathBuf {
    // Depo agacinin DISINDA: scratch bir git worktree'sinin icine duserse bu
    // deponun binding testleri dokunulmamis bir agacta bile kiriliyor.
    let d = std::env::temp_dir().join(format!("wapps-drverb-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).expect("stat").permissions().mode() & 0o777
}

// --- short() -------------------------------------------------------------------

#[test]
fn short_truncates_at_16_with_an_ellipsis_and_leaves_shorter_input_alone() {
    // Go: len<=16 ise AYNEN doner; degilse ilk 16 + "…" (U+2026, 3 BAYT).
    assert_eq!(drverb::short("0123456789abcdef"), "0123456789abcdef");
    assert_eq!(drverb::short("0123456789abcdefX"), "0123456789abcdef…");
    assert_eq!(drverb::short("kisa"), "kisa");
}

// --- writeSecretFile0600: O_EXCL + 0600 ----------------------------------------

#[test]
fn write_secret_file_0600_creates_with_mode_0600() {
    let d = tmpdir("excl-mode");
    let p = d.join("share.hex");
    drverb::write_secret_file_0600(&p, b"not-a-real-key\n").expect("yazilmali");
    assert_eq!(mode_of(&p), 0o600, "pay dosyasi 0600 DEGIL");
}

#[test]
fn write_secret_file_0600_refuses_to_clobber_an_existing_file() {
    // O_EXCL SOZLESMEDIR, sus degil. Iki sey birden onluyor:
    //   1. onceden var olan GEVSEK IZINLI bir dosyanin uzerine yazmayi;
    //   2. "var olan dosyanin modu DEGISMEZ" tuzagini — duz bir yazici 0644
    //      bir dosyayi 0644 BIRAKIR ve 0600 sozlesmesi SESSIZCE bozulur.
    let d = tmpdir("excl-refuse");
    let p = d.join("share.hex");
    std::fs::write(&p, b"onceden var").expect("seed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    let err = drverb::write_secret_file_0600(&p, b"yeni").expect_err("uzerine YAZMAMALI");
    assert!(
        err.message.contains("refusing to overwrite existing"),
        "ret mesaji clobber reddini adlandirmiyor: {}",
        err.message
    );
    // Ve gercekten dokunmamis olmali.
    assert_eq!(
        std::fs::read(&p).expect("read"),
        b"onceden var".to_vec(),
        "dosya DEGISTI"
    );
    assert_eq!(
        mode_of(&p),
        0o644,
        "mod degisti — O_EXCL dali yazmaya girmis"
    );
}

// --- snapshot zinciri ----------------------------------------------------------

/// seed_snapshot, iki projeli gecerli bir snapshot kurar. GERCEK SIR YOK:
/// blob'lar duz uydurma baytlar (bu dilim onlari COZMUYOR, yalnizca icerik
/// adreslerini dogruluyor).
fn seed_snapshot(root: &Path) {
    for (project, epoch) in [("alpha", 4u64), ("beta", 9u64)] {
        let pdir = root.join("secrets").join(project);
        std::fs::create_dir_all(pdir.join("blobs")).expect("mkdir");
        std::fs::create_dir_all(pdir.join("manifests")).expect("mkdir");
        let blob = format!("fake-blob-bytes-for-{project}").into_bytes();
        let bh = wapps::cryptoid::blob_hash(&blob);
        std::fs::write(pdir.join("blobs").join(&bh), &blob).expect("blob");
        let man = format!(
            r#"{{"schema":"wapps-secrets/data-manifest/v2","project":"{project}","epoch":{epoch},"entries":[{{"keyName":"KEY_ONE","keyVersion":1,"blobHash":"{bh}","wrap":{{"recipient":"worker-kek:v1","kid":"0123456789abcdef","wrap":"AAAA"}}}}]}}"#
        );
        std::fs::write(pdir.join("manifests").join(format!("{epoch}.json")), &man).expect("man");
        let mh = wapps::cryptoid::blob_hash(man.as_bytes());
        let ptr = format!(
            r#"{{"schema":"wapps-secrets/current/v1","project":"{project}","epoch":{epoch},"manifestSha256":"{mh}"}}"#
        );
        std::fs::write(pdir.join("current"), ptr).expect("ptr");
    }
}

#[test]
fn verify_walks_every_project_in_sorted_order() {
    let d = tmpdir("verify-ok");
    seed_snapshot(&d);
    let mut out = Vec::new();
    drverb::run_verify(&mut out, &d).expect("gecerli snapshot dogrulanmali");
    let s = String::from_utf8(out).expect("utf8");
    let alpha = s.find("alpha").expect("alpha satiri yok");
    let beta = s.find("beta").expect("beta satiri yok");
    assert!(alpha < beta, "projeler SIRALI gezilmedi");
    assert!(s.contains("epoch=4"), "alpha'nin epoch'u basilmadi");
    assert!(s.contains("epoch=9"), "beta'nin epoch'u basilmadi");
    assert!(
        s.contains("✓ snapshot VERIFIED (2 project(s)"),
        "ozet satiri yanlis: {s}"
    );
}

#[test]
fn verify_rejects_a_pointer_manifest_hash_mismatch() {
    // Zincirin ta kendisi: pointer manifest'in hash'ini tasiyor. Manifest'te
    // TEK bir baytlik oynama tamper (ya da yarim replika) demektir.
    let d = tmpdir("verify-chain");
    seed_snapshot(&d);
    let mp = d.join("secrets/alpha/manifests/4.json");
    let mut man = std::fs::read_to_string(&mp).expect("read");
    man = man.replace("KEY_ONE", "KEY_TWO"); // ayni uzunluk, farkli hash
    std::fs::write(&mp, man).expect("write");
    let err = drverb::run_verify(&mut Vec::new(), &d).expect_err("zincir kirilmis olmali");
    assert!(
        err.message.contains("pointer/manifest hash mismatch"),
        "ret zincir kirilmasini adlandirmiyor: {}",
        err.message
    );
}

#[test]
fn verify_rejects_a_blob_whose_content_address_does_not_match() {
    let d = tmpdir("verify-blob");
    seed_snapshot(&d);
    // Blob'un ADI icerik adresi; icerigi degistirince adres artik yalan.
    let bdir = d.join("secrets/alpha/blobs");
    let name = std::fs::read_dir(&bdir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    std::fs::write(bdir.join(&name), b"kurcalanmis-baytlar").expect("write");
    let err = drverb::run_verify(&mut Vec::new(), &d).expect_err("icerik adresi tutmamali");
    assert!(
        err.message.contains("blob content-address mismatch"),
        "ret icerik adresi ihlalini adlandirmiyor: {}",
        err.message
    );
}

#[test]
fn verify_rejects_an_unsupported_wrap_recipient() {
    // Alici KAPALI bir kume (§2.4). Taninmayan bir alici, gelecekteki bir
    // formatin sessizce "dogrulanmis" sayilmasi demek olurdu.
    let d = tmpdir("verify-recipient");
    seed_snapshot(&d);
    let mp = d.join("secrets/alpha/manifests/4.json");
    let man = std::fs::read_to_string(&mp)
        .expect("read")
        .replace("worker-kek:v1", "someone-else:v9");
    std::fs::write(&mp, &man).expect("write");
    // Pointer'i yeni manifest'e gore duzelt ki zincir DEGIL alici dali olculsun.
    let mh = wapps::cryptoid::blob_hash(man.as_bytes());
    let pp = d.join("secrets/alpha/current");
    let ptr = std::fs::read_to_string(&pp).expect("read");
    let fixed = regex_replace_hash(&ptr, &mh);
    std::fs::write(&pp, fixed).expect("write");
    let err = drverb::run_verify(&mut Vec::new(), &d).expect_err("alici reddedilmeli");
    assert!(
        err.message.contains("unsupported wrap recipient"),
        "ret aliciyi adlandirmiyor: {}",
        err.message
    );
}

/// regex_replace_hash, pointer JSON'undaki manifestSha256 alanini degistirir
/// (testin kendi yardimcisi; uretim kodunda karsiligi yok).
fn regex_replace_hash(ptr: &str, new_hash: &str) -> String {
    let key = "\"manifestSha256\":\"";
    let i = ptr.find(key).expect("manifestSha256 yok") + key.len();
    let j = i + ptr[i..].find('"').expect("kapanis tirnagi yok");
    format!("{}{}{}", &ptr[..i], new_hash, &ptr[j..])
}

// --- split -----------------------------------------------------------------------

#[test]
fn split_writes_one_0600_share_per_part_and_prints_the_kid_but_never_the_key() {
    let d = tmpdir("split-ok");
    let outdir = d.join("shares");
    let master_hex = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    let mut out = Vec::new();
    drverb::run_split_core(&mut out, &outdir, 3, 2, &master_hex, &mut rng).expect("split");
    let s = String::from_utf8(out).expect("utf8");

    for i in 1..=3 {
        let p = outdir.join(format!("wapps-master-share-{i}-of-3.hex"));
        assert!(p.exists(), "pay {i} yazilmadi");
        assert_eq!(mode_of(&p), 0o600, "pay {i} 0600 DEGIL");
    }
    // kid basilir (dogrulanabilsin diye), ANAHTAR BASILMAZ.
    assert!(
        s.contains("MASTER_KEK kid: 9f72ea0cf49536e3"),
        "kid basilmadi: {s}"
    );
    assert!(!s.contains(&master_hex), "MASTER_KEK ciktiya SIZDI");
}

#[test]
fn split_refuses_parameters_that_would_not_reconstruct() {
    let d = tmpdir("split-params");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    // threshold < 2, ve parts < threshold.
    assert!(drverb::run_split_core(&mut Vec::new(), &outdir, 3, 1, &mh, &mut rng).is_err());
    assert!(drverb::run_split_core(&mut Vec::new(), &outdir, 2, 3, &mh, &mut rng).is_err());
    assert!(!outdir.exists(), "reddedilen cagri yine de dizin actI");
}

#[test]
fn split_refuses_a_master_that_is_not_64_hex() {
    let d = tmpdir("split-badhex");
    let outdir = d.join("shares");
    let mut rng: &[u8] = &[0x11u8; 4096];
    for bad in ["deadbeef", "zz".repeat(32).as_str(), ""] {
        let e = drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, bad, &mut rng);
        assert!(
            e.is_err(),
            "gecersiz master kabul edildi: uzunluk {}",
            bad.len()
        );
    }
}

#[test]
fn split_writes_nothing_when_a_share_file_already_exists() {
    // O_EXCL'in verb seviyesindeki sonucu: ikinci kez ayni dizine split
    // yapmak SESSIZCE eski paylari degistirmez, HATA verir.
    let d = tmpdir("split-twice");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("ilk split");
    let first = std::fs::read(outdir.join("wapps-master-share-1-of-3.hex")).expect("read");
    let mut rng2: &[u8] = &[0x22u8; 4096];
    let e = drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng2);
    assert!(e.is_err(), "ikinci split reddedilmedi");
    let after = std::fs::read(outdir.join("wapps-master-share-1-of-3.hex")).expect("read");
    assert_eq!(first, after, "var olan pay EZILDI");
}

// --- combine ---------------------------------------------------------------------

#[test]
fn combine_round_trips_a_split_and_writes_0600() {
    let d = tmpdir("combine-ok");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("split");

    let s1 = outdir.join("wapps-master-share-1-of-3.hex");
    let s3 = outdir.join("wapps-master-share-3-of-3.hex");
    let outp = d.join("master.hex");
    let mut out = Vec::new();
    drverb::run_combine_core(&mut out, &[s1, s3], &outp, "").expect("combine");
    let printed = String::from_utf8(out).expect("utf8");

    assert_eq!(mode_of(&outp), 0o600, "yeniden kurulan anahtar 0600 DEGIL");
    let got = std::fs::read_to_string(&outp).expect("read");
    assert_eq!(got.trim(), mh, "round-trip MASTER_KEK'i geri vermedi");
    // Anahtar DOSYAYA yazilir, EKRANA yazilmaz.
    assert!(!printed.contains(&mh), "MASTER_KEK stdout'a SIZDI");
    assert!(
        printed.contains("kid 9f72ea0cf49536e3"),
        "kid basilmadi: {printed}"
    );
}

#[test]
fn combine_prints_the_silent_wrong_key_warning() {
    // BU BIR SUS DEGIL, TEK SAVUNMA — `--expect-kid` VERILMEDIGINDE.
    // ShamirCombine yanlis paylarda HATA VERMEZ; dogru uzunlukta, YANLIS bir
    // anahtar doner. Uyari duserse tore SESSIZCE yanlis tamamlanir.
    //
    // Uyari metni bu seritte DEGISTI ve degisim kasitli: eskisi "bu kid'i
    // dogrula" diyordu ama karsilastirilacak degerin NEREDE oldugunu
    // SOYLEMIYORDU — oysa o deger replikadaki her manifest'in icinde duruyor.
    // Yeni metin hem otomatik yolu (--expect-kid) hem de degerin kaynagini
    // (dr verify) adlandirmali; asagidaki uc iddia tam olarak bunu tutuyor.
    let d = tmpdir("combine-warn");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("split");
    let mut out = Vec::new();
    drverb::run_combine_core(
        &mut out,
        &[
            outdir.join("wapps-master-share-1-of-3.hex"),
            outdir.join("wapps-master-share-2-of-3.hex"),
        ],
        &d.join("m.hex"),
        "",
    )
    .expect("combine");
    let s = String::from_utf8(out).expect("utf8");
    assert!(
        s.contains("kid NOT verified"),
        "kontrolun YAPILMADIGI soylenmiyor: {s}"
    );
    assert!(
        s.contains("silently-WRONG"),
        "sessiz-yanlis uyarisi yok: {s}"
    );
    // Riski soylemek YETMEZ: cozumu de adlandirmali.
    assert!(
        s.contains("--expect-kid"),
        "otomatik yol (--expect-kid) adlandirilmiyor: {s}"
    );
    assert!(
        s.contains("dr verify"),
        "beklenen kid'in KAYNAGI (dr verify) adlandirilmiyor: {s}"
    );
}

#[test]
fn combine_refuses_a_kid_mismatch_and_writes_nothing() {
    // BULGUNUN KAPANDIGI YER. Ayni kurcalanmis pay, ayni fiil — ama
    // --expect-kid ile artik SESSIZ degil: hata veriyor VE dosya birakmiyor.
    let d = tmpdir("combine-expect-mismatch");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("split");
    let outp = d.join("m.hex");
    let e = drverb::run_combine_core(
        &mut Vec::new(),
        &[
            outdir.join("wapps-master-share-1-of-3.hex"),
            outdir.join("wapps-master-share-2-of-3.hex"),
        ],
        &outp,
        "0000000000000000",
    )
    .expect_err("kid uyusmazligi KABUL EDILDI");
    let _ = e;
    // FAIL-CLOSED: reddedilen bir toren DOSYA BIRAKMAMALI. Once yazip sonra
    // hata vermek, operatore yanlis anahtari elinde birakirdi — ve o dosya
    // 0600 oldugu icin "dogrulanmis" gorunurdu.
    assert!(
        !outp.exists(),
        "kid uyusmazliginda --out dosyasi YAZILMIS (fail-closed degil)"
    );
}

#[test]
fn combine_accepts_the_matching_kid_case_insensitively() {
    // Operator kid'i bir terminalden ELLE tasiyor: bosluk ve BUYUK harf
    // reddedilirse bayrak sahada kullanilmaz hale gelir.
    let d = tmpdir("combine-expect-match");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("split");
    // 0x22*32'nin kid'i frozen vektorde pinli (tests/cryptoid.rs).
    let kid = "9F72EA0CF49536E3";
    let outp = d.join("m.hex");
    let mut out = Vec::new();
    drverb::run_combine_core(
        &mut out,
        &[
            outdir.join("wapps-master-share-1-of-3.hex"),
            outdir.join("wapps-master-share-2-of-3.hex"),
        ],
        &outp,
        &format!("  {kid} "),
    )
    .expect("dogru kid REDDEDILDI");
    assert!(outp.exists(), "eslesen kid'de dosya YAZILMADI");
    let s = String::from_utf8(out).expect("utf8");
    assert!(
        s.contains("kid MATCHES"),
        "dogrulamanin YAPILDIGI soylenmiyor: {s}"
    );
}

#[test]
fn combine_with_a_tampered_share_still_succeeds_but_yields_a_different_kid() {
    // SESSIZ ARIZANIN VERB SEVIYESINDEKI KANITI. Bir pay bozuldugunda `dr
    // combine` BASARIYLA tamamlanir, 0600 bir dosya yazar ve 0 ile doner —
    // yalnizca kid FARKLIDIR. Yanlis cevap dogru cevaptan AYRILMAZ gorunur;
    // fark ancak sifre cozulemedigi anda, yani EN KOTU ANDA anlasilir.
    let d = tmpdir("combine-tamper");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("split");

    let s1 = outdir.join("wapps-master-share-1-of-3.hex");
    let mut hexs = std::fs::read_to_string(&s1)
        .expect("read")
        .trim()
        .to_string();
    // Ilk hex basamagini degistir (pay govdesinde, x-koordinatinda DEGIL).
    let first = if hexs.starts_with('a') { 'b' } else { 'a' };
    hexs.replace_range(0..1, &first.to_string());
    let bad = d.join("bad-share.hex");
    std::fs::write(&bad, format!("{hexs}\n")).expect("write");

    let outp = d.join("wrong-master.hex");
    let mut out = Vec::new();
    drverb::run_combine_core(
        &mut out,
        &[bad, outdir.join("wapps-master-share-2-of-3.hex")],
        &outp,
        // --expect-kid VERILMEDEN: sessiz ariza HALA burada, ve bu vaka onu
        // pinliyor. Bayrakla kapandigini olcen ayri bir test asagida.
        "",
    )
    .expect("BOZUK PAY HATA VERMEMELI — sessiz ariza pinleniyor");
    let printed = String::from_utf8(out).expect("utf8");
    let got = std::fs::read_to_string(&outp).expect("read");
    assert_eq!(
        got.trim().len(),
        64,
        "yine de 64-hex bir anahtar yazildi (beklenen)"
    );
    assert_ne!(got.trim(), mh, "bozuk pay DOGRU anahtari verdi (imkansiz)");
    assert!(
        !printed.contains("9f72ea0cf49536e3"),
        "bozuk pay dogru kid'i basti — sessiz ariza SAPTANAMAZ olurdu"
    );
}

#[test]
fn combine_refuses_a_share_file_that_is_not_hex() {
    let d = tmpdir("combine-nothex");
    let p = d.join("junk.hex");
    std::fs::write(&p, "bu hex degil!!\n").expect("write");
    let q = d.join("junk2.hex");
    std::fs::write(&q, "aabb\n").expect("write");
    let e = drverb::run_combine_core(&mut Vec::new(), &[p, q], &d.join("o.hex"), "")
        .expect_err("hex olmayan pay kabul edildi");
    assert!(
        e.message.contains("is not hex"),
        "ret mesaji: {}",
        e.message
    );
}

#[test]
fn combine_tolerates_whitespace_and_newlines_in_share_files() {
    // Operator paylari elle kopyaliyor; bosluk/yenisatir tolere EDILMELI.
    let d = tmpdir("combine-ws");
    let outdir = d.join("shares");
    let mh = "22".repeat(32);
    let mut rng: &[u8] = &[0x11u8; 4096];
    drverb::run_split_core(&mut Vec::new(), &outdir, 3, 2, &mh, &mut rng).expect("split");
    let raw = std::fs::read_to_string(outdir.join("wapps-master-share-1-of-3.hex")).expect("read");
    let spaced: String = raw
        .trim()
        .chars()
        .collect::<Vec<_>>()
        .chunks(8)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" \n ");
    let p = d.join("spaced.hex");
    std::fs::write(&p, spaced).expect("write");
    let outp = d.join("m.hex");
    drverb::run_combine_core(
        &mut Vec::new(),
        &[p, outdir.join("wapps-master-share-2-of-3.hex")],
        &outp,
        "",
    )
    .expect("bosluklu pay kabul edilmeliydi");
    assert_eq!(std::fs::read_to_string(&outp).expect("read").trim(), mh);
}

// --- dr restore ---------------------------------------------------------------
//
// Bu bloktaki iddialarin differential'da KARSILIGI YOK, ve sebep yapisal:
// karsilastirma iki ikilinin PAYLASTIGI bir kusuru goremez. "Degerler ASLA
// basilmaz" tam olarak oyle bir sozlesme — iki ikili de sizdirsaydi vaka
// EQUAL doner ve gate yesil kalirdi.

/// restore_fixture, Go implementasyonunun URETTIGI gercek bir snapshot'i
/// diske serer (WKW1 wrap + WSB1 blob, sabit nonce'lar). master = 0x42*32,
/// kid = 425ed4e4a36b30ea. GERCEK SIR DEGIL.
fn restore_fixture(d: &Path) -> (PathBuf, Vec<PathBuf>) {
    let snap = d.join("snap");
    let base = snap.join("secrets").join("alpha");
    std::fs::create_dir_all(base.join("blobs")).expect("mkdir");
    std::fs::create_dir_all(base.join("manifests")).expect("mkdir");
    for (bh, hx) in [
        ("be4ce647f3f370c5d9c42bb83eff3260d158d55a4ea1b469b06576146b1c499c",
         "575342312020202020202020202020202020202020202020202020203c61b33bd0299d9839212c18c994315668e1a46d1e96a6281dd2c16cdc7be65a9e44efaeb230798557bdc8fced3f3d7d5ac0e244d7104cb30429a602674b997f9e31628805fe082b956fc144a46ced91b26b1b860093a7cf3750b3851f075a89f9bc5c6d7b537e02ad4357d9089928d543d9286a0309992fdac1cd7fb65102da492dfcd4b809f52a19d054575e72d970bbaaa75908c3d15ea5b8cfac575c311fe74860c76e67fe59035557023ae540bf1a8925d239c655e21d2834e3ba3bb1e4f10f670d8763a109877a3c48628fc61e4fbc0c7803cfc8d255697dc95f32fb107261c2a04387c08b5a3d295a41d8d8a1999ee18e1bcb2bf6e0c5a56604dab0b953fe212fce916b746df6030feb9f394e"),
        ("dd71fe25146eb516321d0dfa7c05ba8d35835be38f6fd98d8639d24220193860",
         "57534231212121212121212121212121212121212121212121212121826e90a05f585cf6a24d62245a26c8e2671925a9cd0af5a8aa740ee20ca7dcd50881ca1b8f144b696da263a57703a5770b1cd99ca0d0384263a5f4fc0589210ed36cb2e46764ff5c6139bd33a838d612a8cb4c105bcea140866ec711f48120c67c9ccd237c616093224d65fe02fa18cc8eda7eabcec14410193317d2641cbbd7e09abd28980360a4a280a65cb801983e36969d81d8e6688f8a911cd8dfa9cf2020b2aab8ef78fb0cce4d8e2e39bc9e3ae420097b5deb17570f78c7db707a2bf5d6f1c7487fe295b80c6da2683f01b08677eb2467837ace370985e99d81cbb683b87f47a0d4c495d248d9441f9292d678aec4e0424e03e00a5a22a1ff21accbdf4b859d47a1c476022d5a636e9b52cc9a"),
    ] {
        let bytes: Vec<u8> = (0..hx.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hx[i..i + 2], 16).expect("hex"))
            .collect();
        std::fs::write(base.join("blobs").join(bh), &bytes).expect("blob");
    }
    let man = r#"{"entries":[{"blobHash":"be4ce647f3f370c5d9c42bb83eff3260d158d55a4ea1b469b06576146b1c499c","keyName":"DATABASE_URL","keyVersion":1,"wrap":{"kid":"425ed4e4a36b30ea","recipient":"worker-kek:v1","wrap":"V0tXMVBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUDInofKxTr4Tynfzyvd/0HvLzwer6qk/Fg6opIcnfYZ2gTUvAoeDJg/KXpONFZEFrA=="}},{"blobHash":"dd71fe25146eb516321d0dfa7c05ba8d35835be38f6fd98d8639d24220193860","keyName":"API_TOKEN","keyVersion":2,"wrap":{"kid":"425ed4e4a36b30ea","recipient":"worker-kek:v1","wrap":"V0tXMVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUW7U06UZyWF7miDurmCyb10WAqaFFmpad3JqGOxbWzGSZeFGKoLkXFyQD/FAVG6+yQ=="}}],"epoch":7,"project":"alpha","schema":"wapps-secrets/data-manifest/v2"}"#;
    std::fs::write(base.join("manifests").join("7.json"), man).expect("manifest");
    let d2 = ring::digest::digest(&ring::digest::SHA256, man.as_bytes());
    let msum: String = d2.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(
        base.join("current"),
        format!(
            r#"{{"schema":"wapps-secrets/current/v1","project":"alpha","epoch":7,"manifestSha256":"{msum}"}}"#
        ),
    )
    .expect("current");
    // frozen `shamir.shares_hex` — 0x42*32'nin 2-of-3 paylari.
    let shares = [
        "e98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98f01",
        "0fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc302",
    ];
    let paths: Vec<PathBuf> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let p = d.join(format!("s{}.hex", i + 1));
            std::fs::write(&p, format!("{s}\n")).expect("share");
            p
        })
        .collect();
    (snap, paths)
}

#[test]
fn restore_writes_a_0600_env_file_and_never_prints_the_values() {
    let d = tmpdir("restore-ok");
    let (snap, shares) = restore_fixture(&d);
    let outp = d.join("env.out");
    let mut out = Vec::new();
    drverb::restore_project_from_snapshot(&mut out, &snap, "alpha", &shares, &outp)
        .expect("restore basarili olmali");

    // 1. Dosya 0600 OLMALI: duz metin sir tasiyor.
    assert_eq!(
        mode_of(&outp),
        0o600,
        "restore edilen env dosyasi 0600 DEGIL"
    );

    // 2. Degerler gercekten cozulmus olmali (HChaCha20 turetimi dogru mu).
    let body = std::fs::read_to_string(&outp).expect("read");
    assert!(body.contains("DATABASE_URL="), "DATABASE_URL satiri yok");
    assert!(body.contains("API_TOKEN="), "API_TOKEN satiri yok");

    // 3. DEGERLER ASLA BASILMAZ — bu iddianin differential'da KARSILIGI YOK.
    //    Iki ikili de sizdirsaydi karsilastirma EQUAL derdi.
    let printed = String::from_utf8(out).expect("utf8");
    for secret in ["postgres://user:pass@host/db", "tok_live_abc123"] {
        assert!(
            !printed.contains(secret),
            "restore ciktisi bir DEGERI sizdirdi (deger basilmiyor, yalnizca bu satir)"
        );
    }
    // Cikti yalnizca SAYI vermeli.
    assert!(printed.contains("2 value(s)"), "ozet satiri yok: {printed}");
}

#[test]
fn restore_refuses_when_the_wrap_kid_is_not_the_reconstructed_keys_kid() {
    // Paylardan biri kurcalanirsa Shamir SESSIZCE baska bir anahtar uretir.
    // restore bunu manifest'teki kid ile karsilastirdigi icin ERKEN duser —
    // AEAD'e hic varmadan. Bu ayrim onemli: AEAD'de dusseydi hata "tamper"
    // gibi gorunur ve operatoru YANLIS teshise gonderirdi.
    let d = tmpdir("restore-kid");
    let (snap, shares) = restore_fixture(&d);
    let bad = d.join("bad.hex");
    let orig = std::fs::read_to_string(&shares[0]).expect("read");
    std::fs::write(&bad, format!("ff{}", &orig[2..])).expect("write");
    let outp = d.join("env.out");
    let e = drverb::restore_project_from_snapshot(
        &mut Vec::new(),
        &snap,
        "alpha",
        &[bad, shares[1].clone()],
        &outp,
    )
    .expect_err("kurcalanmis pay KABUL EDILDI");
    assert!(
        format!("{e:?}").contains("kid"),
        "hata kid uyusmazligini adlandirmiyor"
    );
    // FAIL-CLOSED: yarim bir env dosyasi BIRAKILMAMALI.
    assert!(!outp.exists(), "reddedilen restore DOSYA BIRAKTI");
}

#[test]
fn verify_prints_the_wrap_kid_so_combine_has_something_to_compare_against() {
    // BULGUNUN KAYNAK YARISI. `dr combine --expect-kid` bir DEGER istiyor ve o
    // degerin geldigi yer burasi: kid replikadaki her manifest'in icinde
    // (`entries[].wrap.kid`) duruyor, `verify` o manifest'i zaten okuyup
    // ayristiriyordu ama kid'i BASMIYORDU.
    //
    // Bu iddia differential'a EK, onun yerine degil: iki ikili de kid'i
    // basmayi biraksaydi karsilastirma EQUAL derdi ve bulgu sessizce geri
    // gelirdi. (Olculdu: Rust tarafinda kid'i bozan bir mutasyon
    // differential'da DIFFERENT=3 verdi ama bu dosyadaki 20 iddianin HICBIRI
    // dusmedi — yani bu test o kor noktayi kapatiyor.)
    let d = tmpdir("verify-kid");
    let (snap, _) = restore_fixture(&d);
    let mut out = Vec::new();
    drverb::run_verify(&mut out, &snap).expect("verify");
    let s = String::from_utf8(out).expect("utf8");
    // Deger bir SIR DEGIL: master'in SHA-256'sinin ilk 16 hex'i, ve zaten
    // manifest'te aciktan duruyor.
    assert!(
        s.contains("kid=425ed4e4a36b30ea"),
        "verify ciktisi kid TASIMIYOR; operator beklenen degeri nereden alacak: {s}"
    );
}
