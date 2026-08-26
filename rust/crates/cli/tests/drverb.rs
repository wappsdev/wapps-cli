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
    drverb::run_combine_core(&mut out, &[s1, s3], &outp).expect("combine");
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
    // BU BIR SUS DEGIL, TEK SAVUNMA. ShamirCombine yanlis paylarda HATA
    // VERMEZ; dogru uzunlukta, YANLIS bir anahtar doner. Operatorun bunu
    // anlamasinin TEK yolu kid'i karsilastirmasi, ve bunu soyleyen tek sey bu
    // uyari satiri. Uyari duserse tore SESSIZCE yanlis tamamlanir.
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
    )
    .expect("combine");
    let s = String::from_utf8(out).expect("utf8");
    assert!(
        s.contains("VERIFY this kid"),
        "kid dogrulama cagrisi yok: {s}"
    );
    assert!(
        s.contains("silently-WRONG"),
        "sessiz-yanlis uyarisi yok: {s}"
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
    let e = drverb::run_combine_core(&mut Vec::new(), &[p, q], &d.join("o.hex"))
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
    )
    .expect("bosluklu pay kabul edilmeliydi");
    assert_eq!(std::fs::read_to_string(&outp).expect("read").trim(), mh);
}
