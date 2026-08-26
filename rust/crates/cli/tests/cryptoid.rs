// cryptoid IDDIA testleri — differential DEGIL, UCUNCU BIR ORACLE.
//
// NEDEN AYRI BIR SINIF: pty differential iki ikilinin PAYLASTIGI bir kusuru
// GOREMEZ. Rust'a yanlis ama Go ile AYNI sekilde yazilan bir HKDF `DIFFERENT=0`
// verir ve port yesil GORUNUR. Bu agacta o korluk iki kez CANLI goruldu
// (`doctorleak` sizintisi, `set`/`import-env` epoch bulgulari). Kripto
// cekirdeginin olcusu bu yuzden bir KARSILASTIRMA degil bir IDDIA olmak
// zorunda: beklenen degerler Go/TS'ten BAGIMSIZ olarak pinlenmis frozen
// vektorlerdir.
//
// SIR BASMA KURALI: bu dosyadaki hicbir assert BASARISIZLIKTA anahtar
// malzemesi BASMAZ. `assert_eq!` ham hex'i dokerdi; bunun yerine esitlik
// bool'a indirgeniyor ve mesaj yalnizca vektorun ADINI tasiyor. Degerler test
// vektorudur (gercek sir DEGIL) ama kural degerin gercekligine gore degil,
// ALISKANLIGA gore uygulaniyor.
use std::path::{Path, PathBuf};

use wapps::cryptoid::{
    blob_hash, derive_project_kek, kek_kid, open_blob, shamir_combine, shamir_split,
    unwrap_dek_with_kek, verify_blob_hash, Slot,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku")
        .to_path_buf()
}

/// frozen, capraz-dil vektor dosyasini okur. Bu dosyanin BUGUNKU tek gercek
/// tuketicisi `worker/test/blob.test.ts` (TS); Go tarafi ayni degerleri KOPYA
/// literaller olarak tasiyor. Rust dosyayi GERCEKTEN okuyarak ikinci gercek
/// tuketici oluyor — bir literal kopyasi, dosya degistiginde sessizce eskir.
fn frozen() -> serde_json::Value {
    let p = repo_root().join("worker/test/vectors/frozen_vectors.json");
    let raw = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("frozen vektor dosyasi okunamadi ({}): {e}", p.display()));
    serde_json::from_str(&raw).expect("frozen vektor JSON'u ayristirilamadi")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- §2.2 kid ------------------------------------------------------------------

#[test]
fn kek_kid_matches_the_frozen_kid_for_both_masters() {
    // Beklenenler internal/cryptoid/kek_test.go ile AYNI literaller (§2.2).
    for (master, want) in [
        ([0x22u8; 32], "9f72ea0cf49536e3"),
        ([0x33u8; 32], "deb0e38ced1e41de"),
    ] {
        let got = kek_kid(&master).expect("kid");
        assert!(
            got == want,
            "kid frozen vektorden SAPTI (master 0x{:02x}*32)",
            master[0]
        );
    }
}

#[test]
fn kek_kid_over_ascii_hex_differs_from_kid_over_raw_bytes() {
    // TUZAK (§2.2): girdi ASCII hex DIZESI degil, 32 HAM bayt. Hex geciren bir
    // port DERLENIR ve tamamen farkli bir kid uretir. Bu test o sessiz yanlisi
    // yakalar.
    let raw = [0x22u8; 32];
    let ascii_hex = "22".repeat(32);
    let over_raw = kek_kid(&raw).expect("kid");
    let over_ascii = kek_kid(&ascii_hex.as_bytes()[..32]).expect("kid");
    assert!(
        over_raw != over_ascii,
        "ASCII hex uzerinden kid HAM baytlarinkiyle ayni cikti"
    );
}

#[test]
fn kek_kid_refuses_anything_but_32_bytes() {
    assert!(kek_kid(&[0u8; 31]).is_err(), "31 bayt kabul edildi");
    assert!(kek_kid(&[0u8; 33]).is_err(), "33 bayt kabul edildi");
}

// --- §2.3 HKDF -----------------------------------------------------------------

#[test]
fn derive_project_kek_matches_the_frozen_keks() {
    // HKDF-SHA256(ikm=master, salt="wapps-secrets/kek/v1", info=project, L=32).
    // salt ya da info'daki TEK baytlik bir sapma bu iddiayi dusurur.
    let master = [0x22u8; 32];
    for (project, want) in [
        (
            "vaulter",
            "14de5786d70663c6fd42879ed2c391fbb2fd6d109b532410312cf2564e0902d5",
        ),
        (
            "lumira",
            "1413fbc058690c0ef5c01322013c1c80b2212cdaf6a99ba11e02084dd77555f0",
        ),
    ] {
        let kek = derive_project_kek(&master, project).expect("kek");
        assert!(hexs(&kek) == want, "KEK({project}) frozen vektorden SAPTI");
    }
}

#[test]
fn derive_project_kek_is_per_project() {
    let master = [0x22u8; 32];
    let a = derive_project_kek(&master, "vaulter").expect("kek");
    let b = derive_project_kek(&master, "lumira").expect("kek");
    assert!(a != b, "iki proje ayni KEK'i verdi — info baglanmiyor");
}

// --- §3.5.3 AAD ----------------------------------------------------------------

#[test]
fn slot_aad_matches_the_frozen_encoding() {
    // "vaulter" ‖ 00 ‖ "DATABASE_URL" ‖ 00 ‖ "3" (ondalik ASCII).
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);
    let want = "7661756c7465720044415441424153455f55524c0033";
    assert!(
        hexs(&slot.aad()) == want,
        "AAD kodlamasi frozen vektorden SAPTI"
    );
}

#[test]
fn slot_rejects_nul_in_project_or_key_name() {
    // NUL reddi AAD kodlamasinin INJEKTIF olmasinin sarti: NUL'a izin verilirse
    // iki farkli slot AYNI AAD'yi uretebilir ve bir wrap baska bir slota
    // replay edilebilir hale gelir.
    assert!(
        Slot::new("vau\0lter", "K", 1).validate().is_err(),
        "project'te NUL kabul edildi"
    );
    assert!(
        Slot::new("vaulter", "K\0EY", 1).validate().is_err(),
        "keyName'de NUL kabul edildi"
    );
    assert!(
        Slot::new("vaulter", "KEY", 1).validate().is_ok(),
        "temiz slot reddedildi"
    );
}

#[test]
fn slot_aad_uses_decimal_ascii_for_key_version() {
    // keyVersion ONDALIK ASCII; bir port onu tek bayt ya da BE-u64 yazsaydi
    // uzunluk degisirdi ve bu test dusserdi.
    let slot = Slot::new("p", "K", 10);
    assert!(
        slot.aad().ends_with(b"\x0010"),
        "keyVersion ondalik ASCII olarak kodlanmadi"
    );
}

// --- §3.5.4 icerik adresi ------------------------------------------------------

#[test]
fn blob_hash_matches_the_frozen_content_address() {
    let f = frozen();
    let blob = unhex(f["blob"]["blob_hex"].as_str().expect("blob_hex"));
    let want = f["blob"]["blob_hash"].as_str().expect("blob_hash");
    assert!(
        blob_hash(&blob) == want,
        "blob icerik adresi frozen vektorden SAPTI"
    );
}

#[test]
fn verify_blob_hash_accepts_uppercase_and_rejects_tamper() {
    let f = frozen();
    let mut blob = unhex(f["blob"]["blob_hex"].as_str().expect("blob_hex"));
    let want = f["blob"]["blob_hash"].as_str().expect("blob_hash");
    assert!(
        verify_blob_hash(&blob, want).is_ok(),
        "dogru hash reddedildi"
    );
    assert!(
        verify_blob_hash(&blob, &want.to_uppercase()).is_ok(),
        "buyuk harf hash reddedildi"
    );
    let n = blob.len() - 1;
    blob[n] ^= 0x01;
    assert!(
        verify_blob_hash(&blob, want).is_err(),
        "kurcalanmis blob kabul edildi"
    );
}

// --- §3.9 Shamir ---------------------------------------------------------------

#[test]
fn shamir_split_reproduces_the_frozen_shares_under_the_pinned_rng() {
    // BU TEST PORTUN BIR TASARIM KISITINI OLCUYOR: `shamir_split` RNG'yi
    // PARAMETRE aliyor. Almasaydi bu vektor kullanilamaz ve `split`in kripto
    // cekirdegi HIC olculemezdi (differential de olcemez — cikti her kosumda
    // farkli olurdu).
    let f = frozen();
    let secret = unhex(f["shamir"]["secret_hex"].as_str().expect("secret_hex"));
    let pattern = unhex(
        f["shamir"]["rng_pattern_hex"]
            .as_str()
            .expect("rng_pattern_hex"),
    );
    let parts = f["shamir"]["parts"].as_u64().expect("parts") as usize;
    let threshold = f["shamir"]["threshold"].as_u64().expect("threshold") as usize;
    let want: Vec<String> = f["shamir"]["shares_hex"]
        .as_array()
        .expect("shares_hex")
        .iter()
        .map(|v| v.as_str().expect("share").to_string())
        .collect();

    // Sabit RNG: deseni tekrarlayan bir akis (Go testindeki bytes.Repeat ile ayni).
    let mut rng = std::iter::repeat(pattern.clone())
        .flatten()
        .take(4096)
        .collect::<Vec<u8>>();
    let shares = shamir_split(&secret, parts, threshold, &mut rng.as_slice()).expect("split");
    assert!(
        shares.len() == parts,
        "pay sayisi {} != {parts}",
        shares.len()
    );
    for (i, sh) in shares.iter().enumerate() {
        assert!(hexs(sh) == want[i], "shamir pay {i} FROZEN vektorden SAPTI");
    }
    rng.clear();
}

#[test]
fn shamir_combine_recovers_the_secret_from_the_frozen_shares() {
    let f = frozen();
    let secret = unhex(f["shamir"]["secret_hex"].as_str().expect("secret_hex"));
    let shares: Vec<Vec<u8>> = f["shamir"]["shares_hex"]
        .as_array()
        .expect("shares_hex")
        .iter()
        .map(|v| unhex(v.as_str().expect("share")))
        .collect();
    // Herhangi 2 pay (threshold=2) sirri geri vermeli — ucu de denenir.
    for pair in [[0usize, 1], [0, 2], [1, 2]] {
        let subset = vec![shares[pair[0]].clone(), shares[pair[1]].clone()];
        let got = shamir_combine(&subset).expect("combine");
        assert!(got == secret, "pay cifti {pair:?} sirri geri vermedi");
    }
}

#[test]
fn shamir_round_trip_holds_for_every_pair() {
    let secret = [0x5Au8; 32];
    let mut rng: &[u8] = &[0x11u8; 4096];
    let shares = shamir_split(&secret, 3, 2, &mut rng).expect("split");
    for pair in [[0usize, 1], [0, 2], [1, 2]] {
        let subset = vec![shares[pair[0]].clone(), shares[pair[1]].clone()];
        assert!(
            shamir_combine(&subset).expect("combine") == secret,
            "cift {pair:?} donmedi"
        );
    }
}

#[test]
fn shamir_combine_yields_a_silently_wrong_key_for_a_tampered_share() {
    // SESSIZ ARIZA BICIMININ TA KENDISI, ve BILEREK PINLENIYOR: Shamir
    // BUTUNLUK SAGLAMAZ. Bozuk bir pay HATA VERMEZ — dogru uzunlukta, dogru
    // GORUNUMLU, YANLIS bir anahtar doner. Bu testin adi bir hatirlatma:
    // `dr combine`in uyari satiri bir sus degil, bu davranisin TEK savunmasi.
    let secret = [0x5Au8; 32];
    let mut rng: &[u8] = &[0x11u8; 4096];
    let shares = shamir_split(&secret, 3, 2, &mut rng).expect("split");
    let mut bad = shares[0].clone();
    bad[0] ^= 0xFF;
    let got = shamir_combine(&[bad, shares[1].clone()]).expect("combine HATA VERMEMELI");
    assert!(got.len() == 32, "bozuk pay 32 bayt DISINDA bir sey verdi");
    assert!(got != secret, "bozuk pay dogru sirri verdi (imkansiz)");
}

#[test]
fn shamir_combine_rejects_structurally_invalid_share_sets() {
    let secret = [0x5Au8; 32];
    let mut rng: &[u8] = &[0x11u8; 4096];
    let shares = shamir_split(&secret, 3, 2, &mut rng).expect("split");
    assert!(
        shamir_combine(&shares[..1]).is_err(),
        "tek pay kabul edildi"
    );
    assert!(
        shamir_combine(&[shares[0].clone(), shares[0].clone()]).is_err(),
        "yinelenen x kabul edildi"
    );
    let short = shares[1][..shares[1].len() - 2].to_vec();
    assert!(
        shamir_combine(&[shares[0].clone(), short]).is_err(),
        "esit olmayan uzunluk kabul edildi"
    );
    let mut zero_x = shares[1].clone();
    let n = zero_x.len() - 1;
    zero_x[n] = 0;
    assert!(
        shamir_combine(&[shares[0].clone(), zero_x]).is_err(),
        "x=0 kabul edildi"
    );
}

#[test]
fn shamir_split_rejects_invalid_parameters() {
    let mut rng: &[u8] = &[0x11u8; 4096];
    assert!(
        shamir_split(&[], 3, 2, &mut rng).is_err(),
        "bos sir kabul edildi"
    );
    assert!(
        shamir_split(&[1, 2], 2, 3, &mut rng).is_err(),
        "parts < threshold kabul edildi"
    );
    assert!(
        shamir_split(&[1, 2], 3, 1, &mut rng).is_err(),
        "threshold < 2 kabul edildi"
    );
    assert!(
        shamir_split(&[1, 2], 256, 2, &mut rng).is_err(),
        "parts > 255 kabul edildi"
    );
}

#[test]
fn shamir_split_fails_closed_when_the_rng_is_short() {
    // Kisa okuma = HATA (fail-closed). Sessizce sifirla doldurmak polinomun
    // rastgele katsayilarini yok eder ve paylardan sir SIZAR.
    let mut rng: &[u8] = &[0x11u8; 3];
    assert!(
        shamir_split(&[0u8; 32], 3, 2, &mut rng).is_err(),
        "kisa RNG kabul edildi"
    );
}

// --- §3.5.4 WSB1 blob acma (XChaCha20-Poly1305) --------------------------------
//
// BU TESTIN OLCTUGU SEY BIR CRATE KARARIDIR. `ring` XChaCha20-Poly1305
// TASIMIYOR (`xchacha` kaynakta sifir kez, NONCE_LEN=12). Port onu RustCrypto
// ekleyerek degil, HChaCha20'yi elde yazip `ring`in duz ChaCha20-Poly1305'ine
// baglayarak cozuyor. O turetimin DOGRU oldugunu soyleyen tek sey bu vektor:
// frozen `blob_hex`, Go/TS tarafindan uretilmis GERCEK bir WSB1 blob'u, ve
// acilisi `plaintext` alanini bayt bayt geri vermeli. Turetim bir bit
// kayarsa AEAD auth'u duser ve bu test kirmizi olur.
#[test]
fn open_blob_opens_the_frozen_wsb1_blob() {
    let f = frozen();
    let b = &f["blob"];
    let dek: [u8; 32] = unhex(b["dek_hex"].as_str().unwrap()).try_into().unwrap();
    let slot = Slot::new(
        b["slot"]["project"].as_str().unwrap(),
        b["slot"]["keyName"].as_str().unwrap(),
        b["slot"]["keyVersion"].as_u64().unwrap(),
    );
    let blob = unhex(b["blob_hex"].as_str().unwrap());
    let pt = open_blob(&blob, &dek, &slot).expect("frozen WSB1 blob ACILMALI");
    // Plaintext bir test vektoru ama yine de DEGER basilmiyor (§sir kurali).
    assert!(
        pt == b["plaintext"].as_str().unwrap().as_bytes(),
        "acilan plaintext frozen vektorden SAPTI ({} bayt)",
        pt.len()
    );
}

// --- §2.4 WKW1 DEK unwrap ---------------------------------------------------------
//
// BU VEKTOR BU SERITTE EKLENDI, ve neden onemli: WKW1'in HICBIR YERDE frozen
// bir BAYT vektoru YOKTU (docs/PORT-dr.md §7.3). Go tarafindaki
// TestWKW1RoundTripAndSlotBinding bir ROUND-TRIP'tir (nonce rastgele) — kendi
// sardigini kendi acar, yani yanlis-ama-tutarli bir implementasyonu YESIL
// gecirir. Buradaki vektor `internal/cryptoid.WrapDEKForKEK` tarafindan SABIT
// bir nonce ile URETILDI, yani Rust'in acisini Go'nun GERCEK baytlarina
// pinliyor. Bu bir karsilastirma degil, ucuncu bir oracle.
#[test]
fn unwrap_dek_with_kek_opens_the_go_generated_wkw1_wrap() {
    let f = frozen();
    let k = &f["wkw1"];
    let master = unhex(k["master_hex"].as_str().unwrap());
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);
    let wrap = unhex(k["wrap_hex"].as_str().unwrap());
    assert!(
        wrap.len() == 76,
        "WKW1 cercevesi 76 bayt olmali, {} bulundu",
        wrap.len()
    );
    let dek =
        unwrap_dek_with_kek(&master, "vaulter", &slot, &wrap).expect("Go'nun WKW1 wrap'i ACILMALI");
    assert!(
        hexs(&dek) == k["dek_hex"].as_str().unwrap(),
        "acilan DEK frozen vektorden SAPTI"
    );
}

/// Wrap'in SLOT'a baglandigini olcer: ayni wrap baska bir projeye/anahtara/
/// versiyona REPLAY EDILEMEZ. AAD yanlis kurulursa (ornegin keyVersion
/// atlanirsa) bu test kirmizi olur — ve o hata differential'da GORUNMEZDI,
/// cunku iki ikili de ayni yanlis AAD'yi paylasabilir.
#[test]
fn wkw1_wrap_does_not_replay_to_another_slot() {
    let f = frozen();
    let k = &f["wkw1"];
    let master = unhex(k["master_hex"].as_str().unwrap());
    let wrap = unhex(k["wrap_hex"].as_str().unwrap());
    for (project, key, ver) in [
        ("vaulter", "DATABASE_URL", 4u64), // versiyon kaydi
        ("vaulter", "OTHER_KEY", 3),       // anahtar adi kaydi
        ("other", "DATABASE_URL", 3),      // proje kaydi (KEK de degisir)
    ] {
        let slot = Slot::new(project, key, ver);
        assert!(
            unwrap_dek_with_kek(&master, project, &slot, &wrap).is_err(),
            "wrap {project}/{key}/v{ver} slotuna REPLAY EDILEBILDI"
        );
    }
}

/// Cerceve ihlalleri fail-closed: kisa/uzun wrap ve yanlis magic.
#[test]
fn wkw1_rejects_framing_violations() {
    let f = frozen();
    let k = &f["wkw1"];
    let master = unhex(k["master_hex"].as_str().unwrap());
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);
    let good = unhex(k["wrap_hex"].as_str().unwrap());

    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    let mut too_long = good.clone();
    too_long.push(0);

    for (name, w) in [
        ("bos", Vec::new()),
        ("kisa", good[..75].to_vec()),
        ("uzun", too_long),
        ("yanlis magic", bad_magic),
    ] {
        assert!(
            unwrap_dek_with_kek(&master, "vaulter", &slot, &w).is_err(),
            "{name} wrap KABUL EDILDI"
        );
    }
}

/// Kurcalanmis bir ciphertext baytinin AEAD'de dusmesi gerekir — WKW1'in
/// butunluk sagladigi yer burasi (Shamir'in AKSINE, ki o saglamaz).
#[test]
fn wkw1_rejects_a_tampered_ciphertext_byte() {
    let f = frozen();
    let k = &f["wkw1"];
    let master = unhex(k["master_hex"].as_str().unwrap());
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);
    let mut w = unhex(k["wrap_hex"].as_str().unwrap());
    let last = w.len() - 1;
    w[last] ^= 0x01;
    assert!(
        unwrap_dek_with_kek(&master, "vaulter", &slot, &w).is_err(),
        "kurcalanmis WKW1 wrap KABUL EDILDI"
    );
}

/// Yanlis master (yani yanlis KEK) acmamali. `dr restore`un kid kontrolu bu
/// dususu ONCEDEN yakalar; bu test o kontrolun ARKASINDAKI savunmayi olcer.
#[test]
fn wkw1_rejects_a_wrong_master_key() {
    let f = frozen();
    let k = &f["wkw1"];
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);
    let wrap = unhex(k["wrap_hex"].as_str().unwrap());
    assert!(
        unwrap_dek_with_kek(&[0x43u8; 32], "vaulter", &slot, &wrap).is_err(),
        "yanlis master ile WKW1 ACILDI"
    );
}

/// WSB1 tamper savunmalari: magic, kisa girdi, kurcalanmis ciphertext.
#[test]
fn open_blob_rejects_tamper_and_bad_framing() {
    let f = frozen();
    let b = &f["blob"];
    let dek: [u8; 32] = unhex(b["dek_hex"].as_str().unwrap()).try_into().unwrap();
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);
    let good = unhex(b["blob_hex"].as_str().unwrap());

    let mut bad_magic = good.clone();
    bad_magic[3] = b'2';
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    for (name, blob) in [
        ("bos", Vec::new()),
        ("yalnizca overhead", vec![0u8; 44]),
        ("yanlis magic", bad_magic),
        ("kurcalanmis ct", tampered),
    ] {
        assert!(
            open_blob(&blob, &dek, &slot).is_err(),
            "{name} blob KABUL EDILDI"
        );
    }
    // Yanlis slot (AAD) da dusmeli — blob da slotuna baglidir.
    assert!(
        open_blob(&good, &dek, &Slot::new("vaulter", "DATABASE_URL", 4)).is_err(),
        "blob baska bir slota REPLAY EDILEBILDI"
    );
}

/// §3.5.2 padding TAMPER SAVUNMALARI — ve bu test bir MUTASYONUN urunu.
///
/// `unpad`in sifir-dolgu kontrolu SILINDIGINDE tum suit YESIL kaldi: hicbir
/// vektor o dali gezmiyordu. Buradaki girdiler YAPISAL OLARAK GECERLI WSB1
/// konteynerleri — dogru magic, dogru nonce, AEAD etiketi DOGRULANIYOR — ama
/// cozulen padded formlari kurallari ihlal ediyor. Yani yalnizca `unpad`i
/// olcuyorlar: dogru cozup padding kontrollerini atlayan bir implementasyon
/// bu dosyadaki DIGER her vektoru gecer ve SADECE burada duser.
///
/// Bu, differential'in yapisal olarak goremeyecegi siniftan: iki ikili de
/// kontrolu atlasaydi karsilastirma EQUAL derdi.
#[test]
fn open_blob_enforces_the_padding_rules() {
    let f = frozen();
    let n = &f["blob_padding_negatives"];
    let dek: [u8; 32] = unhex(n["dek_hex"].as_str().unwrap()).try_into().unwrap();
    let slot = Slot::new("vaulter", "DATABASE_URL", 3);

    // Kontrol: AYNI yoldan uretilmis GECERLI konteyner ACILMALI. Bu olmadan
    // asagidaki dort reddin "her sey duser"den ayirt edilmesi mumkun olmazdi.
    let good = unhex(n["good_hex"].as_str().unwrap());
    let pt = open_blob(&good, &dek, &slot).expect("gecerli konteyner ACILMALI");
    assert!(
        pt.len() == 5,
        "kontrol vektorunun uzunlugu {} (5 bekleniyor)",
        pt.len()
    );

    for name in [
        "nonzero_fill_hex",         // dolgu baytlarindan biri SIFIR DEGIL
        "len_overflows_bucket_hex", // uzunluk oneki KOVAYI asiyor
        "not_a_valid_bucket_hex",   // padded boyut TANINAN bir kova degil
    ] {
        let blob = unhex(n[name].as_str().unwrap());
        assert!(
            open_blob(&blob, &dek, &slot).is_err(),
            "{name}: padding ihlali KABUL EDILDI"
        );
    }
}
