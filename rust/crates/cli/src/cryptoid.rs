// cryptoid — `wapps dr`in kripto cekirdegi (SPEC §2.2–§2.5, §3.5, §3.9).
//
// KAPSAM: bu modul Go'daki internal/cryptoid'in `dr`in ihtiyac duydugu alt
// kumesini tasir — kid turetimi (§2.2), per-proje KEK (§2.3), slot AAD
// (§3.5.3), icerik adresi (§3.5.4), Shamir (§3.9), ve `dr restore` ile
// birlikte XChaCha20-Poly1305 uzerinden WKW1 unwrap (§2.4) + WSB1 acma
// (§3.5.4).
//
// BIR ONCEKI TURUN BURAYA YAZDIGI IDDIA CURUTULDU, ve nasil curutuldugu
// onemli. Iddia suydu: "`UnwrapDEKWithKEK` ve `OpenBlob` XChaCha20-Poly1305
// istiyor, `ring` onu tasimiyor, yani `dr restore` YENI BIR CRATE olmadan
// portlanamaz." OLCUMUN ILK YARISI DOGRUYDU ve bagimsiz olarak yeniden
// dogrulandi: `ring 0.17.14` kaynaginda `xchacha` SIFIR kez geciyor,
// `NONCE_LEN` = 96/8 = 12. Ama SONUC yanlisti — "ring'de XChaCha yok" ile
// "XChaCha portlanamaz" ayni sey degil:
//
//     XChaCha = HChaCha20 (bir PERMUTASYON) + ring'in ZATEN tasidigi
//               duz ChaCha20-Poly1305
//
// Yeni crate SIFIR (bkz. asagidaki XChaCha bolumu ve docs/PORT-dr.md §7.1).
//
// ULASILABILIRLIK — ONCEKI TURUN BURAYA YAZDIGI BOSLUK KAPANDI. O tur soyle
// yazmisti: "derive_project_kek 0, Slot::aad 0 -> BUGUN OLU; frozen vektore
// karsi yesil duran iki test, hicbir kullanicinin varamayacagi bir kodu
// koruyor." `dr restore` indigi icin o iki fonksiyon artik CANLI ve zincir
// uctan uca izlenebilir:
//
//   clap `dr restore` -> run_dr_restore -> restore_project_from_snapshot
//     -> unwrap_dek_with_kek -> derive_project_kek + Slot::aad
//                            -> xchacha20_poly1305_open -> hchacha20
//     -> open_blob -> unpad -> is_valid_bucket
//
// Kural aynen duruyor ve bu modulun her yeni fonksiyonu icin sorulmali:
// "test var" ile "davranis sevk ediliyor" AYNI SEY DEGIL.
//
use ring::digest;
use ring::hkdf;
use std::io::Read;

/// hkdf_salt, per-proje KEK turetiminin sabit salt'i (20 ASCII bayt, §2.3).
const HKDF_SALT: &[u8] = b"wapps-secrets/kek/v1";

/// WRAP_RECIPIENT, v2 manifest'lerdeki tek gecerli wrap alicisi (kapali kume, §2.4).
pub const WRAP_RECIPIENT: &str = "worker-kek:v1";

/// kek_kid, bir master anahtarin kid'ini turetir: SHA-256(32 HAM bayt)'in ilk
/// 16 kucuk-harf hex karakteri (§2.2).
///
/// TUZAK — VE BU IMZA O TUZAGI KAPATMIYOR: girdi ASLA ASCII hex dizesi
/// degildir. `&[u8]` bir hex dizesinin baytlarini da kabul eder, DERLENIR ve
/// tamamen farkli bir kid uretir. Uzunluk kontrolu 32 hex karakterlik bir
/// dizeyi de gecirir. Tek gercek savunma testtir:
/// `kek_kid_over_ascii_hex_differs_from_kid_over_raw_bytes`.
pub fn kek_kid(raw: &[u8]) -> Result<String, String> {
    if raw.len() != 32 {
        return Err("cryptoid.KekKid: master key must be 32 raw bytes".to_string());
    }
    let sum = digest::digest(&digest::SHA256, raw);
    let hex: String = sum.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok(hex[..16].to_string())
}

/// okm_len, `ring`in HKDF expand'ine cikti uzunlugunu tasiyan tip. `ring`
/// uzunlugu bir TIP uzerinden istiyor (Go'nun io.ReadFull(r, buf) kaliginin
/// karsiligi); bu kucuk sarmalayici o farki kapatiyor.
#[derive(Clone, Copy)]
struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// derive_project_kek, per-project KEK'i turetir (§2.3):
/// HKDF-SHA-256(ikm=master, salt="wapps-secrets/kek/v1", info=project, L=32).
pub fn derive_project_kek(master: &[u8], project: &str) -> Result<[u8; 32], String> {
    if master.len() != 32 {
        return Err("cryptoid.DeriveProjectKEK: master key must be 32 raw bytes".to_string());
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT).extract(master);
    // info TEK bir parca: Go `hkdf.New(..., []byte(project))` ile birebir.
    // Birden fazla parca verilseydi ring onlari BITISTIRIR — ayni bayt dizisi
    // ciktigi surece esit, ama parcalama bir port ayrintisi olarak kalmasin.
    let info = [project.as_bytes()];
    let okm = prk
        .expand(&info, OkmLen(32))
        .map_err(|_| "cryptoid.DeriveProjectKEK: hkdf expand".to_string())?;
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .map_err(|_| "cryptoid.DeriveProjectKEK: hkdf fill".to_string())?;
    Ok(out)
}

/// Slot, bir degerin mantiksal yerini tanimlar: (project, keyName, keyVersion).
#[derive(Clone, Debug)]
pub struct Slot {
    pub project: String,
    pub key_name: String,
    pub key_version: u64,
}

impl Slot {
    pub fn new(project: impl Into<String>, key_name: impl Into<String>, key_version: u64) -> Self {
        Slot {
            project: project.into(),
            key_name: key_name.into(),
            key_version,
        }
    }

    /// validate, project/keyName'in NUL ICERMEDIGINI dogrular (§3.5.3). Bu, AAD
    /// kodlamasinin INJEKTIF olmasinin sarti: NUL serbest birakilirsa iki
    /// farkli slot ayni AAD'yi uretebilir ve bir wrap baska bir slota replay
    /// edilebilir.
    pub fn validate(&self) -> Result<(), String> {
        if self.project.as_bytes().contains(&0x00) {
            return Err("cryptoid: project name must not contain NUL".to_string());
        }
        if self.key_name.as_bytes().contains(&0x00) {
            return Err("cryptoid: key name must not contain NUL".to_string());
        }
        Ok(())
    }

    /// aad, ciphertext'i mantiksal slot'una baglayan ek dogrulama verisi:
    /// project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion(ondalik ASCII) (§3.5.3).
    pub fn aad(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(self.project.as_bytes());
        b.push(0x00);
        b.extend_from_slice(self.key_name.as_bytes());
        b.push(0x00);
        b.extend_from_slice(self.key_version.to_string().as_bytes());
        b
    }
}

/// blob_hash, blob'un icerik adresi: TUM depolanan baytlar uzerinde kucuk-harf
/// hex SHA-256 (§3.5.4).
pub fn blob_hash(blob: &[u8]) -> String {
    let sum = digest::digest(&digest::SHA256, blob);
    sum.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// verify_blob_hash, getirilen blob baytlarinin beklenen cipla-hex icerik
/// adresiyle eslestigini parse/decrypt ONCESI dogrular (§3.5.4).
///
/// Karsilastirma SABIT ZAMANLI (Go `subtle.ConstantTimeCompare`).
///
/// `ring::constant_time::verify_slices_are_equal` KULLANILMIYOR: 0.17'de
/// deprecated ve kendi notu "no promises regarding side channels" diyor. Bir
/// yan-kanal vaadini, o vaadi acikca geri ceken bir API'ye dayandirmak sahte
/// sadakat olurdu. Karsilastirma burada ELDE yazili ve uzunluk esitse ERKEN
/// CIKMIYOR — Go'nun subtle'iyla ayni sozlesme.
pub fn verify_blob_hash(blob: &[u8], expected_hex: &str) -> Result<(), String> {
    let got = blob_hash(blob);
    let want = expected_hex.to_ascii_lowercase();
    if !constant_time_eq(got.as_bytes(), want.as_bytes()) {
        return Err("cryptoid: BLOB_HASH_MISMATCH".to_string());
    }
    Ok(())
}

/// constant_time_eq, esit uzunluktaki iki dilimi erken cikmadan karsilastirir.
/// Uzunluk farki gizli DEGIL (hash uzunlugu sabit), o yuzden onda erken cikilir.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- §3.9 Shamir Secret Sharing, GF(2^8) --------------------------------------
//
// HashiCorp Vault'un GF(2^8) Shamir algoritmasinin portu (MPL-2.0), Go tarafi
// ile ayni. Harici crate BAGIMLILIGI YOK ve OLMAMALI: algoritma frozen
// vektorle pinli (`tests/cryptoid.rs`), yani bir crate'in getirecegi tek sey
// denetlenecek fazladan yuzey olurdu.
//
// Pay formati: her pay = [len(secret) bayt y-degeri] ‖ [1 bayt x-koordinat].

/// GF_TABLES, log/exp tablolari (indirgeme polinomu 0x11b, uretec 0x03).
/// DERLEME ZAMANINDA kuruluyor — Go'daki `init()`in karsiligi, ama kilit yok.
const GF_TABLES: ([u8; 256], [u8; 256]) = build_gf_tables();

const fn gf_mul_no_table(a: u8, b: u8) -> u8 {
    let (mut a, mut b, mut p) = (a, b, 0u8);
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

const fn build_gf_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x = 1u8;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        x = gf_mul_no_table(x, 3);
        i += 1;
    }
    // gf_exp[255] pratikte kullanilmaz; wrap icin gf_exp[0]'a esitlenir (Go ile ayni).
    exp[255] = exp[0];
    (exp, log)
}

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = &GF_TABLES;
    exp[(log[a as usize] as usize + log[b as usize] as usize) % 255]
}

fn gf_inv(a: u8) -> u8 {
    // 0'in tersi tanimsiz; cagiranlar bunu asla tetiklememeli (Go panik ediyor).
    assert!(a != 0, "cryptoid: gf_inv(0)");
    let (exp, log) = &GF_TABLES;
    exp[(255 - log[a as usize] as usize) % 255]
}

fn gf_div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "cryptoid: gf_div by zero");
    if a == 0 {
        return 0;
    }
    gf_mul(a, gf_inv(b))
}

/// gf_eval, polinomu x noktasinda degerlendirir (Horner; poly[0] = sabit terim).
fn gf_eval(poly: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for i in (0..poly.len()).rev() {
        result = gf_add(gf_mul(result, x), poly[i]);
    }
    result
}

/// shamir_split, secret'i `parts` paya boler; herhangi `threshold` pay geri toplar.
///
/// RNG BIR PARAMETRE, VE BU BIR TASARIM KISITI — SONRADAN EKLENEMEZ. Go tarafi
/// `rng io.Reader` aliyor ve frozen vektor (`shamir.rng_pattern_hex`) tam da
/// bunun sayesinde var. RNG iceride sabitlenseydi `split` DETERMINISTIK olarak
/// pinlenemez, differential'lanamaz (cikti her kosumda farkli) ve dolayisiyla
/// HIC olculemezdi.
pub fn shamir_split(
    secret: &[u8],
    parts: usize,
    threshold: usize,
    rng: &mut dyn Read,
) -> Result<Vec<Vec<u8>>, String> {
    if secret.is_empty() {
        return Err("cryptoid.ShamirSplit: empty secret".to_string());
    }
    if parts < threshold {
        return Err("cryptoid.ShamirSplit: parts < threshold".to_string());
    }
    if threshold < 2 {
        return Err("cryptoid.ShamirSplit: threshold < 2".to_string());
    }
    if parts > 255 {
        return Err("cryptoid.ShamirSplit: parts > 255".to_string());
    }

    // x-koordinatlari sabit: 1..parts (0 ASLA kullanilamaz; x=0 sirrin kendisi).
    let mut shares: Vec<Vec<u8>> = (0..parts)
        .map(|i| {
            let mut s = vec![0u8; secret.len() + 1];
            s[secret.len()] = (i + 1) as u8;
            s
        })
        .collect();

    let mut poly = vec![0u8; threshold];
    for (j, &sb) in secret.iter().enumerate() {
        poly[0] = sb; // sabit terim = gizli bayt
                      // Kisa okuma = HATA (fail-closed). Sifirla doldurmak katsayilari yok
                      // eder ve paylardan sir sizar.
        rng.read_exact(&mut poly[1..])
            .map_err(|e| format!("cryptoid.ShamirSplit: rng: {e}"))?;
        for (i, share) in shares.iter_mut().enumerate() {
            share[j] = gf_eval(&poly, (i + 1) as u8);
        }
    }
    poly.iter_mut().for_each(|b| *b = 0);
    Ok(shares)
}

/// shamir_combine, paylari Lagrange interpolasyonuyla x=0'da birlestirir.
///
/// SESSIZ ARIZA — PORTLANAN DAVRANIS: bu fonksiyon YANLIS ama YAPISAL OLARAK
/// GECERLI paylarda HATA VERMEZ. Dogru uzunlukta, dogru gorunumlu, YANLIS bir
/// anahtar doner. Shamir butunluk SAGLAMAZ. Reddedilen tek seyler yapisal
/// ihlaller (tek pay, yinelenen x, esit olmayan uzunluk, x=0). Cagiranin
/// savunmasi kid karsilastirmasidir — `dr combine` bu yuzden kid basar ve
/// uyarir.
pub fn shamir_combine(shares: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if shares.len() < 2 {
        return Err("cryptoid.ShamirCombine: need at least 2 shares".to_string());
    }
    let share_len = shares[0].len();
    if share_len < 2 {
        return Err("cryptoid.ShamirCombine: share too short".to_string());
    }
    let mut xs = Vec::with_capacity(shares.len());
    for sh in shares {
        if sh.len() != share_len {
            return Err("cryptoid.ShamirCombine: shares have unequal length".to_string());
        }
        let x = sh[share_len - 1];
        if x == 0 {
            return Err("cryptoid.ShamirCombine: invalid x-coordinate 0".to_string());
        }
        if xs.contains(&x) {
            return Err("cryptoid.ShamirCombine: duplicate x-coordinate".to_string());
        }
        xs.push(x);
    }

    let secret_len = share_len - 1;
    let mut secret = vec![0u8; secret_len];
    for (j, out) in secret.iter_mut().enumerate() {
        // Lagrange, x=0'da: sum_i y_i * prod_{k!=i} x_k/(x_i - x_k).
        let mut result = 0u8;
        for (i, sh) in shares.iter().enumerate() {
            let yi = sh[j];
            let mut num = 1u8;
            let mut den = 1u8;
            for (k, &xk) in xs.iter().enumerate() {
                if k == i {
                    continue;
                }
                num = gf_mul(num, xk); // (0 - x_k) = x_k  (GF'de -a = a)
                den = gf_mul(den, gf_add(xs[i], xk)); // (x_i - x_k) = x_i xor x_k
            }
            result = gf_add(result, gf_mul(yi, gf_div(num, den)));
        }
        *out = result;
    }
    Ok(secret)
}

// --- XChaCha20-Poly1305 (§2.4 WKW1, §3.5.4 WSB1) ---------------------------------
//
// `ring` XChaCha20-Poly1305 TASIMIYOR (olculdu: kaynakta `xchacha` sifir kez,
// `NONCE_LEN` = 96/8 = 12). Ama XChaCha, ChaCha'nin YERINE gecen bir sifre
// DEGIL, onun onune konan bir ANAHTAR TURETME adimidir:
//
//   XChaCha20-Poly1305(key, nonce24, aad) =
//       ChaCha20-Poly1305(HChaCha20(key, nonce24[0..16]),
//                         0x00000000 ‖ nonce24[16..24], aad)
//
// Yani gereken tek sey HChaCha20, ve o bir PROTOKOL degil bir PERMUTASYON:
// ChaCha20'nin cift-tur cekirdegi, SON TOPLAMA ADIMI OLMADAN, durumun ilk ve
// son dortlulerini birlestirerek 32 bayt dondurur. Durum tasimaz, dallanmaz,
// uzunluga bagli degildir.
//
// BU BIR CRATE KARARIDIR VE OLCULEREK ALINDI (docs/PORT-dr.md §7.1):
//   RustCrypto `chacha20poly1305`  -> +14 crate, `cargo deny` 0, IKINCI denetim yuzeyi
//   HChaCha20 elde + `ring`in AEAD'i -> +0 crate, `cargo deny` 0, tek yuzey
// Aday deny'i GECIYORDU — yani karar bir gate karari degil bir POLITIKA
// karari, ve Cargo.toml'daki `ring` gerekcesi (`sha2` uc crate ekleyecegi ve
// "iki ayri denetim yuzeyi" olacagi icin REDDEDILDI) ayni gerekceyi +14
// crate'e KAT KAT daha guclu uyguluyor.
//
// "Elde kripto yazmak" itirazi burada gecerli DEGIL cunku olcu tahmine
// birakilmiyor: `open_blob` frozen `blob_hex` vektorune karsi BAYT DUZEYINDE
// pinli (Go/TS uretimi gercek bir blob), `unwrap_dek_with_kek` ise Go'nun
// URETTIGI frozen bir WKW1 wrap'ine karsi. Turetim bir bit kayarsa AEAD
// auth'u duser ve testler kirmizi olur. Shamir'in (GF(2^8)) ayni gerekceyle
// elde yazilmis olmasiyla AYNI karar.

/// XCHACHA_NONCE_LEN, XChaCha20-Poly1305'in nonce uzunlugu (24 bayt).
pub const XCHACHA_NONCE_LEN: usize = 24;

/// quarter_round, ChaCha20'nin dortte-bir turu (RFC 8439 §2.1).
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// hchacha20, HChaCha20 alt-anahtar turetimi: 32 baytlik anahtar + 16 baytlik
/// nonce -> 32 baytlik alt-anahtar (RFC draft-irtf-cfrg-xchacha §2.2).
///
/// ChaCha20 blok fonksiyonundan TEK farki: 20 turdan sonra baslangic durumu
/// GERI EKLENMEZ; cikti dogrudan durumun 0..4 ve 12..16 kelimelerinden
/// (little-endian) toplanir. O toplama adimini yanlislikla eklemek sessizce
/// YANLIS ama ayni boyda bir anahtar uretirdi — frozen vektor tam olarak bunu
/// yakalar.
fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let w = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut s: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        w(&key[0..4]),
        w(&key[4..8]),
        w(&key[8..12]),
        w(&key[12..16]),
        w(&key[16..20]),
        w(&key[20..24]),
        w(&key[24..28]),
        w(&key[28..32]),
        w(&nonce16[0..4]),
        w(&nonce16[4..8]),
        w(&nonce16[8..12]),
        w(&nonce16[12..16]),
    ];
    for _ in 0..10 {
        // sutunlar
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        // capraz
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_le_bytes());
        out[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&s[12 + i].to_le_bytes());
    }
    out
}

/// xchacha20_poly1305_open, XChaCha20-Poly1305 acar: HChaCha20 ile alt-anahtar
/// turetir, kalan 8 baytlik nonce'u 0x00000000 ile onekleyerek `ring`in duz
/// ChaCha20-Poly1305'ine devreder. `ct` ETIKETI ICERIR (sondaki 16 bayt).
///
/// FAIL-CLOSED: her ihlal (kisa girdi, auth hatasi) `None`. Cagiran taraf bunu
/// kendi hata koduna cevirir — bu fonksiyon SEBEP AYIRT ETMEZ, cunku "yanlis
/// anahtar" ile "kurcalanmis ciphertext" arasindaki farki disari sizdirmak bir
/// oracle olurdu.
fn xchacha20_poly1305_open(
    key: &[u8; 32],
    nonce24: &[u8],
    ct_with_tag: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    if nonce24.len() != XCHACHA_NONCE_LEN {
        return None;
    }
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[0..16]);
    let subkey = hchacha20(key, &n16);

    // ChaCha20-Poly1305 nonce'u: dort SIFIR bayt ‖ nonce24'un son 8 bayti.
    let mut n12 = [0u8; 12];
    n12[4..12].copy_from_slice(&nonce24[16..24]);

    let unbound = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &subkey).ok()?;
    let lesskey = ring::aead::LessSafeKey::new(unbound);
    let nonce = ring::aead::Nonce::assume_unique_for_key(n12);

    let mut buf = ct_with_tag.to_vec();
    let pt = lesskey
        .open_in_place(nonce, ring::aead::Aad::from(aad), &mut buf)
        .ok()?;
    Some(pt.to_vec())
}

// --- §3.5.2 padding + §3.5.4 WSB1 konteyneri ------------------------------------

/// BLOB_MAGIC, v1 blob konteyner sihirli baytlari (§3.5.4).
pub const BLOB_MAGIC: &[u8; 4] = b"WSB1";
/// WRAP_MAGIC, WKW1 wrap cerceve sihirli baytlari (§2.4).
pub const WRAP_MAGIC: &[u8; 4] = b"WKW1";

const BUCKET_256: usize = 256;
const BUCKET_1K: usize = 1024;
const BUCKET_4K: usize = 4096;
/// BLOB_CAP, toplam depolanan blob objesi ust siniri (§5.7): 64 KB.
const BLOB_CAP: usize = 65536;
/// BLOB_OVERHEAD, magic(4) + nonce(24) + AEAD tag(16).
const BLOB_OVERHEAD: usize = 4 + XCHACHA_NONCE_LEN + 16;
/// LEN_PREFIX, padlenmis formdaki uint32-BE uzunluk oneki.
const LEN_PREFIX: usize = 4;

/// WRAP_TOTAL_LEN, bir WKW1 wrap'inin toplam uzunlugu: magic(4) + nonce(24) +
/// ciphertext(32 + 16 tag) = 76 (§2.4).
pub const WRAP_TOTAL_LEN: usize = 4 + XCHACHA_NONCE_LEN + 32 + 16;

/// max_bucket, blob kapasitesine sigan en buyuk 4 KiB kati kova.
fn max_bucket() -> usize {
    (BLOB_CAP - BLOB_OVERHEAD) / BUCKET_4K * BUCKET_4K
}

/// is_valid_bucket, decrypt'te bir kova boyutunun TANINAN bir kova olup
/// olmadigini dogrular. Bu bir tamper savunmasidir: AEAD gecmis olsa bile
/// kova disi bir uzunluk formatin ihlalidir.
fn is_valid_bucket(size: usize) -> bool {
    if size == BUCKET_256 || size == BUCKET_1K {
        return true;
    }
    size >= BUCKET_4K && size <= max_bucket() && size.is_multiple_of(BUCKET_4K)
}

/// unpad, padlenmis formu cozer: uint32-BE uzunluk oneki ‖ plaintext ‖ SIFIR
/// dolgu (§3.5.2). Dolgu baytlarinin sifir oldugu ve uzunlugun kovaya sigdigi
/// DOGRULANIR; ihlal `None` (BLOB_MALFORMED).
fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < LEN_PREFIX || !is_valid_bucket(padded.len()) {
        return None;
    }
    let l = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    // `end` tasmasi: l bir u32, LEN_PREFIX+l usize'da tasmaz (64-bit), ama
    // kova asimi Go'daki `end > len(padded)` ile AYNI sekilde reddedilir.
    let end = LEN_PREFIX.checked_add(l)?;
    if end > padded.len() {
        return None;
    }
    if padded[end..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(padded[LEN_PREFIX..end].to_vec())
}

/// open_blob, bir "WSB1" blob'unu cozer: magic + AEAD (AAD = slot) dogrulanir,
/// padding kaldirilir (§3.5.4). Her ihlal `Err` (BLOB_MALFORMED, tamper).
///
/// Hata AYRIMI YOK ve bu bilincli: "yanlis DEK" ile "kurcalanmis bayt"
/// arasindaki farki disari vermek bir oracle olurdu (Go'nun ErrBlobMalformed
/// tekilligiyle ayni karar).
pub fn open_blob(blob: &[u8], dek: &[u8; 32], slot: &Slot) -> Result<Vec<u8>, String> {
    slot.validate()?;
    if blob.len() < BLOB_OVERHEAD {
        return Err("cryptoid: BLOB_MALFORMED".into());
    }
    if &blob[..4] != BLOB_MAGIC {
        return Err("cryptoid: BLOB_MALFORMED".into());
    }
    let nonce = &blob[4..4 + XCHACHA_NONCE_LEN];
    let ct = &blob[4 + XCHACHA_NONCE_LEN..];
    let padded = xchacha20_poly1305_open(dek, nonce, ct, &slot.aad())
        .ok_or_else(|| "cryptoid: BLOB_MALFORMED".to_string())?;
    unpad(&padded).ok_or_else(|| "cryptoid: BLOB_MALFORMED".to_string())
}

/// unwrap_dek_with_kek, bir WKW1 wrap'ini projenin KEK'i altinda acar (§2.4).
///
/// AAD, blob AEAD ile AYNI slot baglamasidir — bir wrap baska bir projeye,
/// anahtara ya da versiyona REPLAY EDILEMEZ. Her ihlal WRAP_INVALID
/// (fail-closed). Cerceve uzunlugu SABIT (76) ve bu once kontrol edilir.
pub fn unwrap_dek_with_kek(
    master: &[u8],
    project: &str,
    slot: &Slot,
    wrap: &[u8],
) -> Result<[u8; 32], String> {
    slot.validate()?;
    if wrap.len() != WRAP_TOTAL_LEN || &wrap[..4] != WRAP_MAGIC {
        return Err("cryptoid: WRAP_INVALID".into());
    }
    let kek = derive_project_kek(master, project)?;
    let nonce = &wrap[4..4 + XCHACHA_NONCE_LEN];
    let ct = &wrap[4 + XCHACHA_NONCE_LEN..];
    let pt = xchacha20_poly1305_open(&kek, nonce, ct, &slot.aad())
        .ok_or_else(|| "cryptoid: WRAP_INVALID".to_string())?;
    if pt.len() != 32 {
        return Err("cryptoid: WRAP_INVALID".into());
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&pt);
    Ok(dek)
}
