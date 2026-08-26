// cryptoid — `wapps dr`in kripto cekirdegi (SPEC §2.2–§2.5, §3.5, §3.9).
//
// KAPSAM, ve NEDEN EKSIK: bu modul Go'daki internal/cryptoid'in `dr`in
// PORTLANMIS alt komutlarinin ihtiyac duydugu alt kumesini tasir — kid
// turetimi (§2.2), per-proje KEK (§2.3), slot AAD (§3.5.3), icerik adresi
// (§3.5.4) ve Shamir (§3.9).
//
// `UnwrapDEKWithKEK` (WKW1) ve `OpenBlob` (WSB1) BILEREK YOK. Ikisi de
// XChaCha20-Poly1305 istiyor (24 BAYTLIK nonce) ve bu agacin tek kripto
// kutuphanesi olan `ring` onu TASIMIYOR — olculdu: `ring 0.17.14` kaynaginda
// `xchacha` SIFIR kez geciyor ve `aead::nonce::NONCE_LEN` 96/8 = 12 bayt.
// Yani `dr restore` YENI BIR CRATE olmadan portlanamaz ve bu bir BAGIMLILIK
// POLITIKASI karari (bkz. docs/PORT-dr.md §3, ve Cargo.toml'daki `ring`
// gerekcesi: ikinci bir kripto denetim yuzeyi tasimanin bedeli). O karar
// alinana kadar bu modul YALANCI bir tam-port GORUNTUSU vermiyor.
// ULASILABILIRLIK — YESIL BIR GATE'IN ALTINA SAKLANMAMASI GEREKEN BIR BOSLUK:
// bu modulun HER fonksiyonu testlerden yesil, ama HEPSI bir verb'den
// ULASILABILIR DEGIL. Olculdu (uretim kodundaki cagri sayisi):
//
//   kek_kid 2, blob_hash 4, verify_blob_hash 1, shamir_split 3,
//   shamir_combine 2, WRAP_RECIPIENT 1   -> hepsi CANLI
//   derive_project_kek 0, Slot::aad 0     -> BUGUN OLU
//
// `derive_project_kek` ve `Slot` YALNIZCA `dr restore`un musterisi, ve o alt
// komut portlanmadi. Yani frozen vektore karsi yesil duran iki test, bugun
// hicbir kullanicinin varamayacagi bir kodu koruyor. SILINMEDILER cunku
// tasidiklari sey capraz-dil bir SOZLESME (Go/TS ile bayt paritesi) ve o
// sozlesmeyi simdi pinlemek, restore yazilirken yeniden turetmekten ucuz.
// Ama "test var" ile "davranis sevk ediliyor" AYNI SEY DEGIL, ve bunu burada
// yazmak o iki cumleyi birbirine karistirmamak icin.
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
