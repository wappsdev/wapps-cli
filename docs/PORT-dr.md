# `wapps dr` — Rust port planı

**Durum: PORTLANMADI.** Bu belge, portu bir sonraki şeridin yarısından
başlayabilmesi için ÖLÇÜLMÜŞ bir haritadır. Buradaki her sayı ve her
"var/yok" bu ağaçta çalıştırılarak bulundu; hiçbiri hatırlanmadı.

Ölçüm tarihi: `feat/rust-secrets-get-port`, `get`in yapılandırma kolu
kapatıldıktan sonra (Rust 7.1k satır, pty differential EQUAL=311).

---

## 0. Neden bu şerit girmedi

Görev "`dr`e girecek gerçek zamanın var mı diye KENDİN karar ver" diyordu.
Karar: **hayır**, ve gerekçesi üç ölçüm:

1. **Yüzey, "~895 satır"dan büyük.** `dr` ÜÇ dosya değil **ALTI alt komut**:
   `verify`, `restore`, `split`, `combine`, `bootstrap`, `accept-epoch-reset`.
   Verb kodu 895 satır, ama arkasında portlanmamış üç bağımlılık var:

   | bağımlılık | satır (test hariç) | kim istiyor |
   |---|---|---|
   | `internal/cryptoid` (dek/kek/shamir/errors/rand) | 602 | restore, split, combine |
   | `internal/tofu` PreflightEnv + BootstrapEnvVars | (ayrı) | bootstrap |
   | `store.AuditHead` + `AcceptEpochReset` başlığı | (Rust store.rs'te **YOK**) | accept-epoch-reset |

   Gerçek port yüzeyi ~1500+ satır.

2. **Bir BAĞIMLILIK POLİTİKASI kararı gerekiyor** (bkz. §3). Bu estate'te o
   karar bir aday tablosu + `cargo deny` koşumu ile veriliyor
   (`Cargo.toml`daki serde_yaml_ng tablosu örnek). Bir şeridin son yarım
   saatinde alınacak bir karar değil.

3. Yarım bir `dr`, kapalı bir `get` deliğinin yanında durmamalı.

---

## 1. Parça parça: saf mı, kirli mi

"Saf" = girdi→çıktı, dosya/ağ/saat/RNG yok → `wapps` lib'ine girer ve
doğrudan birim testlenir. Kirli olanların ölçüsü differential'dır.

| parça | saf? | neye dokunuyor | notlar |
|---|---|---|---|
| `Slot::AAD()` (§3.5.3) | **SAF** | — | `project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion(ondalık ASCII)`. NUL reddi enjektifliğin şartı. |
| pad/unpad (§3.5.2, kova 256/1K/4K) | **SAF** | — | frozen |
| `BlobHash` / `VerifyBlobHash` | **SAF** | — | SHA-256 çıplak küçük-harf hex. Karşılaştırma SABİT ZAMANLI (Go `subtle`). |
| `KekKid` (§2.2) | **SAF** | — | SHA-256(32 **HAM** bayt)'ın ilk 16 hex'i. **TUZAK:** girdi ASCII hex dizesi DEĞİL. |
| `DeriveProjectKEK` (§2.3) | **SAF** | — | HKDF-SHA256(ikm=master, salt=`"wapps-secrets/kek/v1"` 20 bayt, info=project, L=32) |
| `UnwrapDEKWithKEK` (WKW1 §2.4) | **SAF** | — | magic `WKW1`(4) + nonce(24) + ct(48) = **76 bayt sabit** |
| `OpenBlob` (WSB1 §3.5.4) | **SAF** | — | magic `WSB1` + nonce(24) + ct |
| `ShamirSplit` | saf DEĞİL | **RNG** | çıktı nondeterministik → differential'lanamaz (bkz. §4) |
| `ShamirCombine` | **SAF** | — | GF(2^8), poly 0x11b, üreteç 0x03 |
| `loadSnapshotProject` | kirli | dosya | pointer→manifest sha256 zinciri |
| `snapshotProjects` | kirli | dosya | `secrets/<p>/` dizin listesi, **sıralı** |
| `dr verify` | kirli | dosya | ağ YOK, sır YOK |
| `dr restore` | kirli | dosya (0600 yazım) | ağ YOK |
| `dr split` / `dr combine` | kirli | dosya (0600, **O_EXCL**) | ağ YOK |
| `dr bootstrap` | kirli | prompt + **child exec** + scrubber | ağ YOK |
| `dr accept-epoch-reset` | kirli | **AĞ** (GET /v1/audit/head) + prompt + pin | tek ağ'a çıkan `dr` verb'ü |

---

## 2. Sıralama önerisi — ve neden bu sıra

**Bu sıra bağımlılık maliyetine göre, satır sayısına göre DEĞİL.**

### Dilim A — `dr verify` (YENİ BAĞIMLILIK YOK)
Yalnızca SHA-256 istiyor ve `ring` ZATEN bağımlılıkta (`binding.rs` onu
kullanıyor). Tam bir alt komut, uçtan uca, sıfır politika kararı.
Ayrıca `snapshot*` şekillerini ve zincir doğrulamasını indirir — `restore`
onların üstüne oturur.

### Dilim B — `dr split` + `dr combine` (YENİ BAĞIMLILIK YOK)
Shamir GF(2^8) **elde yazılır** (185 satır Go; bir crate GEREKMEZ ve
alınmamalı — algoritma frozen vektörle pinli). `KekKid` = SHA-256 → `ring`.
`writeSecretFile0600`un **O_EXCL**'i sözleşme: var olan gevşek-izinli bir
dosyayı clobber etmeyi VE "os.WriteFile var olan dosyanın modunu
değiştirmez" tuzağını önlüyor. Rust'ta `OpenOptions::new().create_new(true)`
+ `.mode(0o600)`.

### Dilim C — `dr accept-epoch-reset` (store.rs'e iki ekleme)
`AuditHead` rotası ve `X-Wapps-Intent: epoch-reset` başlığı Rust store'da
YOK. Sahte gate'e `GET /v1/audit/head` eklenince differential'lanabilir.

### Dilim D — `dr bootstrap` (`internal/tofu` port'u gerekir)
`BootstrapEnvVars` kataloğu + `PreflightEnv`. `runWithInjectedEnv` zaten
`exec_core` olarak Rust'ta VAR — scrubber ve exit-code yansıması yeniden
yazılmamalı, o yola girilmeli.

### Dilim E — `dr restore` (**TEK** politika kararı burada)
XChaCha20-Poly1305 istiyor. Bkz. §3.

---

## 3. TEK bağımlılık kararı — ÖLÇÜLDÜ

`ring 0.17.14` (halihazırda bağımlılıkta) kaynağında ölçüldü:

| ihtiyaç | ring'de var mı | ölçüm |
|---|---|---|
| SHA-256 | **VAR** | `ring::digest` |
| HKDF-SHA256 (extract/expand) | **VAR** | `src/hkdf.rs`: `Salt::extract`, `Prk::expand` |
| ChaCha20-Poly1305 | VAR ama **12 baytlık nonce** | `src/aead/nonce.rs`: `NONCE_LEN = 96/8` |
| **XChaCha20-Poly1305 (24 baytlık nonce)** | **YOK** | `grep -ri xchacha ring-0.17.14/src/` → **sıfır eşleşme** |

WKW1 (§2.4) ve WSB1 (§3.5.4) **ikisi de 24 baytlık nonce** kullanıyor
(Go: `chacha20poly1305.NewX`). Yani:

> **`dr restore` bir YENİ CRATE olmadan portlanamaz. Diğer beş alt komut
> portlanabilir.**

Bir sonraki şeridin `restore`a girmeden ÖNCE yapması gereken, bu deponun
kendi kalıbıyla bir aday tablosu ölçmek (crate delta + `cargo deny check`),
tahmin etmek değil. Başlangıç adayı: RustCrypto `chacha20poly1305`
(`XChaCha20Poly1305` tipi). Ölçülecekler: `Cargo.lock` crate delta,
`cargo deny check` çıkışı, ve `ring` yanında **İKİNCİ bir kripto denetim
yüzeyi** taşımanın bedeli — `ring`i `sha2` yerine seçme gerekçesi
(`Cargo.toml`) tam olarak bu ikinciliğe karşıydı.

---

## 4. Hangi oracle'a karşı ölçülür

### 4a. `frozen_vectors.json` — ZATEN VAR ve ÇAPRAZ DİL
`worker/test/vectors/frozen_vectors.json`. Bugün **iki** tüketicisi var:
`internal/cryptoid/kek_test.go` (Go) ve `worker/test/blob.test.ts` +
`worker/src/crypto/blob.ts` (TS). Rust **üçüncü** tüketici olur.

Taşıdığı bloklar (ADLAR ve UZUNLUKLAR; değerler burada BASILMAZ):

| blok | alanlar | Rust'ta neyi pinler |
|---|---|---|
| `wrap` | `dek_hex`(64), `recipient_scalar_hex`(64), `recipient`, `recipient_fingerprint`, `slot{project,keyName,keyVersion}`, `wrap_hex`(464) | WKW1 unwrap + AAD |
| `blob` | `dek_hex`(64), `nonce_hex`(48), `slot{...}`, `plaintext`, `blob_hex`(600), `blob_hash`(64) | WSB1 open + padding + içerik adresi |
| `shamir` | `secret_hex`(64), `rng_pattern_hex`, `parts`, `threshold`, `shares_hex`[3] | GF(2^8) split **ve** combine |
| `ed25519` (+ 4 negatif vaka) | — | `dr` için GEREKMEZ (imza yüzeyi) |

**`shamir` bloğu `rng_pattern_hex` taşıyor** — yani `ShamirSplit` bile
SABİT bir RNG ile deterministik olarak pinlenebilir. Rust portunda
`ShamirSplit` RNG'yi parametre almalı (Go'daki `rng io.Reader` gibi);
almazsa bu vektör kullanılamaz ve split ölçüsüz kalır.

**HKDF için AYRI bir frozen vektör YOK ama Go testi var:**
`TestDeriveProjectKEKFrozen` (`internal/cryptoid/kek_test.go:57`). Rust
tarafında aynı beklenen değerler bir İDDİA testine gitmeli.

### 4b. pty differential — hangi verb'ler girebilir
| verb | differential'lanabilir mi | neden |
|---|---|---|
| `dr verify` | **EVET** | snapshot fikstürü iki ikili için de aynı dizinden okunur; çıktı deterministik |
| `dr combine` | **EVET** | girdi pay dosyaları sabit; çıktı (kid + 0600 dosya) deterministik. `written` alanı MOD'u da karşılaştırıyor → 0600 sözleşmesi ölçülür |
| `dr restore` | **EVET** | fikstür snapshot + sabit paylar; `--out` dosyası `written`e girer |
| `dr accept-epoch-reset` | **EVET** | sahte gate'e `/v1/audit/head` eklenirse |
| `dr bootstrap` | kısmen | child exec + scrubber ölçülebilir (`tofu` shim kalıbı var); prompt dalı pty ile ölçülür |
| `dr split` | **HAYIR** | RNG → her koşumda farklı paylar. Ölçüsü İDDİA (frozen `rng_pattern_hex`) + round-trip |

**UYARI — bu turda iki kez yaşandı:** differential iki ikilinin PAYLAŞTIĞI
bir kusuru göremez. `dr`in kripto çekirdeği tam olarak o sınıfta: Rust'a
yanlış ama Go ile AYNI şekilde yazılan bir HKDF `DIFFERENT=0` verir.
**Kripto parçalarının ölçüsü frozen vektöre karşı İDDİA olmak zorundadır**;
differential yalnızca sarmalayıcı verb'in kapı/çıktı davranışını ölçer.

---

## 5. Portun sessizce yanlış yapacağı yerler (Go'dan okundu)

1. **`KekKid` girdisi HAM 32 bayt**, ASCII hex değil. Hex dizeyi hash'leyen
   bir port çalışır görünür ve TAMAMEN farklı bir kid üretir.
2. **`ShamirCombine` yanlış/eksik payla HATA VERMEZ** — sessizce YANLIŞ bir
   32 baytlık anahtar üretir. Go bunu biliyor ve `dr combine`in çıktısına
   uyarıyı basıyor ("too few or mismatched shares yield a silently-WRONG
   32-byte key (no error)"). Bu uyarı satırı bir süs değil, portlanması
   gereken bir davranış. `dr split` de aynı sebeple round-trip sağlaması
   yapıyor (`shares[:threshold]` gerçekten geri dönüyor mu) ve dönmezse
   **hiçbir şey yazmadan** abort ediyor.
3. **`dr restore` kid uyuşmazlığında ERKEN düşer** — her entry için
   `e.Wrap.Kid != kid` kontrolü, unwrap denemesinden ÖNCE.
4. **`writeRestoredEnvFile` 0600 + atomik rename**; `writeSecretFile0600`
   ise **O_EXCL** (üzerine YAZMAZ). İki farklı dosya sözleşmesi, ikisi de
   ayrı ayrı ölçülmeli.
5. **`wipeBytes` best-effort**, ve Go yorumu dürüst: `masterHex` **string'i
   wipe EDİLEMİYOR**. Rust'ta `Zeroizing<String>` ile bu boşluk KAPATILABİLİR
   — ama o zaman iki ikili ayrışır (davranış değil, bellek hijyeni olarak).
   Bilinçli bir karar olarak alınmalı, kazara değil.
6. **Ajan politikası: `dr`in TAMAMI TTY-only değil.** `verify` guard'sız
   (sır kullanmıyor); `restore`/`split`/`combine`/`bootstrap`/
   `accept-epoch-reset` `PolicyTTY`. `agentPolicy` haritası `secrets`
   altındaki verb'ler için; `dr` **kökte mount'lu** (`rootCmd.AddCommand(
   secrets.DrCmd)`), yani `secretsPreRunE` `dr` için **HİÇ KOŞMUYOR** ve
   guard'lar her verb'ün kendi RunE'sinde ELDE yazılmış. `projects list`in
   bağlama kapısını hiç görmemesiyle aynı yapısal sebep — ve aynı sebeple
   port'ta kolayca fazladan bir kapı eklenir.

---

## 6. Rust CLI'da `dr` HİÇ YOK

`rust/crates/cli/src/cli.rs` içinde `"dr"` alt komutu tanımlı DEĞİL
(ölçüldü: sıfır eşleşme). Yani ilk dilim clap ağacına `dr` grubunu da
eklemek zorunda.

**`helptext.rs` için ÖLÇÜLDÜ, ve iyi haber:** o test ağaçları
karşılaştırmıyor; Rust clap ağacının HER düğümünün yardım metnini gezip
**spec referansı** arıyor (`§`, "spec 7.4", "section 2.1"). Go ikilisinin
yedi `dr` yardım metni de bu kurala karşı ölçüldü (`dr`, `verify`,
`restore`, `split`, `combine`, `bootstrap`, `accept-epoch-reset`) →
**yedisi de TEMİZ**. Yani yardım metinleri AYNEN taşınabilir; `helptext.rs`
değişmeden yeşil kalır. (`accept-epoch-reset`in Long'u
`internal/store/epochpin.go` diyor — bu bir KAYNAK DOSYA referansı, spec
referansı değil; kural onu yakalamıyor ve Go bugün onu yayınlıyor, yani
port da aynen taşımalı.)
