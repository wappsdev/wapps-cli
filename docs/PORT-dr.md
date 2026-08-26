# `wapps dr` — Rust port planı

**Durum: KISMEN PORTLANDI** (`verify`, `split`, `combine` — bkz. §7).
Bu belgenin ilk hali `feat/rust-secrets-get-port` uzerinde ORTAYA konmustu;
asagidaki §3 ve §4a DUZELTILDI, cunku port sirasinda OLCULUP YANLIS bulundular.
Duzeltmeler §7'de gerekceleriyle yazili.

**Durum (ilk hali): PORTLANMADI.** Bu belge, portu bir sonraki şeridin yarısından
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

---

## 7. PORT TURU — olculenler, ve bu belgenin IKI YANLISI

Bu bolum `dr verify` / `dr split` / `dr combine` portlanirken eklendi. Buradaki
her sayi bu agacta kosuldu.

### 7.1 §3 YANLISTI: `dr restore` YENI BIR CRATE GEREKTIRMIYOR

§3'un olcumu DOGRU: `ring 0.17.14` XChaCha20-Poly1305 TASIMIYOR (`xchacha`
kaynakta sifir kez; `NONCE_LEN = 96/8`). Bu bagimsiz olarak yeniden dogrulandi.

**Ama §3'un SONUCU yanlis.** "ring'de XChaCha yok" ile "XChaCha portlanamaz"
ayni sey degil, ve aradaki fark olculdu:

> XChaCha20-Poly1305 = **HChaCha20 ile alt-anahtar turetimi** + `ring`in ZATEN
> tasidigi duz **ChaCha20-Poly1305**.
>
> `XChaCha(key, nonce24)` = `ChaCha20Poly1305(HChaCha20(key, nonce24[0..16]),
> 0x00000000 ‖ nonce24[16..24])`

HChaCha20 ChaCha20 permutasyonunun **son toplama adimi olmayan** halidir: saf
bir fonksiyon, ~25 satir, durum tasimaz. `ring` gerekli her seyi disa aciyor
(`aead::CHACHA20_POLY1305`, `aead::LessSafeKey::open_in_place`, 12 baytlik
`Nonce::assume_unique_for_key`).

**KANIT — tahmin degil, kosuldu:** gecici bir test, elde yazilmis HChaCha20 +
`ring`in AEAD'i ile `frozen_vectors.json`daki **WSB1 blob'unu ACTI** ve
`plaintext` alanini bayt bayt geri verdi (28 bayt). Test amacini kanitladiktan
sonra SILINDI (spekulatif kod agacta birakilmaz); bir sonraki serit onu
`blob` vektorunden birebir yeniden uretebilir.

Yani `restore`un maliyeti sudur:

| yol | crate delta | `cargo deny` | ikinci kripto denetim yuzeyi |
|---|---|---|---|
| RustCrypto `chacha20poly1305 0.10` | **+14** (99 → 113) | **0** (gecer) | **EVET** |
| **HChaCha20 elde + `ring`** | **0** | 0 | **HAYIR** |

+14 crate: aead, chacha20, chacha20poly1305, cipher, cpufeatures,
crypto-common, generic-array, inout, opaque-debug, poly1305, rand_core,
typenum, universal-hash, version_check.

Aday `cargo deny`yi GECIYOR — yani karar bir gate karari DEGIL, bir POLITIKA
karari, ve `Cargo.toml`daki `ring` gerekcesi onu zaten vermis durumda: `sha2`
uc crate ekleyecegi ve "iki ayri denetim yuzeyi" demek olacagi icin
REDDEDILMISTI. Ayni gerekce burada +14 crate'e KAT KAT daha guclu uygulanir.

**ONERI: HChaCha20'yi elde yaz, `ring`in ChaCha20-Poly1305'ini kullan.** Bunun
"elde kripto yazmak" olmadigina dikkat: HChaCha20 bir permutasyon, bir
protokol degil, ve olcusu tahmine birakilmiyor — `frozen_vectors.json`daki
`blob` (WSB1) ve Go'nun WKW1 round-trip'i onu BAYT DUZEYINDE pinliyor.
Shamir'in ayni gerekceyle elde yazilmis olmasiyla ayni karar.

### 7.2 §4a YANLISTI: `frozen_vectors.json`in BUGUN TEK tuketicisi var

§4a "bugun iki tuketicisi var: `internal/cryptoid/kek_test.go` (Go) ve
`worker/test/blob.test.ts` (TS)" diyor. Olculdu — **Go o dosyayi OKUMUYOR.**
Dosyayi `import`/`read` eden TEK yer `worker/test/blob.test.ts`. Go tarafi ayni
degerleri **KOPYA LITERALLER** olarak tasiyor (`frozenShamirShares`,
`frozenKekVaulter`, ...) ve dosyaya yalnizca bir YORUMDA atifta bulunuyor.

Onemi: bir literal kopyasi, kaynak dosya degistiginde **sessizce eskir**.
Rust portu bu yuzden dosyayi GERCEKTEN okuyor (`tests/cryptoid.rs::frozen()`)
ve boylece dosyanin **ikinci gercek tuketicisi** oldu.

Kopyalarin BUGUN ayni oldugu ayrica dogrulandi (Go literalleri ile JSON
`shares_hex` birebir esit) — yani bu bir bulgu, bir kirilma degil.

### 7.3 `/wrap` blogu WKW1 DEGIL

§4a'nin tablosu `/wrap` blogunun "WKW1 unwrap + AAD"i pinledigini soyluyor.
Olculdu: `wrap_hex` **232 bayt** ve ilk dort bayti ASCII **`age-`**. WKW1 ise
**76 bayt** (`magic(4)+nonce(24)+ct(48)`). O blok §3.5.5'in **X25519 age**
wrap'i — `dr` ile ilgisi YOK.

**Sonuc: WKW1'in HICBIR yerde frozen bir BAYT vektoru yok.** Go tarafindaki
`TestWKW1RoundTripAndSlotBinding` bir round-trip (nonce rastgele), bir bayt
pini degil. `restore` portlanirken bu bosluk bilinerek girilmeli.

### 7.4 Portlanan yuzey ve olculer

| alt komut | portlandi | olcusu |
|---|---|---|
| `verify` | **EVET** | differential (8 vaka) + `tests/drverb.rs` iddialari |
| `split` | **EVET** | **YALNIZCA IDDIA** — RNG yuzunden differential'lanamaz |
| `combine` | **EVET** | differential (13 vaka, yazilan dosya+mod dahil) + iddia |
| `restore` | hayir | §7.1 (crate GEREKMIYOR; yol acik) |
| `bootstrap` | hayir | `internal/tofu` portu gerekiyor |
| `accept-epoch-reset` | hayir | store'da `AuditHead` + intent basligi yok |

`shamir_split` RNG'yi **parametre aliyor** (§4a'nin uyardigi tasarim kisiti),
ve frozen `rng_pattern_hex` ile paylar BAYT BAYT pinlendi.

### 7.5 BULGU: yanlis tamamlanan bir toreni bugun soyleyen HICBIR SEY YOK

Olculdu — Go ikilisi, ayni fikstur, tek farki bir payin ilk bayti:

```
DOGRU  : EXIT 0  "✓ MASTER_KEK reconstructed → good.hex  (0600, kid 425ed4e4a36b30ea)"
YANLIS : EXIT 0  "✓ MASTER_KEK reconstructed → wrong.hex (0600, kid a30ed9e82836786b)"
```

Iki cikti **kid disinda karakter karakter ayni**: ayni ✓, ayni cikis kodu,
ayni 0600 mod, ayni 65 bayt. `ShamirCombine` hata VERMIYOR (Shamir butunluk
saglamaz), ve Rust portu ayni yanlis anahtari **bayt bayt** uretiyor (parite
korunuyor — differential vakasi:
`human_dr_combine_tampered_share_silently_succeeds`).

Operatorun elindeki TEK isaret kid, ve onu karsilastirmasini soyleyen tek sey
`dr combine`in uyari satiri. **Ama dogru kid'in nerede oldugu sorusunun cevabi
rahatsiz edici:**

> Dogru kid, replikadaki **HER manifest'in icinde** duruyor (`entries[].wrap.kid`).
> `dr verify` o manifest'i okuyor, ayristiriyor ve `epoch`, `keys`,
> `manifest=<kisa hash>` basiyor — **kid'i BASMIYOR** (olculdu: cikti kid'i
> sifir kez iceriyor).

Yani snapshot'i ve paylari ELINDE TUTAN bir operator, dogrulamayi otomatik
yaptirabilecek her seye sahip — ve arac ona bunu ELDE yaptiriyor. `dr restore`
bu kontrolu ZATEN yapiyor (`e.Wrap.Kid != kid` → erken dusme); `dr combine`
yapmiyor.

Bu bir PORT hatasi degil, Go tarafinin bugunku davranisi, ve port onu SADIK
sekilde tasidi. Ama bir sonraki serit icin ucuz ve gercek bir iyilestirme:
`dr combine --expect-kid <kid>` ya da `dr verify`in kid'i basmasi. Sessiz
arizanin siniflarindan en kotusu bu — **cevabin kendisi degil, cevabin YANLIS
oldugunun ANLASILMA ZAMANI gizleniyor: sifre cozulemedigi an, yani en kotu an.**

---

## 8. PORT TURU 2 — `restore` indi, ve §7.1'in ACIK BIRAKTIGI YOL DOGRULANDI

Bu bölümün her sayısı bu ağaçta koşuldu.

### 8.1 `dr restore` PORTLANDI — Cargo.toml'a SIFIR crate

§7.1 yolu göstermişti, bu tur onu ÜRETİME aldı. `xchacha20_poly1305_open` =
elde yazılmış HChaCha20 (~40 satır, saf permütasyon) + `ring`in
`CHACHA20_POLY1305`i. `cargo deny` **0**, crate sayısı **99 → 99**.

Kanıt bir round-trip DEĞİL, üç ayrı ORACLE:

| ölçü | ne pinliyor |
|---|---|
| `open_blob_opens_the_frozen_wsb1_blob` | Go/TS üretimi GERÇEK bir WSB1 blob'u açılıyor |
| `unwrap_dek_with_kek_opens_the_go_generated_wkw1_wrap` | Go'nun ÜRETTİĞİ WKW1 baytları |
| `human_dr_restore_ok` (differential) | sahada, Go ikilisine karşı, yazılan dosya + mod |

### 8.2 §7.3'ün BOŞLUĞU KAPATILDI: WKW1'in artık frozen bayt vektörü VAR

§7.3 doğru saptamıştı: WKW1'in hiçbir yerde bayt vektörü yoktu ve Go'nun
`TestWKW1RoundTripAndSlotBinding`i bir round-trip — kendi sardığını kendi
açar, yani **yanlış-ama-tutarlı** bir implementasyonu yeşil geçirir.

`frozen_vectors.json`a `wkw1` bloğu eklendi ve baytları
`internal/cryptoid.WrapDEKForKEK` **SABİT bir nonce ile ÜRETTİ**. Bu bir
round-trip değil bir çapraz-dil oracle: Rust'ın açışını Go'nun gerçek
baytlarına pinliyor.

### 8.3 §7.2 HÂLÂ GEÇERLİ, ve bir ÖNERİ doğuruyor

Yeniden ölçüldü: `frozen_vectors.json`ı **Go OKUMUYOR** (kopya literaller).
Bu turda eklenen `wkw1` ve `blob_padding_negatives` bloklarının bugün TEK
tüketicisi Rust.

> **ÖNERİ (bu turda YAPILMADI):** Go tarafı `internal/cryptoid`de dosyayı
> gerçekten okusun. Bugün Go'nun literalleri ile dosya aynı — ama bu
> **ölçülerek** doğrulanıyor, mekanizmayla değil. Dosya değişirse Go sessizce
> eskir. Değişiklik `dr`in kapsamı dışında olduğu için önerilmekle bırakıldı.

### 8.4 MUTASYON: bir TAMAM SANILAN suit, bir kontrolü HİÇ ölçmüyordu

`unpad`in **sıfır-dolgu kontrolü SİLİNDİĞİNDE tüm suit YEŞİL kaldı.** Hiçbir
vektör o dalı gezmiyordu — çünkü frozen `blob` vektörü GEÇERLİ bir blob ve
geçerli bir blob padding savunmasını hiç tetiklemez.

`blob_padding_negatives` bloğu bu yüzden eklendi: yapısal olarak GEÇERLİ
(magic doğru, AEAD etiketi DOĞRULANIYOR) ama çözülen padded formu kuralları
ihlal eden üç konteyner. Yani yalnızca `unpad`i ölçüyorlar. Aynı mutasyon
artık `open_blob_enforces_the_padding_rules` ile düşüyor; `is_valid_bucket`
ve uzunluk-taşması mutasyonları da öyle.

**Ders §7.5'in kardeşi:** "frozen vektöre karşı yeşil" ile "her dal ölçülüyor"
AYNI ŞEY DEĞİL. Bir POZİTİF vektör, negatif dalları hiç gezmez.

### 8.5 §7.5'in BULGUSU KAPATILDI (bkz. CHANGELOG)

`dr verify` kid'i BASIYOR (kaynak), `dr combine --expect-kid` onu TÜKETİYOR
ve uyuşmazlıkta **hiçbir şey yazmadan** reddediyor (karşılaştırıcı). İkisi
aynı commit'te Go + Rust'a indi.

Sıra fail-closed için zorunlu: **kid kontrolü dosya yazılmadan ÖNCE.** Bu
sıralamayı bozan bir mutasyon İKİ TARAFA BİRDEN uygulandı ve differential
`DIFFERENT=0` dedi — yani karşılaştırma bu kusura **kör**. Yakalayan yalnızca
iddialar oldu.

### 8.6 KENDİ İŞİMİ ÇÜRÜTME DENEMESİ — bir ölçüm SAHTE ÇIKTI

`restore`un SIFIR girdili bir manifest'te ne yaptığı korpusta YOKTU. İddiam
şuydu: Go'nun `strings.Join(nil, "\n") + "\n"`i `"\n"` verir, yani boş proje
de tek bir yenisatır yazar.

İlk ölçüm denemesi `script(1)` ile yapıldı ve **"STDOUT EŞİT" dedi — ama iki
ikili de HİÇ ÇALIŞMAMIŞTI** (`script: tcgetattr/ioctl: Operation not supported
on socket`). İki boş çıktı eşit görünür. Bu, `diff.py`nin başlığındaki
VACUUM/TIMEOUT tuzağının aynısı, ve elle koşulan bir ölçüde o korumaların
HİÇBİRİ yok.

Gerçek ölçüm ağacın kendi `ptyrun.py`si ile yapıldı: iki ikili de `b"\n"`,
mod `0600`, exit 0 — iddia DOĞRU. Sonra vaka korpusa alındı
(`dr_restore_empty_manifest`) ki bir daha ELLE ölçülmesin.

**Ders:** elle koşulan bir karşılaştırma, ölçtüğü şeyin GERÇEKTEN koştuğunu
ayrıca kanıtlamalı. "Fark yok" ile "hiçbir şey olmadı" aynı görünür.

### 8.7 KALAN İKİ ALT KOMUT, ve tam olarak neyin eksik olduğu

Girilmedi (yarım bir alt komut bırakmamak için) ve gerekenler:

| alt komut | Rust'ta EKSİK olan |
|---|---|
| `bootstrap` | `internal/tofu` portu: `PreflightEnv` + `BootstrapEnvVars`. Rust'ta `tofu` modülü YOK. |
| `accept-epoch-reset` | store'da `AuditHead` rotası **ve** `X-Wapps-Intent: epoch-reset` başlığı YOK; ayrıca `internal/intent` portu. |

İkisi de Go ikilisinde ÇALIŞMAYA DEVAM EDİYOR.
