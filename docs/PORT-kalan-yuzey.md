# CLI yüzeyinin KALANI — ölçülmüş envanter, kapsam ve dilim listesi

**Bu belge kod değiştirmez.** Bir port şeridinin girdisidir: Go ikilisinin yüzeyi
karşısında Rust ikilisinin bugün gerçekten uyguladığı yüzey, differential'ın fiil
başına kapsamı, ve sıralı bir dilim listesi.

**Buradaki her sayı ve her "var/yok" bu ağaçta çalıştırılarak bulundu.**
Hiçbiri hatırlanmadı, hiçbiri kaynaktan tahmin edilmedi. Kaynak yalnızca İKİNCİ
dedektör olarak kullanıldı; ikili ile kaynak ayrıştığı üç yerde ayrışmanın
kendisi §2'de bulgu olarak yazıldı.

Ölçüm künyesi:

| | |
|---|---|
| depo | `wapps-cli` |
| dal | `feat/rust-secrets-get-port` |
| commit | `7c248b736a3310e09332f97df4dc73268b836885` |
| Go ikilisi | `go build -o <scratch>/wapps-go .` → exit 0 |
| Rust ikilisi | `cargo build --bin wapps` → exit 0 |
| differential | `EQUAL=435 DIFFERENT=0 UNSOUND=0`, `cargo test --test differential` exit **0** |

Taban büyüklükler (test dosyaları hariç, `wc -l`):

| ağaç | satır |
|---|---|
| Go `cmd/` + `internal/` | 13 022 |
| Rust `src/` | 9 478 |
| Rust `tests/` | 7 646 |
| pty korpusu (`tests/pty/*.py`) | 4 159 |

---

## 0. Nasıl ölçüldü

**Yüzey iki ikiliye SORULDU.** Bir gezici her düğümde `--help` çalıştırıyor,
çıktıdan aday alt komut adlarını çıkarıyor, sonra **her adayı ayrıca
çalıştırarak** gerçekten var olduğunu doğruluyor. Bir aday yalnızca yardım
metninde göründüğü için envantere girmiyor.

Bu iki aşama şart oldu ve sebebi ölçüldü: ilk gezicinin ayrıştırıcısı
"ad + iki boşluk + açıklama" varsayıyordu, ama cobra sütunları hizalarken
uzun adlardan sonra **tek** boşluk bırakıyor. `dr accept-epoch-reset` ve
`secrets rotate-plan` bu yüzden envanterden sessizce düşmüştü. Adayı
çalıştırarak doğrulayan ikinci aşama, ayrıştırıcının kendi kusurunu yakalayan
şey oldu.

**Çıkış kodları doğrudan okundu.** `cmd | tail` sonrası `$?` `tail`in kodudur;
ölçümlerin hepsinde çıktı önce dosyaya yazıldı, kod ondan sonra okundu.

Ara çıktılar (bu koşumun scratch'inde): `01-tree-{go,rs}.json` (ham yardım
ağaçları), `02-envanter.txt`, `03-version-ve-yerel-project.txt`,
`04-kapsam.txt`, `05-differential.log`, `06-crate-kararlari.txt`,
`07-fiyat-girdileri.txt`, `08-yardim-duzeni.txt`.

---

## 1. Fiil envanteri

Gezilen düğüm sayısı: **Go 50**, **Rust 31**. Rust'ta olmayan yol: **19**.

> **Dilim 1'den sonra:** `dr accept-epoch-reset` indi, yani Rust **32** düğüm
> taşıyor ve eksik yol **18**. Aşağıdaki tablolar ÖLÇÜM ANININ fotoğrafı;
> yalnızca bu satır güncellendi ki ölçümün kendisi tahrif edilmesin.

Aşağıdaki tabloda "yerel bayraklar" kök kalıtsal bayrakları (`-c/--config`,
`-p/--project`, `-v/--verbose`, `-h/--help`) DIŞARIDA bırakır — cobra onları
her alt komutun yardımında tekrar basar, clap basmaz, ve bu bir yetenek farkı
değil bir yardım-dizgi farkıdır.

### 1.1 İki ikilide de VAR (30 yol)

| yol | yerel bayraklar | bayraklar eşit mi |
|---|---|---|
| `(kök)` | `--version` (yalnız Go) | **HAYIR** — §2.1 |
| `doctor` | `--for` | evet |
| `dr` | — | evet |
| `dr verify` | `--snapshot` | evet |
| `dr restore` | `--confirm --out --share --snapshot` | evet |
| `dr split` | `--master-hex --out-dir --parts --threshold` | evet |
| `dr combine` | `--expect-kid --out --share` | evet |
| `dr bootstrap` | `--skip-preflight --var` | evet |
| `projects` / `projects list` | — | evet |
| `projects rm` | `--yes` | evet |
| `rotate` | — | evet |
| `rotate skip` | `--reason` | evet |
| `secrets` | — | evet |
| `secrets get` | — | evet |
| `secrets set` | `--from-file` | evet |
| `secrets list` | — | evet |
| `secrets rm` | `--yes` | evet |
| `secrets exec` | `--break-glass --intent --prefix` | evet |
| `secrets apply` | — | evet |
| `secrets env` | `--prefix --write` | evet |
| `secrets import-env` | — | evet |
| `secrets init` | `--force --project-name` | evet |
| `secrets status` | `--json` | evet |
| `secrets trust-repo` | — | evet |
| `secrets rotate-plan` | `--assume-policy --identity --json --since` | evet |
| `secrets policy` | — | evet |
| `secrets policy show` | `--json` | evet |
| `secrets policy set` | `--yes` | evet |
| `secrets policy lint` | — | evet |
| `tofu` | — | evet |

**Ortak 30 yolun 29'unda yerel bayrak kümesi BİREBİR aynı.** Tek fark kökteki
`--version` (§2.1).

### 1.2 Rust'ta YOK (19 yol)

| yol | yerel bayraklar | Go satırı (test dışı) |
|---|---|---|
| `login` | `--check --write` | `cmd/login.go` 414 (whoami+token ile paylaşımlı) |
| `whoami` | — | ↑ aynı dosya |
| `token` / `token exchange` | `--key --project --ttl --verb` | ↑ aynı dosya |
| `secrets sync` | `--all-apps --app --coolify-url --dry-run --force --prefix --target` | `sync.go` 206 + `sync_coolify.go` 456 |
| `coolify` | — | `cmd/coolify/` 455 |
| `coolify deploy-app` | `--compose-file --env-from-shell --name --project-uuid --server-uuid` | ↑ |
| `coolify deploy-app-git` | `--base-dir --build-arg --build-pack --dockerfile --git-branch --git-repo --github-app-uuid --instant-deploy --name --ports --project-uuid --server-uuid --watch-path` | ↑ |
| `coolify import-app` | `--output-dir --server-uuid` | ↑ |
| `coolify set-labels` | `--app-uuid --label --strip-cert-resolver` | ↑ |
| `coolify update-env` | `--app-uuid --env` | ↑ |
| `deploy` | `--ep --json --poll-interval --repo --timeout --wait` | `cmd/deploy/deploy.go` 283 |
| `skill` | — | `cmd/skill/skill.go` 138 |
| `skill install` | `--copy --dir --local` | ↑ |
| `skill status` | — | ↑ |
| `skill uninstall` | `--dir --local` | ↑ |
| `completion` | — | cobra üretiyor |
| `help` | — | cobra üretiyor |

**`--project` iki yerde YEREL bir bayrak, kalıtsal olan değil**
(`dr accept-epoch-reset`, `token exchange`) — ikisinde de kökün `-p`si
gölgeleniyor. Bu bir ayrıntı değil, port için bir tuzak: `Ctx::resolve`
çağrılmadan proje adı doğrudan bayraktan okunuyor.

Portlanmamış fiillerin arkasındaki, Rust'ta karşılığı OLMAYAN paketler:

| Go paketi | satır (test dışı) | Rust karşılığı |
|---|---|---|
| `internal/coolify` | 527 | **yok** |
| `internal/skill` | 401 | **yok** |
| `internal/source` | 376 | **yok** |
| `internal/session` | 302 | `session.rs` **69 satır** (yalnız gate URL + auth başlıkları) |
| `internal/deploy` | 299 | **yok** |
| `internal/updatecheck` | 256 | **yok** |
| `internal/intent` | 51 | **yok** (başlık sabitleri) |

Store rotaları — Go `WorkerStore`un dışa açık **13** metodu var
(`Projects ProjectDelete Keys Read Set Import Delete Whoami AuditHead PolicyGet
PolicyPut RotatePlan TokenMint`). Rust `store.rs` **8** ayrı `/v1/` rotası
taşıyor. **Rust'ta karşılığı olmayan üç metot ve üç rota:**

| Go metodu | rota | gövde (satır) | kimin için |
|---|---|---:|---|
| `Whoami` | `GET /v1/whoami` | 14 | `whoami` |
| `AuditHead` | `GET /v1/audit/head` | 17 | `dr accept-epoch-reset` |
| `TokenMint` | `POST /v1/token` | 34 | `token exchange` |

---

## 2. İkili ↔ kaynak ayrışmaları (bulgular)

Bunlar tabloyu kurarken düşen, kendi başlarına bulgu olan üç şey.

### 2.1 `--version` yalnızca Go'da var, ve bu bir RET olarak gözlemleniyor

```
GO  --version  rc=0  stdout="wapps version dev"
RS  --version  rc=1  stderr={"error":"INTERNAL","message":"unknown flag: --version",...}
GO  version    rc=1  (alt komut olarak YOK — yalnız bayrak)
```

Go'da değer `.goreleaser.yml`in ldflag'iyle geliyor
(`-X .../cmd.Version={{.Version}}`); yerel yapıda `dev`. Rust ikilisinin
`Cargo.toml`daki sürümü `0.0.0` ve derleme zamanında hiçbir şey enjekte
edilmiyor.

### 2.2 Görev tanımı "`login` portlandı" diyordu; **ikili aksini söylüyor**

```
RS  login --help  rc=1  {"error":"INTERNAL","message":"unrecognized subcommand",...}
```

`rust/crates/cli/src/` altında `login` adında bir modül yok; `login` sözcüğü
yalnızca **kurtarma satırlarında** geçiyor (`clierr.rs`, `session.rs`,
`store.rs`, `doctorverb.rs`, `initverb.rs` — "run `wapps login`" öneren
metinler). Yani portlanmış olan şey `login`in KENDİSİ değil, ona yapılan
ATIFLAR. Bir raporu ikiliye sormadan devralmanın maliyeti tam olarak bu.

### 2.3 `secrets sync`in yardım metni kendi koduyla ayrışıyor

Yardım (`Long`) diyor ki: *"…write an encrypted archive to dest"*
(`cmd/secrets/sync.go:79`). Kod diyor ki: *"…writes the result to the store in
ONE epoch"* (`sync.go:124`). Arşiv okuyucusu zaten kaldırılmış
(`archive_values.go`: "P1.7 re-point: age-arşiv okuyucusu (ArchiveValues)
KALDIRILDI"), ve bu bağımsız olarak doğrulandı:

```
$ go mod why filippo.io/age
(main module does not need package filippo.io/age)
```

**Sonuç port için önemli:** `secrets sync`i portlamak bir **age/şifreleme
crate'i kararı GEREKTİRMİYOR**. Yardım metnini oracle sanan bir port bunu ters
öğrenirdi.

### 2.4 `rotate skip` iki tarafta da bir RET; motor bağlı DEĞİL

`cmd/secrets/rotate_skip.go` insan yolunda `ACTION_UNAVAILABLE` dönüyor
("the SKIP engine is ready (internal/rotation) but the CLI↔live
rotation-ledger wiring lands with the rotation executor"). İki ikili bunu
bayt bayt aynı üretiyor (ölçüldü, `rc=1` her ikisinde).

Bunun envanter için anlamı: `rotate skip` "portlandı" satırında **VAR**, ama
portlanan şey bir reddin metni. Ve `internal/rotation`ın 1490 satırının
CLI'dan kullanılan yüzeyi **tek sembol**: `rotation.RunLedger`. Kalan
~1400 satır bu portun fiyatına GİRMİYOR.

---

## 3. Differential kapsamı — fiil başına

`cases.py` içinde **439** vaka tanımlı, **4**'ü açık gerekçeyle dışarıda,
ölçülen **435**. İnsan/ajan dağılımı: **316 human / 119 agent**.

Dışarıda bırakılan dördü ve gerekçeleri (hepsi korpusta yazılı):
`agent_unknown_subcommand` (cobra yardım düzeni), `human_gate_down` (işletim
sistemi taşıma hatası metni), `human_policy_lint_broken_json` ve
`human_rotate_plan_bad_since` (Go ayrıştırıcılarının kendi prozası).

### 3.1 Vaka sayıları

| vaka | fiil | | vaka | fiil |
|---:|---|---|---:|---|
| 44 | `secrets get` | | 16 | `dr restore` |
| 36 | `secrets set` | | 16 | `tofu` |
| 28 | `secrets apply` | | 15 | `secrets init` |
| 26 | `secrets exec` | | 15 | `secrets rotate-plan` |
| 24 | `secrets env` | | 14 | `secrets trust-repo` |
| 21 | `secrets rm` | | 10 | `projects list` |
| 20 | `secrets import-env` | | 10 | `rotate skip` |
| 19 | `secrets list` | | 9 | `dr verify` |
| 18 | `secrets policy lint` | | 9 | `secrets policy set` |
| 17 | `doctor` | | 7 | `dr split` |
| 17 | `secrets status` | | 6 | `projects rm` |
| 16 | `dr bootstrap` | | 6 | `secrets policy show` |
| 16 | `dr combine` | | | |

Dağılım: **min 6 · medyan 16 · ortalama 17,4 · maks 44** (25 uç fiil).
`armcheck`in gördüğü granülerlikte (policy tek fiil) **23** fiil.

### 3.2 Sıfır vakası olanlar

**Rust'ta uygulanmış olup differential'da ölçülmeyen TEK BİR fiil YOK.**
Portlanmış 30 yolun tamamı korpusta temsil ediliyor. Bu, bu ağaçta "portlanmış
ama ölçülmemiş" diye bir kategori olmadığı anlamına geliyor — ve bu iyi haber
ölçülmeden yazılamazdı.

Sıfır vakası olan her şey, portlanmamış olan şey:

| ölçülmeyen | neden sıfır |
|---|---|
| `login`, `whoami`, `token exchange` | Rust'ta yok |
| `secrets sync` | Rust'ta yok |
| `coolify` (5 alt komut) | Rust'ta yok |
| `deploy` | Rust'ta yok |
| `skill` (3 alt komut) | Rust'ta yok |
| `completion`, `help` | Rust'ta yok |

### 3.3 Fiilden BAĞIMSIZ üç kapsam deliği

Bunlar bir fiile ait değil; korpusun ekseninin dışında kalıyorlar ve bir fiil
listesi onları göstermiyor.

**(a) `--help` ekseni tamamen ölçüm dışı.** Korpusta `--help` geçen **sıfır**
vaka, `--version` geçen **sıfır** vaka, çıplak `wapps` (fiilsiz) **sıfır**
vaka var. §1'in tablosu bu yüzden ELLE gezilerek kuruldu; differential onu
üretemezdi. Ayrışma bugün gözlemlenebilir durumda:

```
wapps secrets nosuchverb   GO rc=0, stdout 1527 bayt (cobra YARDIMI basıyor)
                           RS rc=1, stderr  139 bayt (JSON zarf)
çıplak `wapps`             GO rc=0, 36 satır  ·  RS rc=0, 17 satır
```

Korpus bunu `agent_unknown_subcommand` olarak zaten dışarıda bırakmış ve
gerekçesini yazmış ("`secrets`in 14 alt komutunun tamamını ve cobra'nın yardım
düzenini port etmek demek"). Gerekçe hâlâ geçerli, ama gerekçe **ölçümün
yapılmadığını değiştirmiyor** — bugün Go'nun 50 düğümlük yardım ağacının
hiçbir baytı gate'te değil.

**(b) `updatecheck` + skill auto-refresh her komuttan SONRA çalışıyor ve
korpusta hiç görünmüyor.** `cmd/root.go:119` ve `:123`, `rootCmd.Execute()`
döndükten sonra `maybeNotifyUpdate()` ve `maybeAutoRefreshSkill()` çağırıyor;
ikisi de stderr'e satır basabiliyor. Korpus onları iki ayrı mekanizmayla
susturuyor:

1. `probe.py:100` her vakaya `WAPPS_NO_UPDATE_CHECK=1` veriyor;
2. `cmd/root.go:28` yerel yapıda `Version = "dev"` — semver olmadığı için
   `updatecheck.MaybeNotify` zaten hiç ateşlemez.

Yani bu çapraz kesen davranışın Rust'ta **hiç olmaması** differential'da
görünmez. Rust ikilisinin bu iki çağrıya karşılık gelen hiçbir kodu yok.

**(c) mTLS taşıma kolu ölçülmüyor ve Rust'ta yok.** Go
`internal/session/auth.go` `WAPPS_MTLS_CERT` + `WAPPS_MTLS_KEY` doluysa
client-cert'li bir taşıma kuruyor. Rust `store.rs:206` `.with_no_client_auth()`
diyor — kol hiç yok. Korpusta bu iki değişkeni set eden vaka yok.

### 3.4 Korpusun kendi kapısı: `armcheck`

Yeni bir fiilin kaç vakaya mal olacağını tahmin etmek gerekmiyor, çünkü taban
MEKANİK: `cases.py` import anında `_armcheck()` çalışıyor ve her fiilin dört
kimlik kolunu da gezmesini şart koşuyor — `proj` (`--project`), `cfg`
(`--config`), `rooted` (bayraksız + `.wapps.yaml` var), `bare` (bayraksız +
config yok). Gezilmeyen bir kol için `ARM_WAIVERS`a **gerekçe** yazmak
zorunlu, ve tablo çürümesin diye artık gerekmeyen muafiyet de hata veriyor.

Bugünkü muafiyetler:

| fiil | muaf kollar |
|---|---|
| `doctor` | cfg, proj, rooted |
| `dr verify`, `dr restore`, `dr bootstrap` | cfg, rooted |
| `dr split`, `dr combine`, `projects rm` | cfg, proj, rooted |
| `rotate skip`, `secrets policy`, `secrets rotate-plan` | cfg, proj |

Korpus ayrıca her vakayı human/agent çifti olarak yazıyor. **Taban: bir yeni
fiil için 4 kol × 2 mod = 8 vaka**, muafiyet başına −2. Gözlenen alt sınır 6
(`projects rm`, `secrets policy show`), medyan 16. §5'teki fiyatlar bu iki
çıpaya oturuyor, hisse değil.

---

## 4. Crate kararıyla sınırlı olanlar

`dr`ın portu bir bağımlılık politikası kararını bekliyordu. Kalan yüzeyde aynı
sınıfta ne var sorusunu, **varsayarak değil, mevcut bağımlılıkların tiplerini
ve kaynağını okuyarak** cevapladım.

### 4.1 Crate kararı GEREKTİRMEDİĞİ ÖLÇÜLENLER

| ihtiyaç | kim istiyor | ölçüm | sonuç |
|---|---|---|---|
| **base64** | `login`/`whoami` (JWT payload, RawURL), `coolify` (StdEncoding **encode**) | `drverb.rs:609` `b64_decode` zaten ELDE YAZILI (RFC 4648 dolgulu çözücü) ve `dr restore` onu kullanıyor | yeni crate YOK; encode + RawURL varyantı mevcut yardımcının kardeşi |
| **mTLS client-cert** | `session.HTTPClient` (§3.3-c) | `rustls-0.23.43/src/client/builder.rs:146` `pub fn with_client_auth_cert` **VAR**; `rustls-pki-types-1.15.1/src/lib.rs:171` `impl PemObject for PrivateKeyDer`, `:686` `impl PemObjectFilter for CertificateDer` **VAR**. İkisi de ZATEN doğrudan bağımlılık | yeni crate YOK |
| **skill varlıklarını gömme** | `skill install` | `internal/skill/assets` = **1 dosya, 7901 bayt** (`wapps-secrets/SKILL.md`) | `include_str!` yeter; `include_dir` crate'i GEREKMİYOR |
| **regex** | `deploy` | `internal/deploy/deploy.go:59-60` — toplam **iki** desen: `^[a-z][a-z0-9-]{1,40}$` ve `^[a-z0-9]{20,32}$` | ikisi de karakter-sınıfı kontrolü; `regex` crate'i GEREKMİYOR |
| **age / arşiv şifreleme** | (sanılıyordu: `secrets sync`) | `go mod why filippo.io/age` → *"main module does not need package"* | karar YOK — ihtiyacın kendisi yok (§2.3) |
| **SHA-256** (skill fingerprint) | `skill status` | `ring` zaten bağımlılıkta (`binding.rs`, `drverb.rs`) | yeni crate YOK |
| **HTTP** (`coolify`, `deploy`, `token`, `whoami`, `updatecheck`) | hepsi | `ureq` zaten bağımlılıkta, bloklayan, tokio'suz | yeni crate YOK |

**Yani kalan 19 yoldan hiçbiri `dr restore` sınıfında değil.** `dr`ın crate
kararını gerektiren şey XChaCha20-Poly1305'ti; kalan yüzeyde ona denk bir
kriptografik/format ihtiyacı yok.

### 4.2 GERÇEK crate kararı olan TEK yer: `completion`

cobra dört betik üretiyor ve boyutları ölçüldü:

| kabuk | satır | bayt |
|---|---:|---:|
| bash | 426 | 16 093 |
| zsh | 212 | 7 712 |
| fish | 235 | 9 601 |
| powershell | 270 | 10 792 |

Üç seçenek:

- **(A) `clap_complete`** — grafa yeni crate; ve ürettiği betikler cobra'nınkiyle
  **bayt bayt aynı olmaz**, çünkü tamamlama protokolleri farklı
  (cobra `__complete` alt komutuna dayanıyor). Yani crate'i alsanız bile
  differential'da kalıcı bir ayrışma kalır.
- **(B) Dört betiği sabit metin olarak gömmek** — sıfır crate, bayt bayt aynı,
  toplam ~44 KB. Bedeli: betikler DONAR; yeni bir alt komut eklendiğinde elle
  yenilenmeleri gerekir (bash betiği alt komut adlarını gömüyor).
- **(C) Yüzeyden düşürmek** — `completion` kullanıcıya görünen bir yol;
  düşürmek bir ürün kararı, bir port kararı değil.

**Bu belge bir karar vermiyor; kararı ÖLÇÜLMÜŞ seçeneklerle önüne koyuyor.**
`Cargo.toml`daki `serde_yaml_ng` tablosunun formatı burada da geçerli: aday →
crate deltası → `cargo deny` → gerekçe. Bu tablo ancak şerit içinde
doldurulabilir (aday crate ağaca girmeden `cargo deny` koşulamaz).

### 4.3 Crate DEĞİL ama karar olan: `--version` nereden gelecek

Go'da değer link zamanında geliyor (`.goreleaser.yml` ldflag). Rust'ta
karşılığı `build.rs` + `env!` ya da `CARGO_PKG_VERSION`. Zorluk şu: **release
train Rust'ı hiç tanımıyor** — `.goreleaser.yml`in tek build hedefi
`main: ./main.go`, ve `.github/workflows/{ci,release}.yml` dosyalarında
`cargo`/`rust` geçen satır sayısı **0**. Yani Rust ikilisinin sürüm alması,
önce release train'de bir yer alması demek. Bu bir crate kararı değil, bir
dağıtım kararı ve §6'da ölçemediklerim arasında.

---

## 5. Dilim listesi

Sıra **bağımlılık maliyetine** göre, satır sayısına göre değil. Her dilim için
geçmesi gereken kapı bugün tek ve YEREL: `cargo test` (differential + armcheck
+ helptext + birim testleri), `cargo fmt --check`, `cargo deny check`. CI'da
Rust kapısı **yok** (ölçüldü, §4.3).

Vaka sayıları §3.4'ün mekanik tabanından türetildi: 4 kol × 2 mod = 8, muafiyet
başına −2, üstüne fiilin kendi hata dalları.

---

### Dilim 1 — `dr accept-epoch-reset` · **İNDİ**

**Neden ilk:** `dr`ın altıncı ve son alt komutu; indiği anda `dr` fiili
KAPANIYOR. Uçtan uca bütün boruyu geziyor (yeni verb + yeni store rotası +
yeni sahte-gate rotası + differential vakaları + armcheck) ama hiçbir yeni
bağımlılık istemiyor — yani boruyu bir kütüphane tartışması olmadan test
ediyor.

| | |
|---|---|
| fiiller | `dr accept-epoch-reset` |
| Go kaynağı | `cmd/secrets/dr_epoch_reset.go` 172 satır |
| yeni crate | **YOK** — tahmin tuttu; `regex` de gerekmedi (`^[0-9a-f]{12}$` bir karakter sınıfı, §4.1'in `deploy` için ölçtüğü kararla aynı sınıfta) |
| store'a eklendi | `audit_head()` (`GET /v1/audit/head`), `keys_accepting_epoch_reset()` (`X-Wapps-Intent: epoch-reset`) |
| `epochpin.rs` | **DEĞİŞMEDİ.** Bu satır fiyatlandırmada YANLIŞTI: pin İNDİREN yol zaten vardı (`check_and_advance`in `accept_reset` parametresi, önceki dilimde "atlamak bir istisnayı yeniden keşfettirirdi" gerekçesiyle taşınmıştı). Eksik olan tek şey onu çağıran fiildi |
| sahte gate | **+1 rota** (`GET /v1/audit/head`) + `/keys`in intent başlığına duyarlı hâle gelmesi |
| differential vakası | **22** (16 seremoni + 6 gölge). Tabandan türetimi: 4 kol × 2 mod = 8, `cfg`+`rooted` muaf → **4**; üstüne fiilin 12 kendi dalı |
| kapı | `cargo test` yeşil (`EQUAL=457 DIFFERENT=0 UNSOUND=0`, exit 0) + `cargo clippy` temiz + `_armcheck()` muafiyet gerekçesi yazılı |

**Fiyatlandırmanın GÖRMEDİĞİ bir ayrışma çıktı, ve `dr restore`da da vardı.**
§1.2 "`--project` iki yerde YEREL bir bayrak … port için bir tuzak" diyordu;
tuzak sanıldığından bir adım derinde. cobra'da yaprağın yerel bayrağı kökün
persistent'ini **GÖLGELER** ve gölge komut satırındaki YERDEN BAĞIMSIZDIR —
bütün bayraklar yaprağın flagset'ine karşı ayrıştırılır. clap'te ikisi ayrı
argüman ve hangisinin dolacağını KONUM belirler. İki gözlemlenebilir sonuç:

```
wapps --project p dr accept-epoch-reset      GO çalışır · RS "--project is required"
wapps -c c --project p dr accept-epoch-reset GO çalışır · RS "mutually exclusive"
wapps --project a dr restore …               GO çalışır · RS "--project and --snapshot are required"
wapps -c c --project a dr restore …          GO çalışır · RS "mutually exclusive"
```

Yani ayrışma bu dilimin GETİRDİĞİ bir şey değil: `dr restore`da ölçülmeden
duruyordu ve §6.1'in "portlanmış 30 yolun DAVRANIŞSAL tamlığı ölçülmedi"
maddesinin somut bir örneği. Doğru taraf ölçülerek seçildi: karşılıklı dışlama
bir KİMLİK kuralı, bu iki yaprakta `--project` kimlik bayrağı DEĞİL
(`Ctx::resolve` çağrılmıyor). Kural kaldırılmadı — yerel `--project`i olmayan
`dr verify`de sürüyor ve kontrol vakası korpusta.

---

### Dilim 2 — `whoami`

**Neden ikinci:** ağa çıkan en ucuz fiil, ve sahte gate rotası ZATEN VAR
(`GET /v1/whoami`, bugün `status`un canlılık probu olarak kullanılıyor).
Yapılacak iş rotayı silmek değil, gövdesini gerçek şekle zenginleştirmek.

| | |
|---|---|
| fiiller | `whoami` |
| Go kaynağı | `cmd/login.go` `whoamiCmd` bloğu **46** satır + `store.Whoami` **14** satır |
| yeni crate | **YOK** |
| store'a eklenecek | `whoami()` |
| sahte gate | rota VAR; gövde zenginleştirilecek (principal/email/common-name/gruplar/grantlar) |
| differential vakası | **8–10** (4 kol × 2 mod; üstüne oturumsuz + gate 5xx) |
| kapı | `cargo test` yeşil |

---

### Dilim 3 — `login` (`--check`, `--write`)

| | |
|---|---|
| fiiller | `login`, `login --check`, `login --write` |
| Go kaynağı | `cmd/login.go`ın kalanı (414 − 82 = **332** satır) + `internal/session` 302 satır (Rust bugün **69**) |
| yeni crate | **YOK** — `cloudflared` alt süreci (`std::process::Command`, `execverb.rs`te desen var), 0600 oturum dosyası (`atomicfile.rs` var), JWT payload base64url (§4.1) |
| ölçülebilirlik | `cloudflared` bir **shim** ile ölçülür; desen korpusta ZATEN var (`FIXTURE_FILES["tofu"]` + `TOFU_PATH`, `probe.py` `#!` ile başlayanı 0755 yazıyor). `cloudflared` YOKKEN düşen `ACTION_UNAVAILABLE` dalı shim'siz ölçülür |
| differential vakası | **16–20** (üç bayrak kombinasyonu × kollar; artı: cloudflared yok, token boş, bozuk JWT segmenti, oturum dosyası izinleri) |
| kapı | `cargo test` yeşil + `noecho.rs` (token baytı hiçbir yere sızmamalı) |
| dikkat | Yazma oturumu AYRI bir CF Access uygulaması (`/v1/admin`); `session.rs` bu ayrımı zaten taşıyor (`auth_headers` / `auth_headers_admin`) — yeniden yazılmamalı |

---

### Dilim 4 — `token exchange`

| | |
|---|---|
| fiiller | `token`, `token exchange` |
| Go kaynağı | `cmd/login.go` `tokenExchangeCmd` bloğu **36** satır + `store.TokenMint` **34** satır |
| yeni crate | **YOK** |
| store'a eklenecek | `token_mint()` (`POST /v1/token`) |
| sahte gate | **+1 rota** (`POST /v1/token`) |
| differential vakası | **10–12.** `proj` kolu YEREL bayraktan (Dilim 1'le aynı tuzak); artı `--ttl` sınırı (≤600), `--verb` doğrulaması, tekrarlanabilir `--key`, servis-token yokluğu |
| kapı | `cargo test` yeşil + basılan token'ın scrubber'a takılmaması ölçülü |

---

### Dilim 5 — `secrets sync` (yalnız `--target`sız kol)

| | |
|---|---|
| fiiller | `secrets sync` (Coolify kolu HARİÇ) |
| Go kaynağı | `cmd/secrets/sync.go` 206 + `internal/source` 376 (`file.go` 118, `file_writer.go` 99, `source.go` 85, `tofu.go` 51, `tofu_exec.go` 23) |
| yeni crate | **YOK** — `.env` ayrıştırıcısı (`importenv.rs` benzeri bir yol zaten var), `tofu output -json` alt süreci |
| hazır olan | `wappsyaml.rs` `SourceConfig`i ZATEN modelliyor ve `validate_source` doğrulamayı ZATEN yapıyor — config yarısı portlu |
| differential vakası | **14–18** (4 kol × 2 mod + `--dry-run`, kaynak yok, bozuk `.env` satırı, `tofu` shim'i üzerinden okuma) |
| kapı | `cargo test` yeşil |
| dikkat | Yardım metni "encrypted archive" diyor, kod store'a yazıyor (§2.3). **Oracle koddur.** Yardım metni birebir kopyalanmalı (yanlış olsa da), yoksa `--help` bir gün ölçülmeye başlandığında ayrışır |

---

### Dilim 6 — `coolify` ailesi + `secrets sync --target=coolify`

| | |
|---|---|
| fiiller | `coolify deploy-app`, `deploy-app-git`, `import-app`, `set-labels`, `update-env`, `secrets sync --target=coolify` |
| Go kaynağı | `internal/coolify` 527 + `cmd/coolify` 455 + `sync_coolify.go` 456 = **1438 satır** |
| yeni crate | **YOK** — `ureq` + base64 **encode** (§4.1) |
| hazır olan | `wappsyaml.rs` `CoolifySync` + `CoolifyApp`ı (`uuid`, `archive_prefix`, `delete_unmanaged`, `exclude_keys`) ZATEN modelliyor |
| sahte gate | **Coolify API'si için ayrı bir sahte sunucu** gerekiyor (bugünkü `fakegate.py` yalnız gate rotalarını taşıyor). Korpusta `COOLIFY_URL: "{GATE}"` deseni `doctor` vakalarında var — genişletilebilir |
| differential vakası | **35–45** (altı fiil; `--force`/`--dry-run` × tek-app/çok-app yıkıcılık matrisi başlı başına bir alt küme) |
| kapı | `cargo test` yeşil |
| not | Bu dilim tek başına Rust ağacının ~%15'i kadar yeni kod. **Bölünebilir:** önce `coolify update-env` + `set-labels` (en küçük ikisi, 126 satır), sonra kalanı |

---

### Dilim 7 — `deploy`

| | |
|---|---|
| fiiller | `deploy` |
| Go kaynağı | `internal/deploy` 299 + `cmd/deploy/deploy.go` 283 = 582 satır |
| yeni crate | **YOK** (iki regex elde, §4.1) |
| **mimari tuzak** | `deploy`ın KENDİ çıkış kodu sözleşmesi var: **0..8** (`ExitOK`…`ExitFailed`). Rust `main.rs` bugün hata yolunda **daima 1** ile çıkıyor; `execverb`in `ExitAction::Exit(code)` yolu yalnızca çocuk sürecin kodunu yansıtmak için var. Bu dilim main.rs'in hata yolunu fiil-başına-kod taşıyacak şekilde açmayı gerektiriyor — ve o değişiklik ZATEN portlanmış 30 yolun hepsini etkiler |
| differential vakası | **20–26** (dokuz çıkış kodunun her biri ayrı bir dal; `--wait` yoklaması sahte sunucuda) |
| kapı | `cargo test` yeşil **+ mevcut 435 vaka bozulmamış** (çıkış kodu yolu değiştiği için bu bir regresyon riski) |

---

### Dilim 8 — `skill` ailesi

| | |
|---|---|
| fiiller | `skill install`, `skill status`, `skill uninstall` |
| Go kaynağı | `internal/skill` 401 + `cmd/skill/skill.go` 138 = 539 satır |
| yeni crate | **YOK** — gömme `include_str!` (tek dosya, 7901 bayt, §4.1), sembolik bağ `std::os::unix::fs::symlink`, parmak izi `ring` |
| differential vakası | **18–24** (üç fiil × `--local`/`--copy`/`--dir` × kurulu/kurulu-değil/eskimiş durumları) |
| kapı | `cargo test` yeşil |
| bağımlılık | Dilim 10 bunun ÜSTÜNE oturuyor (auto-refresh, `skill.AutoRefresh()`i çağırıyor) |

---

### Dilim 9 — Yardım düzeni: `--version`, `help`, `completion`, bilinmeyen alt komut

| | |
|---|---|
| yüzey | kök `--version`; `help` alt komutu; `completion` (4 kabuk); `wapps <bilinmeyen>` davranışı; çıplak `wapps` |
| yeni crate | **§4.2'nin kararı burada veriliyor** (clap_complete / gömülü betik / düşürme) |
| bu dilimin ASIL işi | Bugün ölçülmeyen **50 düğümlük yardım eksenini** gate'e sokmak, ve `EXCLUDED`daki `agent_unknown_subcommand`ı kapatmak |
| differential vakası | Bu eksen pty differential'a değil, **ayrı bir anlık-görüntü (snapshot) karşılaştırmasına** ait: 50 düğüm × `--help` baytları. pty differential'a eklenecek olan yalnızca davranış vakaları: bilinmeyen alt komut (2), çıplak `wapps` (2), `--version` (2) → **~6 vaka + 50 düğümlük snapshot** |
| kapı | `cargo test` yeşil + `helptext.rs` (spec referansı yasağı) hâlâ geçerli |
| ön koşul | `--version` için sürüm enjeksiyonu; o da release train kararına bağlı (§4.3) |

---

### Dilim 10 — `updatecheck` + skill auto-refresh (çapraz kesen)

| | |
|---|---|
| yüzey | Fiil DEĞİL: `Execute()` sonrası çalışan iki yan bildirim (`cmd/root.go:119`, `:123`) |
| Go kaynağı | `internal/updatecheck` 256 + `root.go` içindeki iki kapı fonksiyonu |
| yeni crate | **muhtemelen YOK** — `ureq` var, semver ayrıştırıcı Go'da da elde yazılı. **ÖLÇÜLMEDİ:** önbellek dosyasının `time.Time` RFC3339 alanı iki ikili arasında PAYLAŞILIYOR (`~/.cache/wapps/version-check.json`); Rust'ın onu Go'nun yazdığı biçimde okuyup yazması gerekiyor ve bunun `chrono`/`time` crate'i gerektirip gerektirmediği ölçülmedi |
| ön koşul | Dilim 8 (`skill` paketi) ve Dilim 9 (`--version` semver'i) |
| differential vakası | **Bugünkü korpusla ÖLÇÜLEMEZ.** `probe.py` her vakaya `WAPPS_NO_UPDATE_CHECK=1` veriyor ve yerel yapıda `Version="dev"` semver değil. Ölçmek için korpusun bu iki kapıyı AÇAN ayrı bir alt kümesi gerekiyor + GitHub API'si için bir sahte sunucu |
| kapı | Yeni bir korpus alt kümesi + `cargo test` |
| not | **Bu dilimin atlanması sessiz bir farktır.** Bugün Rust ikilisi yeni sürümü hiç haber vermiyor ve `brew upgrade` sonrası skill'i hiç tazelemiyor; hiçbir test bunu söylemiyor |

---

### Sıra özeti

| # | dilim | Go satırı | yeni crate | differential vakası |
|---:|---|---:|---|---|
| 1 | `dr accept-epoch-reset` | 172 | yok | 12–16 |
| 2 | `whoami` | 60 | yok | 8–10 |
| 3 | `login` | 634 | yok | 16–20 |
| 4 | `token exchange` | 70 | yok | 10–12 |
| 5 | `secrets sync` (arşiv kolu) | 582 | yok | 14–18 |
| 6 | `coolify` + sync/coolify | 1438 | yok | 35–45 |
| 7 | `deploy` | 582 | yok | 20–26 |
| 8 | `skill` | 539 | yok | 18–24 |
| 9 | yardım düzeni | (cobra) | **KARAR** §4.2 | ~6 + 50 snapshot |
| 10 | updatecheck + auto-refresh | 256+ | ölçülmedi | yeni korpus alt kümesi |

Dilim 1–8 toplamı **4077 satır Go** (172+60+634+70+582+1438+582+539) ve
**133–171 yeni differential vakası**; korpus 435'ten **568–606**'ya çıkar. Dilim 9 ve 10 satır sayısıyla değil, karar ve
harness genişletmesiyle fiyatlanır.

---

## 6. NEYİ ÖLÇMEDİM

Bunlar tahminle doldurulmadı; ölçülmediği için ölçülmemiş olarak yazılıyor.

1. **Portlanmış 30 yolun DAVRANIŞSAL tamlığı.** Ölçtüğüm şey yüzey (komut +
   bayrak) ve differential'ın vaka sayısı. "`secrets get`in 44 vakası var"
   ile "`secrets get` tamamen ölçülmüş" ayrı iddialar; ikincisi için Go
   tarafında dal kapsamı (coverage) ölçmek gerekirdi, ölçmedim.

2. **`--help` metinlerinin bayt bayt eşitliği.** §1'de bayrak KÜMELERİNİ
   karşılaştırdım, yardım METNİNİ değil. Ortak 30 yolun açıklama satırları,
   sıralaması ve kullanım (`Usage:`) blokları karşılaştırılmadı. Rust
   `dr --help` alt komutları farklı SIRADA listeliyor (clap tanım sırası,
   cobra alfabetik) — bunu gördüm ama sistematik ölçmedim.

3. **Bayrak DEĞER tipleri ve varsayılanları.** `--ttl int` ile `--ttl string`
   ayrımı, `stringArray`in tekrarlanabilirliği, varsayılan değerler. Ortak
   yollarda bayrak ADLARININ eşit olduğunu ölçtüm; tiplerin eşitliğini
   ölçmedim.

4. **Dilim 10'un crate ihtiyacı.** `~/.cache/wapps/version-check.json`
   içindeki `time.Time` alanının Rust'ta hangi araçla üretileceği ve bunun
   yeni bir crate gerektirip gerektirmediği ölçülmedi. Go'nun yazdığı biçimi
   okumadım.

5. **`cargo deny` sonucu hiçbir aday için.** §4.2'nin tablosu boş, çünkü bir
   aday crate ağaca girmeden `cargo deny check` koşulamaz. Bu belge o kararı
   VERMİYOR, seçenekleri ölçülmüş olarak koyuyor.

6. **Release train.** `.goreleaser.yml`in tek build hedefinin `./main.go`
   olduğunu ve CI'da `cargo` geçen satır sayısının 0 olduğunu ölçtüm. Rust
   ikilisinin train'e nasıl gireceğini (ikinci bir `builds:` girdisi mi,
   ayrı bir workflow mu, cross-compile hedefleri neler) ölçmedim — bu bir
   dağıtım kararı.

7. **`worker/` ağacı.** CLI yüzeyi sorusunun dışında; hiç bakmadım.

8. **Differential'ın süresi neden değişti.** Bu koşumda 442 sn sürdü; aynı
   ağaçta daha önce 130 sn ölçülmüştü. Bu klonda eşzamanlı ikinci bir şerit
   çalışıyordu (paylaşılan cargo kilidi log'da görünüyor: *"Blocking waiting
   for file lock on package cache"*). Hükmü etkilemedi (`EQUAL=435
   DIFFERENT=0 UNSOUND=0`, exit 0) ama nedeni izole edilmedi.

9. **`rotate skip`in gerçek yolu.** İki ikilinin de aynı reddi ürettiğini
   ölçtüm. Rotasyon executor'ı bağlandığında ortaya çıkacak GERÇEK yolun
   portu bu belgenin kapsamında değil — bugün öyle bir yol yok.
