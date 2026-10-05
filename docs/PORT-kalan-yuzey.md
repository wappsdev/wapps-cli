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
>
> **Dilim 2 ve 4'ten sonra:** `whoami`, `token` ve `token exchange` indi →
> Rust **35** düğüm, eksik yol **15**. `login` KALDI (Dilim 3), yani
> `cmd/login.go` hâlâ yarım.
>
> **After slice 3:** `login` landed → Rust carries **36** nodes, **14** paths
> missing, and `cmd/login.go` is fully ported.
>
> **After slice 5:** `secrets sync` landed WITHOUT its Coolify arm → Rust
> carries **37** nodes, **13** paths missing. The node is there with all seven
> Go flags, but `--target=coolify` is refused (ACTION_UNAVAILABLE) until
> slice 6.

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

*Closed in slice 9:* the help axis is `tests/helpaxis.rs`, and
`agent_unknown_subcommand` is back in the corpus with its arms.

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

> **DECIDED 2026-10-05 by the owner:** the Rust binary's version comes from
> `Cargo.toml` (`CARGO_PKG_VERSION`), and the release keeps it equal to the git
> tag. Implemented in slice 9: a GoReleaser `before` hook
> (`sh rust/check-version.sh {{ .Version }}`) fails the release when the tag's
> version and `rust/crates/cli/Cargo.toml`'s differ (see slice 9).

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

### Dilim 2 — `whoami` · **İNDİ**

**Neden ikinci:** ağa çıkan en ucuz fiil, ve sahte gate rotası ZATEN VAR
(`GET /v1/whoami`, bugün `status`un canlılık probu olarak kullanılıyor).
Yapılacak iş rotayı silmek değil, gövdesini gerçek şekle zenginleştirmek.

| | |
|---|---|
| fiiller | `whoami` |
| Go kaynağı | `cmd/login.go` `whoamiCmd` bloğu **46** satır + `store.Whoami` **14** satır |
| yeni crate | **YOK** — tahmin tuttu |
| store'a eklendi | `whoami()`, `store::Grant`, `store::WhoamiResult` |
| sahte gate | rota KORUNDU (status'un probu hâlâ onu çağırıyor ve BAŞLIKSIZ çağırdığı için daima varsayılan senaryoyu alıyor); gövde yedi senaryoya zenginleşti |
| differential vakası | **14.** Tabandan türetimi: 4 kol × 2 mod = 8, `cfg`+`rooted` muaf → **4**; üstüne fiilin 10 kendi dalı |
| kapı | `cargo test` yeşil (`EQUAL=511 DIFFERENT=0 UNSOUND=0`, exit 0) |

**Fiyatlandırmanın görmediği iki şey çıktı, ikisi de `whoami`ye ÖZEL DEĞİL:**

1. `store.rs`in `safe_code`u Go'nun `safeCode`u DEĞİLDİ (boş kod `"unknown"`
   olmalı, sınıf dışı baytlar ATILMALI, kırpma 48 bayt — port satırsonunu
   boşluğa çevirip 64'e kırpıyordu). Korpustaki her hata gövdesi temiz bir
   `SCREAMING_SNAKE` kodu taşıdığı için hiçbir vaka bunu görmemişti;
   `whoami`nin 403 dalı boş bir kod görebiliyor. Düzeltme BÜTÜN rotaların
   hata yolunu etkiliyor ve mevcut 457 vaka düzeltmeden sonra da eşit kaldı.
2. Go'nun `encoding/json`'ı `null`u her hedef tipe sessizce kabul ediyor
   (dilim → nil, dize → ""), serde ise hata veriyor. `whoami`nin tipleri
   toleranslı hâle getirildi; **aynı fark gate'in diğer rotalarında
   DURUYOR** ve orası ölçülmemiş bir dal.

---

### Dilim 3 — `login` (`--check`, `--write`) · **LANDED**

| | |
|---|---|
| fiiller | `login`, `login --check`, `login --write` |
| Go kaynağı | `cmd/login.go`ın kalanı (414 − 82 = **332** satır) + `internal/session` 302 satır (Rust bugün **69**) |
| yeni crate | **YOK** — `cloudflared` alt süreci (`std::process::Command`, `execverb.rs`te desen var), 0600 oturum dosyası (`atomicfile.rs` var), JWT payload base64url (§4.1) |
| ölçülebilirlik | `cloudflared` bir **shim** ile ölçülür; desen korpusta ZATEN var (`FIXTURE_FILES["tofu"]` + `TOFU_PATH`, `probe.py` `#!` ile başlayanı 0755 yazıyor). `cloudflared` YOKKEN düşen `ACTION_UNAVAILABLE` dalı shim'siz ölçülür |
| differential vakası | **16–20** (üç bayrak kombinasyonu × kollar; artı: cloudflared yok, token boş, bozuk JWT segmenti, oturum dosyası izinleri) |
| kapı | `cargo test` yeşil + `noecho.rs` (token baytı hiçbir yere sızmamalı) |
| dikkat | Yazma oturumu AYRI bir CF Access uygulaması (`/v1/admin`); `session.rs` bu ayrımı zaten taşıyor (`auth_headers` / `auth_headers_admin`) — yeniden yazılmamalı |

**What landed (measured).**

| | |
|---|---|
| verbs | `login`, `login --check`, `login --write` |
| new modules | `loginverb.rs` (cloudflared runner, JWT shape, rendering), `gobase64.rs` (`raw_url_decode` + `std_decode` moved out of `drverb.rs` unchanged) |
| extended | `session.rs` (State, Load, Save, ParseClaims, admin key/URL), `gotime.rs` (full `Duration.String`, `Round(Second)`, `time.Until`), `gojson.rs` (`decode_struct`: Go's struct-decoding rules) |
| new crate | **NONE** — the estimate held |
| differential cases | **30** (priced 16–20): **25** `login` cases + **5** session-file cases on `whoami` / `secrets policy show`. Arms: `bare` + `proj` walked, `cfg` + `rooted` waived with reasons in `ARM_WAIVERS` |
| harness | `probe.py`: 8th case element seeds session files; every case now captures `XDG_CONFIG_HOME/wapps/session` (bytes + file and dir modes) and `diff.py` compares it; `{NOW+N}` placeholder for TTL lines; `{GATEFILE}` names the live fake gate's session key. `cloudflared` shim in `FIXTURE_FILES` |
| new tests | `tests/session.rs`, `tests/gobase64.rs`, `tests/loginverb.rs` (timeout kill, temp-home cleanup, exit/signal texts), `tests/loginleak.rs` (both binaries, under a pty: no token byte or segment in stdout/stderr, temp HOME gone, only the two 0600 files hold the token), duration vectors in `tests/gotime.rs` |
| gate | `cargo test` green — differential `EQUAL=541 DIFFERENT=0 UNSOUND=0` (511 before + 30), `noecho`, `tokenleak`, `loginleak` all pass; `cargo clippy --all-targets` clean; `go build ./...` and `go test ./...` exit 0 (no Go file changed). `cargo fmt --all -- --check` and `cargo deny check` both exit 0 now. Both were already failing on `main`: there was fmt drift in 55 files, and RUSTSEC-2026-0285 was reported against `rustls 0.23.43`. The first round formatted only its new files, which left new drift in `gojson.rs`, `gotime.rs` and `tests/gotime.rs`, and a verifier rejected it. The repair added three commits. The first rustfmts every `.rs` file the slice touched. The second rustfmts the rest of the crate; it is mechanical with no behaviour change, and lanes can resolve conflicts by re-running `cargo fmt`. The third bumps `rustls` 0.23.43 -> 0.23.45 in `Cargo.lock` only, using the advisory's own fix; no new crate and no `Cargo.toml` change |
| pre-slice check | The current corpus was probed with the Go oracle and with `main`'s Rust binary, built in a detached worktree. Result: `EQUAL=514 DIFFERENT=27 UNSOUND=0`. The 27 are the 25 `login` cases plus `human_whoami_presents_the_cached_read_session` and `human_policy_show_presents_the_cached_admin_session`. The other three session-file cases are equal before the slice, as recorded below |
| mutation proofs | (a) admin header pointed at the read key + expiry ignored → 3 session-file cases red; (b) token step's stderr inherited → `loginleak` red ("the whole token leaked"); (c) temp HOME not removed → `loginleak` red. Each mutation was reverted and the file compared byte-for-byte with its backup. Mutation (b) was re-run in the repair round: `cargo test --test loginleak` exit 101, "rust/read login stderr: the whole token leaked". (a) and (c) were not re-run |

**What the pricing got wrong.**

1. *"`session.rs` already carries the split — do not rewrite it" was only
   half true.* The split existed only as a RECOVERY LINE: `auth_headers_admin`
   was `auth_headers` with a different hint, and neither one read the session
   FILE or `WAPPS_SESSION_EXPIRES`. A Rust `login` would have written a file
   no Rust verb ever presented. Both functions keep their names and recovery
   lines, but now load through `session::load` under their own keys (gate
   host / `<host>-admin`) and refuse an expired session, as
   `internal/session/auth.go` does. Two of the five session-file cases were
   red against the pre-slice binary (`whoami` and `policy show` presenting a
   cached session); the other three were already equal (the old code never
   sent anything) and were proven by mutation instead: pointing the admin
   header at the read key turned two of them red, ignoring expiry turned the
   third red.
2. *The temp HOME is not `std::env::temp_dir()`.* Measured on this machine
   with `TMPDIR` unset: Rust returns `/var/folders/.../T/` (confstr), Go's
   `os.TempDir()` returns `/tmp`. `loginverb::temp_base` carries Go's rule;
   the shim reports whether HOME sits under `${TMPDIR:-/tmp}/wapps-cf-*`.
3. *Go's `json.Unmarshal` is observable here.* A `null` payload logs in with
   an unknown expiry (Go accepts `null` into a struct); keys match
   case-insensitively with the last one winning; a type error is a fixed
   sentence naming the first bad field in document order. All of that was
   measured from Go 1.26 and is carried by `gojson::decode_struct`. Syntax
   errors are translated only for an empty payload and a first byte that
   cannot start a value; any other syntax error keeps serde's sentence
   (known, unmeasured).
4. *Determinism needed Go's own saturation.* `login` prints
   `time.Until(exp)` with nanosecond precision. The success cases use
   exp = 99999999999999, which Go saturates to `2562047h47m16.854775807s` —
   a fixed string that also pins the saturation. `--check` prints whole
   seconds and is aligned to a second boundary by `probe.py`.

**Not measured.** The 5-minute SSO timeout in the corpus (unit-tested with an
injected deadline); `Save`'s mkdir/write error texts (Go names a fixed
`<file>.tmp`, `atomicfile` uses a random name); signal names beyond
HUP/INT/KILL/TERM; an `exp` large enough to overflow Go's internal seconds
(> ~9.2e18); Unicode key folding (Go also folds the Kelvin sign and long s);
invalid UTF-8 inside a payload (Go accepts it, serde rejects it).
`secrets status` and `doctor` still read session files with their own serde
readers, so the JSON-decoding differences in point 3 remain there,
unmeasured.

---

### Dilim 4 — `token exchange` · **İNDİ**

| | |
|---|---|
| fiiller | `token`, `token exchange` |
| Go kaynağı | `cmd/login.go` `tokenExchangeCmd` bloğu **36** satır + `store.TokenMint` **34** satır |
| yeni crate | **YOK** — ama iki YENİ MODÜL: `gostrconv` (`strconv.ParseInt(s,0,64)`) ve `gotime` (`time.Unix(n,0).UTC().Format(RFC3339)`). İkisi de saf, ikisi de elde yazıldı; `rotateplan::rfc3339_valid` ile aynı gerekçe |
| store'a eklendi | `token_mint()` (`POST /v1/token`) |
| sahte gate | **+1 rota** (`POST /v1/token`), ve gövdeden SÜRÜLEN bir rota: dönen jeton istemcinin gönderdiği kapsamdan üretiliyor |
| differential vakası | **40** = fiilin **37**'si + gölgenin kısa-biçim yüzünü `dr`ın iki yaprağında ölçen **3**. Fiilin türetimi: 4 kol × 2 mod = 8, `cfg`+`rooted` muaf → **4**; üstüne fiilin 33 kendi dalı |
| kapı | `cargo test` yeşil + `tests/tokenleak.rs`: basılan jeton HAM, ve basılan baytların GERÇEKTEN redaksiyon yemi olduğu ayrıca ölçülü (mutasyonla doğrulandı) |

**`--ttl` ve `--verb` sınırları İSTEMCİDE YOK — ölçüldü.** Fiyatlandırma
"`--ttl` sınırı (≤600), `--verb` doğrulaması" diyordu; Go ikisini de
doğrulamıyor, olduğu gibi tele koyuyor. Sınır gate'in. Sahte gate bu yüzden
ikisini de zorluyor: doğrulayan bir port gate'in reddini HİÇ göremezdi.

**Gölge tuzağının DÖRDÜNCÜ yüzü burada çıktı ve `dr`ın iki yaprağında da
vardı:** yerel `--project` kökün `-p`sini de KALDIRIYOR (cobra yaprağın
flagset'ini kurarken aynı adlı kalıtılan bayrağı atlıyor, ve yerel olanın
shorthand'ı yok) → `wapps -p x token exchange` Go'da
`unknown shorthand flag: 'p' in -p`. Düzeltme üç yaprağı da kapsıyor ve
kontrol vakası `dr verify`: yerel `--project`i OLMAYAN bir yaprakta `-p`
hâlâ ÇALIŞIYOR (o vaka kırmızı turda ZATEN yeşildi).

**Üçüncü ve dördüncü ayrışma:** (a) pflag boşlukla ayrılmış bir uzun
bayraktan sonraki jetonu KOŞULSUZ değer sayıyor, clap saymıyor —
`token exchange`in dört bayrağı da işaretlendi; **deponun diğer değer alan
bayraklarında aynı fark DURUYOR** (ölçüldü: `dr restore --snapshot -x`) ve
bu dilim o ekseni açmadı. (b) `tokenExchangeCmd`in `Args`ı YOK, yani
fazladan bir argüman cobra'da SESSİZCE yutuluyor; clap 1 ile düşüyordu.

---

### Dilim 5 — `secrets sync` (yalnız `--target`sız kol) · **LANDED**

| | |
|---|---|
| fiiller | `secrets sync` (Coolify kolu HARİÇ) |
| Go kaynağı | `cmd/secrets/sync.go` 206 + `internal/source` 376 (`file.go` 118, `file_writer.go` 99, `source.go` 85, `tofu.go` 51, `tofu_exec.go` 23) |
| yeni crate | **YOK** — `.env` ayrıştırıcısı (`importenv.rs` benzeri bir yol zaten var), `tofu output -json` alt süreci |
| hazır olan | `wappsyaml.rs` `SourceConfig`i ZATEN modelliyor ve `validate_source` doğrulamayı ZATEN yapıyor — config yarısı portlu |
| differential vakası | **14–18** (4 kol × 2 mod + `--dry-run`, kaynak yok, bozuk `.env` satırı, `tofu` shim'i üzerinden okuma) |
| kapı | `cargo test` yeşil |
| dikkat | Yardım metni "encrypted archive" diyor, kod store'a yazıyor (§2.3). **Oracle koddur.** Yardım metni birebir kopyalanmalı (yanlış olsa da), yoksa `--help` bir gün ölçülmeye başlandığında ayrışır |

**What landed (measured).**

| | |
|---|---|
| verbs | `secrets sync`, `secrets sync --dry-run`. `--target=<other>` is refused with Go's sentence; `--target=coolify` returns `ACTION_UNAVAILABLE` ("not available in this build") until slice 6 — a known, unmeasured divergence, deliberately NOT in the corpus (closed by slice 6b) |
| new modules | `syncverb.rs` (source names and reads, `tofu output -json` runner, merge, `mergedToSets`, `rawValueToString`, the `--dry-run` report), `goexec.rs` (`look_path` + `exit_text` moved out of `loginverb.rs` unchanged — `tofu` is now their second caller) |
| extended | `wappsyaml.rs` (`resolved_sources`, and `resolve_rel` now CLEANS like Go's `filepath.Join`), `gojson.rs` (`decode_raw_object`, `compact` = `json.Compact`, Go's "after top-level value" syntax error), `store.rs` (`import_values(.., sync)` sends `X-Wapps-Intent: sync`), `cli.rs` (the node, its seven flags, and Go's `Long` text byte for byte) |
| new crate | **NONE** — the estimate held. The `.env` parser is `importenv::parse_env_file`, shared exactly as Go shares `ParseEnvFileBytes` |
| differential cases | **28** (priced 14–18): 4 arms × 2 modes = 8, plus service token, 3 `--dry-run` (report, in sync, epoch downgrade), 4 source failures (missing file, malformed line, no sources, a source with no keys), merge + sync intent, 2 gate errors, 7 through the `tofu` shim (preflight, value stringification, child failure, missing binary, missing workdir, output not an object, envelope not an object), unknown `--target`, extra args |
| harness | `fakegate.py`: an import that carries the key `__DIGEST__` is refused with a 409 whose code digests the `X-Wapps-Intent` header and every value received — a successful import prints only a count, so this is the one way a case sees WHAT went out. The digest cases run in HUMAN mode because the agent envelope's scrubber redacts the code. The `tofu` shim in `FIXTURE_FILES` gained an `output -json` branch that cats `tofu-output.json` from its own cwd (so the workdir is measured) |
| new tests | `tests/syncverb.rs` (20): stringification vectors (null → "", key order and `2.50`/`1e3` kept), Go's case-insensitive last-wins `value` field, Go's type and syntax sentences, merge order, source names, `resolved_sources` cleaning, the `--dry-run` text, and the `Long` help text compared against `cmd/secrets/sync.go` |
| gate | see the commit: `cargo test` (differential `EQUAL=569 DIFFERENT=0 UNSOUND=0` = 541 + 28), `cargo clippy --all-targets`, `cargo fmt --all -- --check`, `cargo deny check`, `go build ./...`, `go test ./...` (no Go file changed) |
| red before green | all 28 cases DIFFERENT against the pre-slice binary (`unrecognized subcommand`) |
| mutation proofs | each reverted and the file compared byte for byte with its backup: (a) no `X-Wapps-Intent: sync` on the import → 2 cases red (both digest cases); (b) stringify non-strings by re-serializing instead of compacting → 1 red (`human_sync_reads_tofu_through_the_shim`); (c) `resolve_rel` without Go's Clean → 4 red; (d) the `tofu` child's stderr inherited → 1 red (`human_sync_tofu_failure_discards_its_stderr`); (e) one word of the copied `Long` text changed → `the_long_help_is_go_s_text_byte_for_byte_stale_as_it_is` red |

**Findings.**

1. *§2.3 confirmed and kept, on purpose.* The `Long` text still says "write an
   encrypted archive to dest"; the code writes the store in one epoch. The
   Rust help copies the text byte for byte and a test pins it to the Go
   source; the BEHAVIOR follows the code. Fixing the text is a Go change and
   belongs to its own commit on both sides.
2. *`resolve_rel` did not clean, and that was a live divergence outside sync
   too.* Go joins with `filepath.Join` (which cleans); Rust used `Path::join`.
   A tofu source with no workdir maps to "." and printed `<root>/.` instead of
   `<root>`; `./x` printed `<root>/./x`. The fix is in the shared helper, so
   target paths and the `set` file-source path now clean too. The whole
   corpus stayed equal after the change.
3. *Go reports merge collisions in RANDOM order when one source overrides
   several keys* (`source.Merge` ranges over a map). Rust prints them sorted
   within each source. Every corpus case overrides at most one key per
   source, so the order is never measured; it cannot be, against Go.
4. *Which malformed key Go names is random too* (`mergedToSets` ranges over a
   map). Rust names the first in sorted order. Measured only with one bad key.
5. *Sync does NOT write the declared targets*, although a comment in
   `cmd/secrets/apply.go` lists sync among the callers of
   `applyTargetsAfterWrite`. Only `import-env` calls it. Rust follows the code.
6. *`rawValueToString` is not `secrets env`'s stringifier.* A null value
   imports as "", where `env` prints `null`. Separately, `envwrite.rs`'s
   compaction re-serializes through `serde_json::Value`, which reorders object
   keys and rewrites numbers; Go's `json.Compact` does neither. That is a
   suspected divergence in `secrets env`/`apply` for object-valued secrets,
   NOT measured and NOT changed in this slice.
7. *The config root is canonicalized in Rust (symlinks resolved) but only
   made absolute in Go* (`filepath.Abs`). Under a symlinked cwd (e.g. macOS
   `/tmp` → `/private/tmp`) the paths in sync's error messages would differ.
   The harness's workdir is already canonical, so this is NOT measured.

**What the pricing got wrong.**

1. *14–18 cases was low:* 28 landed. The tofu arm alone needed 7 because each
   Go `os/exec` behavior is a separate observable sentence (missing binary vs
   missing workdir, discarded stderr, exit status).
2. *`internal/source/file_writer.go` (99 lines) has no non-test caller.*
   `WriteFileSource` is dead in Go; nothing was ported for it. The live Go
   surface of this slice is ≈480 lines, not 582.
3. *"The config half is ported" was half true:* validation was, but
   `ResolvedSources` (the tofu "." default and Go's path cleaning) was not.

**Not measured.** The Coolify arm (slice 6). Collision order with several
overridden keys per source and the choice among several malformed keys (both
random in Go). A tofu child killed by a signal. Syntax errors in tofu output
other than empty input, a bad first byte, and trailing data (serde's sentence
otherwise). A relative PATH entry holding `tofu` (Go's `exec.ErrDot`).
Symlinked config roots (finding 7).

---

#### Finding after landing: a `file` source can read outside the repository (owner decision: B · **LANDED**)

A background security review flagged `syncverb.rs` for path traversal. The Rust code is a
faithful port, so the finding is about the **Go behaviour it reproduces**, and it is recorded
here rather than fixed in the port:

- `ResolvedSources` joins a relative `path` to the config root without bounding `..`, and passes
  an absolute `path` through unchanged. The absolute case is deliberate and tested in Go
  (`TestResolvedSources_AbsoluteUnchanged`, "secrets-from-anywhere").
- So a cloned repository's `.wapps.yaml` can name `~/.ssh/id_rsa` or `../../other/.env` as a
  source, and `wapps secrets sync` would parse it as `.env` and write the `KEY=value` lines into
  the project the same file names.
- Mitigation today: the repo-binding gate. An unpinned repository refuses agent mode and asks a
  human, but the human is not shown which files the YAML will read.

Fixing it changes the shipped Go CLI's behaviour (it would break projects that use absolute
source paths), and fixing it only in Rust breaks the differential. The owner chooses between:
(A) bound sources to the config root in both binaries, (B) keep the behaviour but list the files
a sync will read in the binding prompt, (C) leave it. Recommendation: (A).

**Decision taken (owner, 2026-10-05): (B). LANDED** in both binaries in one change, so the
differential stays equal.

- *Behaviour kept.* Relative (`../`) and absolute source paths still resolve and are read
  exactly as before; `ResolvedSources` is untouched.
- *What the prompt shows now.* When the binding gate asks a human to bind an unpinned
  repository, a `sync reads:` block lists every declared source, resolved against the config
  root and cleaned (`filepath.Clean` / `go_clean`), one per line as `<type> <path>`, and marks
  the ones outside the config root with `(outside the config root)`. No sources → no block, so
  the prompt is byte-identical to before for every config without `sources:`.

  ```
  This repo is not bound to a project yet.
    repo:    /work/repo
    project: testproj
    sync reads:
      file /work/repo/sync.env
      file /work/other/.env (outside the config root)
      tofu /work/repo
  Bind them? [y/N]:
  ```

- *Where it shows.* The pin is per repository and authorizes every later verb (an agent's
  sync included), so the list is printed by the shared gate (`checkRepoBinding` /
  `check_repo_binding`), whichever verb reached it, and by `secrets trust-repo`'s own prompt
  (stdout, after `backend:`/`profiles:`). Two choices made here that the decision text did not
  spell out: trust-repo is included (it is the other way to pin; leaving it out would leave
  one pin path blind), and `tofu` sources are listed by their workdir (sync runs
  `tofu output -json` there, which is a read from outside the repository just the same).
- *"Outside" is lexical and per path component*: a path is inside when it equals the root or
  starts with `root + "/"` (`/a/bc` is not under `/a/b`). Symlinks are not resolved, so a link
  inside the root that points elsewhere is listed as inside. Under `--config`, the root is the
  config file's directory, not the repository root.
- *Code.* Go: `cmd/secrets/agentgate.go` (`bindPromptText`, `syncReadsBlock`, `withinRoot`; the
  `bindPrompt` seam now takes the config), `cmd/secrets/trustrepo.go` (one line). Rust:
  `configctx.rs` (`bind_prompt_text`, `sync_reads_block`, `within_root`; `check_repo_binding`'s
  `ask` takes `&WappsYaml`), `trustrepo.rs` (`prompt_block`), `main.rs` (the two `ask`
  closures). The Turkish comments of `agentgate.go`, `binding_test.go`, `trustrepo.go`,
  `configctx.rs` and `trustrepo.rs` were translated to English in the same change; no code
  changed with them.
- *Tests.* Go `cmd/secrets/syncreads_test.go` (6) and Rust `tests/syncreads.rs` (6), the same
  vectors: inside / cleaned / `../` / uncleaned absolute / tofu default and absolute workdir,
  no sources, the component-wise root check, both prompt texts with and without sources,
  trust-repo's block. Red first: with stub functions, 4 of 6 failed on each side (the two that
  passed pin the unchanged no-sources prompt).
- *Differential.* **8 new cases** (`SYNC_READS_CASES`): a source inside the root (`./sub/../`,
  read after "y"), a relative `../` source (marked; after "y" the read is attempted outside the
  repository and fails on the absent file, so the kept behaviour is measured), an uncleaned
  absolute source (printed cleaned, declined), a sibling that shares the root as a string
  prefix (`cases/<name>.env`, outside), `--config` (root = `sub/`, `../sync.env` marked and
  read), a tofu workdir, the list shown by `secrets list`, and trust-repo's prompt. Against
  the pre-slice Rust binary and the new Go binary: 7 of the first 7 DIFFERENT, each only by the
  block; after the port 8 EQUAL. Floor in `differential.rs` raised 897 → 905 (the live count,
  measured: 909 cases − 4 excluded).
- *Existing cases touched.* The whole corpus (904 cases at that point: 897 + the first 7 new)
  run against the new Go binary and the pre-slice Rust binary: `EQUAL=885 DIFFERENT=19
  UNSOUND=0`. The 19 are the 7 new cases and **12 existing human `secrets sync` cases** that
  answer the prompt with "y" for a config with `sources:`; a script that strips the block from
  Go's output made all 19 byte-identical to the old Rust output, so the block is the only
  change. No other verb's existing case declares `sources:`.
- *Mutation proofs* (Rust, each against the 8-case subset, file restored and compared byte for
  byte with its backup): (a) root check as a plain string prefix → 1 red (the sibling case);
  (b) path not cleaned → 1 (the absolute case); (c) tofu listed by `path` instead of `workdir`
  → 1; (d) trust-repo without the block → 1; (e) no outside marker → 7; (f) inline prompt
  without the block → 7. Go (against the unit tests, the oracle cannot be checked by the
  differential): string-prefix root check → `TestWithinRoot…` red; no `Clean` →
  `TestSyncReadsBlock…` red.
- *Gates*, each run as its own command and its exit code read on its own: `go build ./...` 0,
  `go vet ./cmd/... ./internal/...` 0, `go test ./...` 0, `cargo fmt --all -- --check` 0,
  `cargo clippy --all-targets -- -D warnings` 0, `cargo deny check` 0, `cargo test --release`
  0 (differential `EQUAL=905 DIFFERENT=0 UNSOUND=0`, 497 s; 55 test binaries ok, `armcheck`
  included). `gofmt -l cmd/` lists `cmd/secrets/env.go`, which this change does not touch and
  which is listed on `main` too.

**Open finding (not fixed, needs a decision).** The listed paths are printed raw, exactly as
the repo id and the project name already were. A hostile `.wapps.yaml` can put a carriage
return or an ANSI escape in a `path:` and redraw the line so the outside marker (or the whole
entry) is hidden on a terminal. Quoting only paths that contain control characters (Go
`strconv.Quote`, Rust `gostrconv::quote`) would close it for the list; the project name has
the same exposure and predates this change. Not done here because it changes what every
binding prompt prints and touches a known `quote` divergence (non-ASCII, slice 6a).

**Not measured.** A symlinked config root (slice 5 finding 7: Rust canonicalizes, Go only
makes absolute, so the printed paths would differ under e.g. `/tmp`; the harness's workdir is
canonical). A config at `/` (the `root == "/"` branch is unit-tested only). Whether a human
actually reads the list before answering.


---

### Dilim 6 — `coolify` ailesi + `secrets sync --target=coolify` · **LANDED** (6a + 6b)

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

#### Slice 6a — `coolify update-env` + `coolify set-labels` · **LANDED**

| | |
|---|---|
| verbs | `coolify` (the family: bare, it prints help and exits 0), `coolify update-env`, `coolify set-labels` |
| Go source | `cmd/coolify` 145 (`coolify.go` 19, `update_env.go` 66, `set_labels.go` 60) + the parts of `internal/coolify` these two call, ≈250 of 527 (`validateUUID`, `Client`/`New`, `HTTPError`, `UpdateAppEnvs`, `SetCustomLabels`, `doBytes`/`do`, `UpsertAppEnv`) |
| new modules | `coolify.rs` 219 (the client), `coolifyverb.rs` 179 (flags, checks, output), `gocsv.rs` 199 (pflag's `readAsCSV`, see finding 1) |
| extended | `gobase64.rs` (`std_encode`, next to the hand-written decoders — §4.1 held), `gostrconv.rs` (`parse_bool`, Go's `strconv.Quote`/`QuoteRune`), `store.rs` (`tls_config()` extracted so the Coolify client trusts exactly the gate client's roots), `cli.rs` (the family and its two leaves), `main.rs` (dispatch, and the flag-value check before the root's `--config`/`--project` check) |
| new crate | **NONE**. `ureq` for HTTP, base64 by hand, CSV by hand (the `csv` crate's error texts are not Go's) |
| differential cases | **66**: 4 identity arms × 2 modes × 2 verbs = 16; update-env 28 (refusal order, CSV splitting and errors, uuid checks, POST, PATCH after 409, every key sent, body echoes, wrong token, 404, pflag shape); set-labels 22 (empty and fully-stripped refusals, bool parsing, the leftmost bad value wins, body echoes, 200-byte cut in both modes, 404, wrong token) |
| harness | `fakegate.py` now serves a fake Coolify v4 API under `/api/v1` (`COOLIFY_URL: "{GATE}/api/v1"`, the doctor cases' pattern). Every request must carry `Authorization: Bearer <test token>`, `User-Agent: curl/8` and `Content-Type: application/json`; bodies are validated field by field (`custom_labels` must be strict padded base64; an env body must be exactly Go's five fields with Go's constant flags). The app uuid or env key picks a scenario; the `echo` scenarios refuse with a body that repeats what was received plus the sha256 of the raw request bytes, so a case sees what went out (the `\n` join, the strip filter, Go's JSON key order and `<>&` escaping) |
| new tests | `tests/gocsv.rs` (41 Go-produced vectors), `tests/coolifyverb.rs` (5: uuid texts, the 200-byte cut, pflag's slice error, `parseEnvKVs`, the strip filter), `tests/gobase64.rs` (+1: `std_encode`, 9 vectors), `tests/gostrconv.rs` (+3: `ParseBool`, `Quote`, `QuoteRune`) |
| gate | `cargo test --release` (differential `EQUAL=635 DIFFERENT=0 UNSOUND=0` = 569 + 66), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `go build ./...`, `go test ./...` (no Go file changed) |
| red before green | all 66 cases DIFFERENT against the pre-slice binary (`unrecognized subcommand`); after the port, 66 EQUAL on the first run |
| mutation proofs | each against the coolify subset of the corpus, reverted, and the file compared byte for byte with its backup: (a) no `User-Agent: curl/8` → 34 red; (b) labels joined with "," → 2 red (both echoes); (c) no PATCH after a 409 → 11 red; (d) `--strip-cert-resolver` defaulting to false → 2 red; (e) error body cut at 199 bytes → 2 red (human and agent); (f) values not read as CSV → 8 red; (g) the root's identity check moved before the flag-value check → 1 red; (h) only the first env key sent → 1 red (`every_key_is_sent`); (i) the first-listed instead of the leftmost bad value → 1 red. One mutation SURVIVED in the first round: a leftmost-error pass over `--env` alone was redundant (`string_slice` already stops at the first bad value), so removing it changed nothing; the pass was deleted and (g) was re-aimed at `main.rs` |

**Findings.**

1. *Every `--env` and `--label` value is CSV.* Both are pflag `StringSliceVar`s,
   so each value goes through `encoding/csv`: `--env A=1,B=2` is two entries,
   `--env '"K=a,b"'` keeps its comma, `--env 'a"b'` is refused with
   `invalid argument "a\"b" for "--env" flag: parse error on line 1, column 2:
   bare " in non-quoted-field`, `--env $'\n'` is refused with `EOF`, and
   everything after the first line break of a value is silently dropped. The
   pricing did not see this; it is why `gocsv.rs` exists. A Traefik label with a
   comma in it (`Host(`a`,`b`)`) is split into two labels by the Go CLI — the
   port does the same, on purpose.
2. *A bad flag VALUE beats the root's `--config`/`--project` check.* pflag
   parses values at parse time, before `PersistentPreRunE`. `main.rs` therefore
   parses the coolify leaves' values before that check (one case pins it).
3. *`--strip-cert-resolver` is a pflag bool:* `--strip-cert-resolver false`
   (spaced) does NOT turn it off — `false` becomes an ignored argument and the
   strip stays on. Measured, and ported.
4. *Go upserts env keys in random order* (a map range); Rust sorts. Only which
   failing key is named can differ, and only when two or more keys fail. No
   case has more than one failing key; one case puts the failing key last in
   sorted order, which proves every key is sent.

**Known divergences, not in the corpus.**

1. *Transport errors.* Go prints `<METHOD> <path>: <Method> "<url>": dial tcp
   <resolved address>: connect: connection refused`; the port prints the same
   prefix and ureq's own cause. Same reason as the gate's `human_gate_down`.
2. *An error body cut through a multi-byte character.* Go prints the raw
   partial bytes (human) or one `�` per invalid byte (agent envelope); the
   port holds the message in a `String` and prints one U+FFFD per invalid
   sequence. Realistic for a non-ASCII Coolify body longer than 200 bytes.
3. *Proxies.* Go's client honours `HTTP(S)_PROXY`/`NO_PROXY`; the port's ureq
   agent uses no proxy (ureq 2 has no `NO_PROXY`). Same as the gate client.
4. *307/308 on PATCH/POST.* Go re-sends the body to the new location; ureq 2
   does not follow and the 3xx counts as success. Coolify's API is not known to
   redirect; not measured.
5. *Non-ASCII `%q`.* `gostrconv::quote` escapes control, space and format
   characters like Go; unassigned and private-use code points print raw where
   Go escapes them.
6. *Flag errors across different flags.* pflag reports the leftmost failing
   token; clap reports an unknown flag before any value error, and a missing
   value (`--app-uuid` at the end) with its own sentence. Not measured.

**What the pricing got wrong.** "126 lines" was the two `cmd` files only; the
slice also needed ≈250 lines of `internal/coolify`, and pflag's CSV reading of
slice flags (finding 1) was not priced at all. 35–45 cases for all six verbs was
low: these two verbs alone needed 66.

**What remains of slice 6** (measured with `wc -l`, Go):

| part | Go lines | what it needs on top of 6a |
|---|---:|---|
| `coolify deploy-app` | 98 | `CreateDockerComposeApp`, `StartApp`, `--env-from-shell` (a CSV slice too), writes `.outputs/<name>-uuid` |
| `coolify deploy-app-git` | 115 | `CreatePrivateGitHubAppApp` (13-field body), `SetBuildArgs`, `TriggerDeploy` (`GET /deploy?uuid=`), deferred-deploy rule, `.outputs/` |
| `coolify import-app` | 97 | `ListApplications` + `doRaw` (array or `{"data": [...]}`), the `[^a-zA-Z0-9_]+` identifier rewrite by hand, writes `imports.sh` + `apps.tf` |
| rest of `internal/coolify` | ≈275 | the calls above plus `ListAppEnvs`, `DeleteAppEnv`, `asString`/`asBool` (the last three are used only by sync) |
| `secrets sync --target=coolify` | 456 | `cmd/secrets/sync_coolify.go`: single-app and multi-app diff, `--force`/`--dry-run`, `delete_unmanaged`, `exclude_keys`, prefix stripping |
| **total** | **≈1041** | of the 1438 priced for slice 6 |

#### Slice 6b — `coolify deploy-app`, `deploy-app-git`, `import-app` + `secrets sync --target=coolify` · **LANDED**

Two commits on the lane, as the task allowed: the three verbs first, the sync
arm second. Together with 6a this lands the whole of slice 6.

| | |
|---|---|
| verbs | `coolify deploy-app`, `coolify deploy-app-git`, `coolify import-app`, `secrets sync --target=coolify` (single-app `--app` and multi-app `--all-apps`, each dry-run by default and applied with `--force`). The `ACTION_UNAVAILABLE` divergence slice 5 recorded is closed |
| Go source | `cmd/coolify` 310 (`deploy_app.go` 98, `deploy_app_git.go` 115, `import_app.go` 97), the rest of `internal/coolify` (`client.go` + `envs.go`), `cmd/secrets/sync_coolify.go` 456 |
| new modules | `coolifysync.rs` 285 (diff, report, prefix mapping, apply, per-app isolation) |
| extended | `coolify.rs` 219 → 517 (both creates, start, deploy, build args, the application list, `ListAppEnvs`, `DeleteAppEnv`, Go's `doRaw` and `do` answer handling, `go_fmt_v` = Go's `%v` of a decoded answer), `coolifyverb.rs` 175 → 563 (three leaves, cobra's sorted required-flag error, leftmost bad value across three value-parsed flags, `.outputs/` and the import files), `cli.rs` (three leaves; `sync` now lets every flag repeat, see finding 1), `main.rs` (`run_sync_coolify`) |
| new crate | **NONE** |
| differential cases | **143** (93 verbs + 50 sync). deploy-app 38 (4 arms × 2 modes; sorted required flags; empty value counts as set; compose read before the shell env; unset/empty/`=`-named shell vars; create echo; env upsert and echo; create failure; no uuid / not JSON; a bad uuid from the API; start failure; ignored `.outputs` write errors; overwrite; wrong token); deploy-app-git 32 (arms; required flags; bool and CSV errors, leftmost wins; six body echoes for defaults, deferred deploy, `--instant-deploy=false`, spaced bool, watch paths + empty base dir, every value flag; build args then deploy, without deploy, malformed pairs counted, `is_buildtime` echo, failure after the create, deploy failure, bad uuid); import-app 23 (arms; server filter; `{"data": …}`; object and non-JSON bodies as empty lists; list failure; cleaned and empty output dir; truncation; output dir a file; `apps.tf` uncreatable). Sync 50: the four arms × two modes (8); flag, token and config refusals before the store read (6); store errors (2); single-app 19 (dry-run, `{"data": …}` and empty-list answers, `--prefix`, `--dry-run` ignored, repeated `--app`, extra args, `--force` in both modes, two journals, the three failure points ADD / PATCH after 409 / REMOVE, a bad env uuid, a duplicate runtime key, a bad and a missing app, wrong token); multi-app 15 (dry-run and `--force` in both modes, `delete_unmanaged` true / false / absent, without `exclude_keys`, `--prefix` ignored, a journal over two apps, list and apply failures isolated, a bad uuid in the config, no block, an empty `apps`) |
| harness | `fakegate.py`: the fake Coolify API gains both creates (exact field sets, strict padded base64 compose, `environment_name` must be "production"), start and deploy (must arrive WITHOUT a body), the application list chosen by a `:<tag>` on the token, env tables per app (`COOLIFY_APP_ENVS`: managed, preview, duplicate, non-string and invalid-uuid entries), env DELETE (unknown env uuid → 404), and `is_buildtime` checked per app (true only on a "gh-*" app). **The journal**: per app, every env write received since that app was last listed; deleting `env-journal` (key `ZZ_JOURNAL`, which sorts last) is refused with a digest of it, so a case sees every value, flag, env uuid and the add → change → remove order. The store side gains per-project bulk sets (`__ALL__@coolproj`). `probe.py` substitutes `{GATE}` in argv too (sync reads `--coolify-url` only) |
| new tests | `tests/coolifysync.rs` (9: the Go diff vectors of `sync_coolify_test.go`, a duplicate runtime key, exclusion counting with a managed key and a duplicate entry, the report text, prefix prepend/strip), `tests/coolifyverb.rs` (+5: `go_fmt_v` on 10 vectors, Go's rune-wise lowercase, `filepath.Join`, `collectEnvFromShell`, the import files) |
| gate | see the commits: `cargo test --release` (differential `EQUAL=821 DIFFERENT=0 UNSOUND=0` = 678 + 143, floor raised to 821), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `go build ./...`, `go test ./...` (no Go file changed) |
| red before green | the 93 verb cases: 93 DIFFERENT against the pre-slice binary (`unrecognized subcommand`), 93 EQUAL after the port on the first run. The 49 sync cases written before the arm: 46 DIFFERENT, 3 EQUAL before and after (two unpinned-config refusals and the `--project` binding refusal: the binding gate fires before `--target` is read); after the port 47 EQUAL and 2 DIFFERENT, which were real (findings 1 and 3). The duplicate-runtime-key case was added after the port, EQUAL at once, and is proven by mutation (j) |
| mutation proofs | each against the coolify or sync subset, reverted, the file compared byte for byte with its backup. Verbs: (a) no deferred deploy → 1 red; (b) build args sent as runtime envs → 7 red; (c) start sent with a body → 15 red; (d) full instead of rune-wise lowercase → 13 red; (e) `filepath.Join` without Clean → 15 red; (f) required flags unsorted → 5 red; (g) shell env read through `std::env::var` → 1 red (finding 2); (h) the `{"data": …}` envelope not read → 1 red. Sync: (a) single-app not destructive → 16 red; (b) preview entries not ignored → 14; (c) managed keys kept in desired → 20; (d) an exclusion counted although managed → 9; (e) removes applied before adds → 3 (journal cases only); (f) a change sent with the OLD value → 2 (journal cases only); (g) multi-app stops at the first failed list → 2; (h) a key equal to the prefix kept → 11; (i) the app uuid checked before the store read → 1 (the pin no longer advances); (j) the first runtime entry kept instead of the last → 1; (k) one app's apply failure aborts the run → 2. One mutation SURVIVED in the first round: an explicit `'İ' → 'i'` branch in the lowercase was redundant (taking the first char of Rust's full lowercase already gives Go's simple mapping), so it was removed and (d) was re-aimed at the first-char rule. Unit tests: an exclusion counted although managed, and `%v`'s exponent threshold moved to 22, each fail their test |

**Findings.**

1. *Every value flag of `secrets sync` refused to repeat* — clap rejects a
   second `--app`, `--target`, `--prefix` or `--coolify-url`, where pflag takes
   the last. A live divergence on the node slice 5 landed, invisible until a
   case repeated a flag. Fixed with `args_override_self` on the `sync` node.
   Other nodes with single-value flags may have the same gap; not measured.
2. *macOS `getenv` stops a name at `=`.* `--env-from-shell 'DA_ONE=x'` would
   read `DA_ONE`'s value through `std::env::var` (libc). Go reads nothing and
   refuses. The port matches names exactly over the environment.
3. *YAML syntax errors are worded differently by the shared loader.*
   `version: [` → Go `config: parse yaml: yaml: line 1: did not find expected
   node content`, Rust `config: parse yaml: version: invalid type: sequence,
   expected i64`. Not a slice-6 divergence: every config-loading verb has it,
   and no case in the corpus uses a YAML SYNTAX error (all of `CONFIG_CASES`
   are semantic). The case written for it was re-pointed at a semantic error;
   the divergence is recorded, not fixed.
4. *Single-app sync checks `--app` only AFTER the store read*, so a bad uuid
   still advances the epoch pin. Measured and ported.
5. *`sync --target=coolify` reads its URL from `--coolify-url` only*, while the
   `coolify` verbs read `COOLIFY_URL`. `--dry-run` is ignored on this arm
   (dry-run is its default). Both ported as they are.
6. *`deploy-app-git` counts skipped build args*: `--build-arg NOEQ --build-arg
   =v --build-arg A=1` sends one env and prints "Set 3 build arg(s)". It also
   writes and prints a uuid the API returned before checking it (only the
   build-arg call refuses `../x`). Ported.
7. *`import-app`'s `app_<uuid[:8]>` fallback is unreachable*: a non-empty name
   never yields an empty identifier. Not ported (it would also panic in Go on
   a uuid shorter than 8 bytes).
8. *Go lowercases rune by rune*: `İstanbul` becomes `istanbul`, where Rust's
   full lowercase gives `i̇stanbul` and the sanitizer would add a `_`.

**Known divergences, not in the corpus.**

1. *Bool flags with a value on `sync`*: pflag accepts `--force=false` and
   `--all-apps=false`; clap's `SetTrue` refuses them. The refusal is the safe
   direction (no apply), but it is a divergence. Pre-existing on the node.
2. *Invalid UTF-8 in a Coolify answer*: Go's decoder replaces it, serde_json
   rejects it, so the port would read an empty list (or `map[]`) where Go reads
   the data.
3. As 6a: transport error texts, proxies, 307/308 on a write.

**What the pricing got wrong.** 35–45 cases for all six verbs; slice 6 needed
209 (66 + 143). The ≈1041 Go lines 6a counted as remaining were right in
size; the part not priced was the HARNESS: a fake that only answers can not
measure an apply, because an apply prints counts. The write journal is what
made the destructive matrix measurable (mutations (e) and (f) are caught by
nothing else).

---

### Dilim 7 — `deploy` · **LANDED**

| | |
|---|---|
| fiiller | `deploy` |
| Go kaynağı | `internal/deploy` 299 + `cmd/deploy/deploy.go` 283 = 582 satır |
| yeni crate | **YOK** (iki regex elde, §4.1) |
| **mimari tuzak** | `deploy`ın KENDİ çıkış kodu sözleşmesi var: **0..8** (`ExitOK`…`ExitFailed`). Rust `main.rs` bugün hata yolunda **daima 1** ile çıkıyor; `execverb`in `ExitAction::Exit(code)` yolu yalnızca çocuk sürecin kodunu yansıtmak için var. Bu dilim main.rs'in hata yolunu fiil-başına-kod taşıyacak şekilde açmayı gerektiriyor — ve o değişiklik ZATEN portlanmış 30 yolun hepsini etkiler |
| differential vakası | **20–26** (dokuz çıkış kodunun her biri ayrı bir dal; `--wait` yoklaması sahte sunucuda) |
| kapı | `cargo test` yeşil **+ mevcut 435 vaka bozulmamış** (çıkış kodu yolu değiştiği için bu bir regresyon riski) |

**What landed (measured).** Two commits on the lane, in the order the trap
asks for: the exit-code path alone first, deploy on top.

| | |
|---|---|
| commit 1: the exit-code path | `CmdError::Exit(u8)` in `cli.rs`: an error the verb has ALREADY written, carrying its own code; `report_error` prints nothing for it and `main` exits with `exit_code()` (1 for every other error, as before). The exec family's mirrored child code (`secrets exec`, `tofu`, `dr bootstrap`) now leaves through it instead of `std::process::exit`. No deploy code in the commit. Regression gate on the untouched corpus: `EQUAL=821 DIFFERENT=0 UNSOUND=0` (349 s); the corpus already has three nonzero child codes (`exec … exit 42`, the `tofu` shim's 3, `dr bootstrap … exit 7`), so the new path was walked by existing cases, not only declared. New test `tests/exitcode.rs` (3), red before the variant existed |
| verb | `deploy <service>` with `--repo --wait --timeout --poll-interval --ep --json`. No agent guard and no binding gate, as in Go; agent mode changes only the ROOT's errors (flag value, arity, exclusion), never the verb's own lines |
| new module | `deployverb.rs` (the proxy client, the HTTP classification, credential resolution, the --wait loop, the JSON line, pflag-style flag parsing). The two regexes are byte-class checks by hand |
| extended | `main.rs` (flag values and `ExactArgs(1)` before the root's exclusion, `run_deploy` wiring `Ctx` + `storevalues::store_values` + `store::keys`/`read`), `cli.rs` (the node, Go's Short/Long byte for byte; `coolify_bool`/`coolify_value` renamed `pflag_bool`/`pflag_value` now that they have a second caller), `coolifyverb.rs` (five flag helpers made `pub(crate)` for reuse), `storevalues.rs` (its first production caller; comments translated, the stale "no verb reaches here" header replaced) |
| new crate | **NONE** — the estimate held (`ureq` with `redirects(0)`, `gojson::decode_struct`/`decode_raw_object` for Go's decoding rules) |
| differential cases | **76** (priced 20–26). Four identity arms × two modes (8, plus one: an unregistered `--project` does not replace the cwd config); exit 1: 15 (unknown repo, bad/too long/HTML-escaped service, repo checked first, arity 0 and 2, a spaced bool is an argument, bad int and bool values, leftmost bad value, value and arity before the exclusion, the exclusion); exit 2: 10 (none, missing id, missing secret, repo-named key, store unreadable / denied / epoch downgrade / config unloadable as a `note:` line, a store without candidates); exit 0 resolution: 9 (env beats store per value, the store read even when env suffices, an unreadable store when env suffices, store legacy names, env legacy names, `DEPLOY_PROXY_EP`, `--ep` beats env and keeps its slash, JSON, another repo); exit 3: 3; exit 4: 3 (403 HTML, 302 not followed, 503); exit 5: 2; exit 6: 12 (400, 404 naming the SERVICE, 404 not JSON, 502, 500 with JSON, 201, an `Error` key in another case, empty / invalid / too long / non-JSON / non-string id); --wait: finished ×2, `unknown` keeps polling, timeout ×2, a deadline cutting a request in flight, failed / cancelled / error with default timings, 404 / 403 naming the DEPLOYMENT ID / edge block mid-poll ×2 |
| harness | `fakegate.py` serves a fake deploy proxy under `/dp` (`--ep {GATE}/dp`): every request must carry `User-Agent: wapps-cli` and the three test credentials, else the proxy's 401; service `dp-echo` answers a deployment id that is a digest of the three header values (which source and which fallback name won, with no value printed); the service picks the trigger answer, the id picks a poll sequence (reset on every trigger, so twins see the same one; `w-slow` answers after 3 s). The bulk read substitutes `{GATE}` in stored values (a `DEPLOY_PROXY_EP` in the store points back at the fake). `probe.py` normalizes the fake's root URL in stdout/stderr back to `{GATE}`: deploy prints the endpoint it resolved, and the port differs per binary. Before this no EQUAL case could contain that string, so no existing comparison loosened (the 821 stayed EQUAL with it) |
| new tests | `tests/deployverb.rs` (13): both patterns with their boundaries, the status table, the HTTP classification table (21 rows), `parseField`, the known-repo list, the store candidates in Go's order, the env-before-store tiers, the endpoint order, the first missing credential, Go's JSON line, the help texts read out of `cmd/deploy/deploy.go` |
| gate | `cargo test --release` (differential `EQUAL=897 DIFFERENT=0 UNSOUND=0` = 821 + 76; the floor in `differential.rs` raised from 821 to 897), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `go build ./...`, `go test ./...` (no Go file changed) |
| red before green | 75 of the cases written first: 75 DIFFERENT against the exit-code commit's binary (no `deploy` subcommand), 75 EQUAL after the port on the first run. The 76th (`agent_deploy_store_read_even_when_env_suffices`) was added after mutation (c) below had no case to catch it; all 76 are DIFFERENT against the pre-deploy binary |
| mutation proofs | each against the deploy subset, the file restored and compared byte for byte with its backup: (a) redirects followed → 1 red (`…edge_302_not_followed`); (b) 302 not an edge block → 1; (c) no store read when the env has everything → 1 (the case added for it); (d) progress lines under `--json` → 3; (e) a request cut by the deadline reported as network → 1; (f) no `unknown` default → 1; (g) the status subject is not the deployment id → 2; (h) the endpoint's trailing slash not trimmed → 1; (i) failure messages on stdout → 34; (j) the store's legacy names ignored → 1; (k) a verb-owned code collapsed to 1 → 40; (l) the exclusion checked before the arity → 1. Unit: env and store tiers interleaved per key → `every_env_tier_beats_every_store_tier` red. The first run of (l) was contaminated and rerun: the runner restored files with `shutil.copy2`, which also restores the OLD mtime, so cargo kept the previous mutation (k) compiled in; it now restores with a fresh mtime |

**Findings.**

1. *deploy exits from inside RunE.* Go calls `os.Exit(runDeploy(...))`, so
   the root's post-command hooks — the update notice and the skill
   auto-refresh — never run after deploy, whatever its outcome. Slice 10 must
   keep them off for this verb.
2. *The store is read whenever a `.wapps.yaml` loads,* even when the env
   supplies every credential: the epoch pin advances, and a store failure is
   silent unless a credential is missing (then it is the `note:` line). Go's
   `StoreValues` does not check `backend:` and there is no binding gate.
3. *An unregistered `--project` is inert:* `StoreValues` reads the cwd (or
   `--config`) file, never the project name the flag carries.
4. *The 404 and 403 subjects swap meaning between routes.* A trigger 404 says
   `deployment "<service>" not known`; a status 403 says `"<deployment id>" not
   in scope for repo …`. Both ported as they are.
5. *Any non-200 is classified, 2xx included:* a 201 with a valid id is
   `unexpected proxy response (HTTP 201)`, exit 6.
6. *The `error` key is matched case-insensitively* (Go struct decoding), so a
   proxy body `{"Error": "…"}` is proxy JSON; `{"error": ""}` and
   `{"error": 5}` are not.
7. *`--timeout`/`--poll-interval` are base-0 ints:* `0x0` is zero, and a
   non-positive value takes the default (1200 s / 15 s).
8. *The endpoint is printed as given* (`…/dp/` keeps its slash) and trimmed
   only in the request path.

**Known divergences, not in the corpus.**

1. *The deadline racing the next poll.* Go `select`s between the context and
   the interval timer; when both expire together either can win. The port
   decides deterministically (a deadline inside the next interval is a
   timeout). No case puts the two within a millisecond of each other.
2. *A `--timeout` past `math.MaxInt64` nanoseconds* (≈292 years): Go's
   `Duration` multiplication wraps; the port waits ~136 years. Not measured.
3. *Proxies:* Go honours `HTTP(S)_PROXY`/`NO_PROXY`; the ureq agent uses none
   (same as the gate and Coolify clients).
4. *Invalid UTF-8 or a lone surrogate in a proxy answer:* Go's decoder
   replaces it, serde_json refuses it (the field reads as empty).

**What the pricing got wrong.** 20–26 cases was low by a factor of three: 76
landed. The nine exit codes are nine CODES, not nine branches — exit 6 alone
is twelve distinct answers, exit 2 is a credential matrix (three values × two
tiers × fallback names) multiplied by the four identity arms, and the --wait
loop has its own success, timeout and fail-closed branches. The exit-code
path itself cost one variant and no regression, as the corpus proved; the
real cost was again the harness (a fake proxy with poll state, and the
printed endpoint's port).

**Not measured.** The default endpoint (no case may reach the real proxy). A
transport timeout of the 45 s request budget. HTTP 1xx answers. A body over
1 MiB. `--json=false` / `--wait=false` (pflag and `pflag_bool` both accept them by construction; no case). The help
layout (`wapps deploy --help`, slice 9).

---

### Dilim 8 — `skill` ailesi · **LANDED**

| | |
|---|---|
| fiiller | `skill install`, `skill status`, `skill uninstall` |
| Go kaynağı | `internal/skill` 401 + `cmd/skill/skill.go` 138 = 539 satır |
| yeni crate | **YOK** — gömme `include_str!` (tek dosya, 7901 bayt, §4.1), sembolik bağ `std::os::unix::fs::symlink`, parmak izi `ring` |
| differential vakası | **18–24** (üç fiil × `--local`/`--copy`/`--dir` × kurulu/kurulu-değil/eskimiş durumları) |
| kapı | `cargo test` yeşil |
| bağımlılık | Dilim 10 bunun ÜSTÜNE oturuyor (auto-refresh, `skill.AutoRefresh()`i çağırıyor) |

**What landed (measured).**

| | |
|---|---|
| verbs | `skill install` (`--local`, `--dir`, `--copy`), `skill status`, `skill uninstall` (`--local`, `--dir`). No gate, as in Go: no agent guard, no binding, no `Ctx::resolve`; the root's `--config`/`--project` are inert (all four arms are in the corpus, none waived) and only their combination is refused, by the root |
| new module | `skill.rs` (embedded asset via `include_str!` of the Go asset itself, the `ring` fingerprint, Go-faithful `MkdirAll`/`Remove`/`RemoveAll`, install/status/uninstall and their output). `AutoRefresh` is NOT ported — it is slice 10 |
| extended | `cli.rs` (the node, Go's Short/Long texts byte for byte), `main.rs` (one dispatch arm + `run_skill`), `goerr.rs` (`AlreadyExists` → "file exists", for Go's `symlink <old> <new>: file exists`), `wappsyaml.rs` (`go_clean` made `pub` so the skill paths reuse it instead of a third copy) |
| new crate | **NONE** — the estimate held |
| differential cases | **43** (priced 18–24): install 23 (user symlink fresh/current/stale source/dangling link/uncleaned link target/copied file in the slot, user copy, `--dir` without `--local`, project symlink/copy/stale copy/cleaned relative `--dir`/absolute `--dir`, `--dir` naming a file ×2, no `$HOME` ×3, `~/.config` blocked, link slot a non-empty and an empty directory, uncleaned `$HOME`, extra arg), status 8, uninstall 7, identity arms 4, both flags 1 |
| harness | Every skill case gets its OWN home: `HOME={CASE}/home` (`{CASE}` is new in `probe.py`, substituted in env values, argv and seeded link targets) puts `$HOME` inside the case directory, which is rebuilt for each binary and snapshotted after the run — so what each binary wrote is compared and no case can reach the real `~/.claude`. Before this the corpus shared one `fakehome` across cases AND across the two binaries. The `written` snapshot now records a symlink as `["symlink", <target>]` (a link and a copy with the same bytes are different installs; a dangling link has no bytes) and an empty directory as `["emptydir", <mode>]`; the seed gained `links` and `dirs`. Measured: with the extended snapshot the 569 previous cases stayed EQUAL against the pre-slice binary. `cases.py` reads the Go asset to seed "current" installs; it looks it up from the pty directory on the import path too, because `tests/armcheck.rs` imports a COPY of the module from a temp dir (the first version used `__file__` only and turned armcheck red) |
| new tests | `tests/skill.rs` (4): the embedded text equals the Go asset byte for byte, the fingerprint equals the one a Go install wrote (`3a6443b6…`), its framing (`name NUL content NUL`), and the Short/Long texts evaluated out of `cmd/skill/skill.go` |
| gate | `cargo test --release` (differential `EQUAL=612 DIFFERENT=0 UNSOUND=0` = 569 + 43; the floor in `differential.rs` raised from 511 to the live count 612), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `go build ./...`, `go test ./...` (no Go file changed) |
| red before green | all 43 cases DIFFERENT against the pre-slice binary (`unrecognized subcommand`) |
| mutation proofs | each reverted, the file compared byte for byte with its backup: (a) compare the existing link as a `Path` instead of a string → 1 red (`…rewrites_an_uncleaned_link`); (b) join without Go's Clean → 2 red; (c) `Remove` without the rmdir fallback → 1 red (`…link_slot_is_an_empty_directory`); (d) `std::fs::create_dir_all` instead of Go's `MkdirAll` → 3 red (the error names a different path); (e) materialize the source before creating the destination → 3 red (the empty destination a failed install leaves behind); (f) `RemoveAll` as `remove_dir_all` on a file → 1 red; (g) no `.fingerprint` marker → 11 red |

**Findings.**

1. *The corpus could not have measured this verb as it stood.* `HOME` was one
   shared `fakehome`, reused by every case and by both binaries in turn, so the
   Go run's install would have been the Rust run's starting state. And the
   snapshot followed symlinks, so a link and a copy compared equal and a
   dangling link crashed the probe. Both fixed in the harness (above).
2. *Go compares the existing link target as a STRING.* A link to
   `…/skills/./wapps-secrets/SKILL.md` is "wrong" and rewritten; Rust's `Path`
   equality ignores `/./` and would keep it. Same family: every path is
   `filepath.Join`ed, so `HOME=/x//home/./` produces a clean target.
3. *Install is not atomic across its steps.* The destination directory is
   created BEFORE the source is materialized, so a symlink install that fails
   on `$HOME` (unset, or `~/.config` a file) leaves an empty
   `.claude/skills/wapps-secrets` behind. Kept as the oracle does it; a case
   pins it.
4. *`os.Remove` falls back to `rmdir`*, so an empty directory in the link's
   place is replaced silently, while a non-empty one fails with
   `symlink <old> <new>: file exists`.
5. *`NeedsRefresh` has no non-test caller in Go* (only `AutoRefresh` is used,
   from `root.go`). Nothing was ported for it.

**What the pricing got wrong.**

1. *18–24 cases was low:* 43 landed. Most of the extra cases are the
   filesystem states a skill directory can be in (stale source, dangling,
   uncleaned or wrong link, real file, empty and non-empty directory in the
   slot, a file in place of the destination, a symlinked destination), each a
   separate branch of Go's code with its own on-disk result.
2. *"No new crate" held, but the harness was the real cost:* the probe had to
   learn per-case homes, symlinks and empty directories before a single case
   could be trusted.

**Not measured.** A umask other than the harness's (Go chmods files to 0644
explicitly and Rust does too; directories follow the umask in both). The
`--flag=false` form of the bool flags (pflag accepts it, clap does not — a
cross-cutting gap of every ported bool flag, not opened here). `--dir` with no
value and unknown shorthand flags. Failures of the temp-file write or the
rename (Go's message carries a random temp name, so it cannot be compared).
A failing `RemoveAll` (Rust prints `unlinkat <dest>: <errno>`). A failing
`getwd`. Bare `wapps skill` (help layout, slice 9). The auto-refresh after
other verbs (slice 10).

---

### Dilim 9 — Yardım düzeni: `--version`, `help`, `completion`, bilinmeyen alt komut · **LANDED** (without `completion`)

| | |
|---|---|
| yüzey | kök `--version`; `help` alt komutu; `completion` (4 kabuk); `wapps <bilinmeyen>` davranışı; çıplak `wapps` |
| yeni crate | **§4.2'nin kararı burada veriliyor** (clap_complete / gömülü betik / düşürme) |
| bu dilimin ASIL işi | Bugün ölçülmeyen **50 düğümlük yardım eksenini** gate'e sokmak, ve `EXCLUDED`daki `agent_unknown_subcommand`ı kapatmak |
| differential vakası | Bu eksen pty differential'a değil, **ayrı bir anlık-görüntü (snapshot) karşılaştırmasına** ait: 50 düğüm × `--help` baytları. pty differential'a eklenecek olan yalnızca davranış vakaları: bilinmeyen alt komut (2), çıplak `wapps` (2), `--version` (2) → **~6 vaka + 50 düğümlük snapshot** |
| kapı | `cargo test` yeşil + `helptext.rs` (spec referansı yasağı) hâlâ geçerli |
| ön koşul | `--version` için sürüm enjeksiyonu; o da release train kararına bağlı (§4.3) |

**What landed (measured).** Everything in the row above except `completion`,
which this lane was told to leave for the owner. It stays an OPEN item: not
ported, the Go command untouched. (Main records the owner's later decision in
§4.2 — keep it, generated by `clap_complete`, installed by the Homebrew
formula; that is the next slice's work and needs its crate row.)

| | |
|---|---|
| the layout | New `cobrahelp.rs` renders cobra v1.10.2's default help and usage templates and pflag v1.0.10's `FlagUsagesWrapped(0)` out of the clap tree: Long or Short, `Usage:` with the Use line (or `<path> [command]`), `Available Commands:` sorted and padded to max(longest name, 11), `Flags:` / `Global Flags:` sorted by name and aligned on the longest `-x, --name type` prefix (+1 for pflag's NUL marker), the first back-quoted word of a usage as the value name, the root's flags as the only persistent ones (a local `--project` shadows the global one, short form included). clap still parses; its help and version flags are disabled on every node and it no longer writes a page |
| data on the tree | cobra Short = `about`, Long = `long_about` (22 new `LONG_*` consts copied from the oracle's pages), Use = `override_usage` (18), pflag type = `value_name` (`--share`, `--var`, `--key`, `--verb` are `stringArray`), and a non-zero default is written into the flag's usage text as pflag prints it (`(default "dev")`, `(default true)`, `(default [read])`), because most of those defaults are applied by the verbs' own pflag-style parsing, not by clap. 2 Short texts, 17 flag usages and 5 type words that had drifted from Go (e.g. `policy show`'s "GET /v1/policy — …", the root's `--project` "(see ~/.config/wapps/projects.yaml)", `dr combine`'s "≥", every missing default) now equal Go |
| behaviour | `cobra_preflight` in `main.rs`, in cobra's order and before the root's PersistentPreRunE: (1) cobra's `Find` (ported: `stripFlags`, `argsMinusFirstX`) — a root word that names no command is `unknown command "x" for "wapps"` with cobra's suggestions (Levenshtein ≤ 2 or case-insensitive prefix, `help` excluded); (2) the help flag on any level prints the found command's page; (3) `--version` prints `wapps version <CARGO_PKG_VERSION>`, or is an unknown flag when Find found a subcommand; (4) a family (no Run) prints its page whatever words follow. `help [command]` is a real root subcommand: runnable, so the mutual exclusion does fire for it; an unknown root topic prints ``Unknown help topic [`x`]`` and the root's usage on stderr, exit 0. The eight families' `print_help` arms in the dispatch became `unreachable!` |
| `--version` (§4.3) | `Cargo.toml` 0.0.0 → **0.23.0** (the latest tag). `rust/check-version.sh <version>` compares it with the crate's `version =` line; `.goreleaser.yml` runs it as a `before` hook with `{{ .Version }}`. Chosen over a CI step because the hook sits next to the ldflag that versions the Go binary and runs for any `goreleaser release`, local or CI, before a single build. Measured: `goreleaser build --snapshot` now stops at the hook (`0.23.0-SNAPSHOT-b05ddfe` ≠ `0.23.0`), which is the check firing; snapshot builds are not part of the release workflow (it runs `release --clean` on `v*` tags). `goreleaser check` exits 2 before and after this change for the same pre-existing reason (the deprecated `brews` key) |
| oracle | Both Go oracles of this slice (`differential.rs`, `helpaxis.rs`) are built as the release builds Go: `-X …/cmd.Version=<CARGO_PKG_VERSION>`. The 905 earlier cases stayed EQUAL against that oracle (the update check it would arm is off: `WAPPS_NO_UPDATE_CHECK=1` in every case) |
| help axis | `tests/helpaxis.rs`: walks the ORACLE's tree out of its own pages (no hand-written node list), requires the Rust tree to be the same list, and compares stdout, stderr and exit of `<path> --help`, `<path> -h` and `help <path>` for every node: **49 nodes** (Go's 54 minus `completion` and its 4 shells), **147 pages, 0 differ**. Red before the port: the node lists differed |
| differential cases | **43** (priced ~6): the original `agent_unknown_subcommand` back from `EXCLUDED` plus 42 — bare `wapps` in all four arms and with both identity flags (help, not the exclusion); `--version` (human, agent, both identity flags, before a subcommand, with `--help`); `secrets nosuchverb` in all four arms and with an unknown flag; a root unknown word in four arms, with `--help`, and with a suggestion (human and agent); the help command (a page, bare, three arms, an unknown word past the root, an unknown root topic, both identity flags refused); the help flag against an unknown flag, `deploy`'s ExactArgs, `projects list`'s NoArgs, the mutual exclusion and `tofu`; and four cases of cobra's Find quirk (below). `ARM_WAIVERS` gained `secre` (the suggestion word; its arms are measured on `nosuch`) |
| harness | `diff.py` removes `completion`'s single listing line from the ORACLE's output (asserting it appears at most once) and prints `COMPLETION_LINE_REMOVED=<n>` (10 in the landing run: the root pages among the 43 cases); `differential.rs` shows that line on every run. It is the only normalization this slice adds, and it drops out when `completion` is ported |
| gate | `cargo test --release` (differential `EQUAL=948 DIFFERENT=0 UNSOUND=0` = 905 + 43; the floor raised from 905 to 948), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `go build ./...`, `go test ./...` (no Go file changed) |
| red before green | all 43 cases DIFFERENT against the pre-slice binary (`EQUAL=0 DIFFERENT=43`), 43 EQUAL after. The first green run had 3 left, and all three were cobra behaviour nobody had written down (findings 1 and 2) |
| mutation proofs | each reverted and the file compared with its backup: (a) Find knowing `-h`/`--help`/`--version` as bools → 5 red (the four Find cases + `--version secrets list`); (b) the unknown-topic usage with the help/version flags → 1; (c) no suggestions → 2; (d) the preflight moved after the mutual exclusion and deploy's arity → 4; (e) the unknown topic on stdout → 1; (f) no family page → 11; (g) the flag column without pflag's +1 → helpaxis 147 of 147 pages red; (h) a `(SPEC 9.1)` in a flag usage → `helptext.rs` red on the cobra page |

**Findings.**

1. *cobra's `Find` runs before the help and version flags exist.* They are
   initialized in `execute`, for the found command only, so `Find` treats
   `-h`, `--help` and `--version` like any flag it does not know as a bool:
   they take the next word as a value. Measured on Go: `wapps -h secrets get`
   → `unknown command "get" for "wapps"`; `wapps secrets -h get` → `secrets`'s
   page; `wapps --version whoami` → the version; `wapps -h tofu` → the root's
   page. clap matches all four differently; the port runs cobra's `Find`
   over the argv instead of trusting clap's match.
2. *The help command prints the root's usage without `-h` and `--version`.*
   Same cause: when `help` runs, the root was never executed, so its help and
   version flags were never added. `wapps help nosuch` lists three flags,
   `wapps --help` five.
3. *Bare `wapps`, `--version`, a family page and the help flag all answer
   before PersistentPreRunE,* so `--config x --project p` is NOT refused with
   them; it IS refused for `wapps help`, which is runnable.
4. *The Rust texts had drifted.* 22 Long texts were missing, 2 Short texts
   and 17 flag usages differed from Go (paraphrases, `>=` for `≥`, every
   non-zero default missing) and 5 repeatable flags showed `string` for
   pflag's `stringArray`; no measurement had ever compared them (§6 item 2).

**What the pricing got wrong.** "~6 cases + a 50-node snapshot" — 43 cases
and 147 pages landed, and the snapshot is a live comparison against the
oracle rather than stored bytes (stored bytes would go stale on the next Go
text change; the oracle cannot). The six behaviour cases were the visible
part; cobra's ordering (Find, help, version, family, PersistentPreRunE) has
an arm for each identity flag and a quirk the plan did not know about. The
"no new crate" held. The real cost was porting cobra's Find and pflag's
column rules, not the texts.

**Known divergence, not in the corpus.** An empty word before a command name
(`wapps secrets "" get`, `wapps "" secrets list`): cobra's stripFlags skips
it, so Go runs the command after it with `""` as an argument; clap takes it as
the family's stray word and Rust prints that family's page (exit 0). Found by
hand while closing the dispatch's family arms (they would otherwise have
panicked); porting it means re-ordering the argv for clap, not done.

**Not measured.** `completion` and every path through it (`wapps help
completion`, a suggestion of `completion` for a typo like `comp`): Go answers,
Rust says unknown. `--version` placed after `tofu` (Go passes it to tofu, Rust
calls it an unknown flag). pflag's `--help=false` / `-h=false` forms. The
help flag after a positional of a `trailing_var_arg` verb (`secrets exec foo
-h`: pflag would still parse `-h`, clap hands it to the child). clap's
missing-value message now names the pflag type (`'--share <stringArray>'`);
Go's `flag needs an argument` was not ported for value flags in any slice.
Help pages under a pty (the axis runs on pipes; the pty cases cover three
pages).
 — `updatecheck` + skill auto-refresh (çapraz kesen)

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
| 1 | `dr accept-epoch-reset` · İNDİ | 172 | yok | 22 (gerçek) |
| 2 | `whoami` · İNDİ | 60 | yok | 14 (gerçek) |
| 3 | `login` · LANDED | 634 | none | 30 (actual) |
| 4 | `token exchange` · İNDİ | 70 | yok | 40 (gerçek) |
| 5 | `secrets sync` (no `--target` arm) · LANDED | 582 (≈480 live, see slice 5) | none | 28 (actual) |
| 6 | `coolify` + sync/coolify · LANDED (6a `update-env` + `set-labels`, 6b the rest) | 1438 | none | 209 (actual: 6a 66 + 6b 143) |
| 7 | `deploy` · LANDED | 582 | none | 76 (actual) |
| 8 | `skill` · LANDED | 539 (AutoRefresh is slice 10) | none | 43 (actual) |
| 9 | yardım düzeni · LANDED without `completion` | (cobra) | none (`completion`: §4.2) | 43 (actual) + 147 help pages |
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
   *Measured since, in slice 9:* every page of 49 nodes in three forms
   (`tests/helpaxis.rs`), byte for byte against the oracle.

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
