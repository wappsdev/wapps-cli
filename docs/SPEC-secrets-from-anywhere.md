# Spec: wapps secrets — her yerden erişim (config-dir-relative + --project)

Status: ✅ IMPLEMENTED (2026-06-03). Fix 1 (config-dir-relative) + Fix 2 (--project registry) + Fix 3 (git preflight configRoot). Tüm 7 kabul kriteri test + canlı smoke ile doğrulandı. Üç implementasyon kararı: tofu `workdir` da resolve edilir; `apply` target'ları configRoot altına yazar; `diff` git-ref + `verify` tofu-output --config kapsamı dışında bırakıldı (archive-read tarafları config-aware). Bkz. `docs/architecture.md` §3 ("Running from any cwd").
Tarih: 2026-06-03
Scope: `wapps secrets` alt-komutlarının proje dizinine `cd` etmeden, herhangi bir cwd'den çalışması.

## Problem (test edilmiş)

Bugün `wapps secrets get/list/exec/env/diff/apply` ancak projenin kök dizininden (`.wapps.yaml`'ın yanından) çalışıyor. Arşiv yolu (`Config.Dest`, varsayılan `secrets/all.enc.age`) **cwd'ye göreli** açılıyor. `--config` flag'i sadece hangi yaml'ın okunacağını belirliyor ama arşiv tabanını taşımıyor.

Kanıt (workspace kökünden, projeye cd etmeden):
```
$ wapps secrets get coolify_uuid_vaulter_app \
    --config /abs/infra-tofu/projects/vaulter/.wapps.yaml --no-sync
Error: secrets.get: read archive: open secrets/all.enc.age: no such file or directory
```
`secrets/all.enc.age` cwd'ye göre çözülüyor → bulunamıyor.

Sonuç: token/key'lere erişmek için her seferinde `cd infra-tofu/projects/<vaulter|vibe-pro|lab>` gerekiyor. "Kaybolmuş gibi" hissinin sebebi bu (aslında 3 arşivde her şey duruyor, age-şifreli + git-commit'li).

## Hedef (istenen UX)

Herhangi bir dizinden:
```bash
# (A) config path vererek
wapps secrets get coolify_token --config /abs/.../vaulter/.wapps.yaml
wapps secrets list --config /abs/.../vaulter/.wapps.yaml

# (B) kayıtlı proje adıyla (daha temiz)
wapps secrets get coolify_token --project vaulter
wapps secrets list --project vaulter
wapps secrets exec --project vaulter -- terraform plan
```
Hem (A) hem (B) cwd'den bağımsız çalışmalı. Mevcut "proje dizinindeyken parametresiz" davranış AYNEN korunmalı (geriye dönük uyumluluk).

## Tasarım

### Fix 1 — Arşiv + dosya yollarını config dizinine göre çöz (ÇEKİRDEK, en yüksek değer)

`.wapps.yaml` içindeki tüm RELATIVE yollar (`dest`, `targets[].path`, `sources[].path`) **cwd'ye değil, `.wapps.yaml`'ın bulunduğu dizine (configRoot) göre** çözülmeli.

- `configRoot = filepath.Dir(<yüklenen .wapps.yaml mutlak yolu>)`.
- `--config` verilmişse: `configRoot = filepath.Dir(cfgFile)`. Verilmemişse: `configRoot = cwd` (mevcut davranış).
- Çözüm kuralı: yol mutlaksa olduğu gibi; relative ise `filepath.Join(configRoot, p)`.

Dokunulacak yerler (gerçek kod, grep'lenmiş):
- `cmd/root.go:100` — `--config` → `cfgFile` (zaten var). Persistent flag.
- `cmd/secrets/*.go` — arşiv okuma noktaları cwd-relative:
  - `env.go:57`, `list.go:28`, `exec.go:63`, `diff.go:54` → `os.ReadFile(archivePath)`
  - `apply.go:44/46` → `os.ReadFile(cfg.Dest)`
  - `sync.go:123` → `ageutil.EncryptWriteAtomic(cfg.Dest, ...)`
- `cmd/secrets/env.go:108-110` — `archivePath()` helper: `cfg.Dest` (veya default `secrets/all.enc.age`) döndürüyor; burada configRoot'a göre `filepath.Join` uygulanmalı.
- `internal/config/wapps_yaml.go` — `Config{Dest, Targets[].Path, Sources[].Path}`. `config.Load(path)` (sync.go:149, apply.go:36) dosyayı okuyor → **`Load` yüklediği path'i biliyor**; en temiz çözüm: `config.Load` çözülmüş `ConfigRoot string` alanını Config'e yazsın, ya da bir `ResolvePath(configRoot, rel) string` helper'ı eklenip tüm tüketim noktaları onu kullansın.

Önerilen minimal yaklaşım: `config` paketine
```go
func (c *Config) ResolveDest(configRoot string) string   // mutlak değilse Join
func (c *Config) ResolveTargetPath(configRoot string, t Target) string
```
helper'ları ekle; `cmd/secrets/*` her `os.ReadFile`/`EncryptWriteAtomic` öncesi bunları çağırsın. `archivePath()` helper'ı `configRoot` parametresi alacak şekilde güncellensin.

`configRoot` tek noktada hesaplanmalı (örn. root persistent pre-run veya bir `resolveConfigRoot(cfgFile) string` util): `cfgFile != "" ? filepath.Dir(cfgFile) : "."`.

### Fix 2 — Global proje kaydı + `--project` flag (UX, opsiyonel ama istenen)

`~/.config/wapps/projects.yaml`:
```yaml
projects:
  vaulter:   /Users/adnankurt/Documents/Projects/infra-tofu/projects/vaulter
  vibe-pro:  /Users/adnankurt/Documents/Projects/infra-tofu/projects/vibe-pro
  lab:       /Users/adnankurt/Documents/Projects/infra-tofu/projects/lab
```
- Yeni persistent flag: `--project <name>` (kısa: `-p`). Verilince registry'den `<dir>` çözülür → `cfgFile = <dir>/.wapps.yaml`, `configRoot = <dir>` (Fix 1'i besler).
- `--config` ve `--project` aynı anda verilirse hata (mutually exclusive).
- Registry yoksa/proje yoksa anlamlı hata: `unknown project "x" (add to ~/.config/wapps/projects.yaml or use --config)`.
- (Nice-to-have) `wapps projects add <name> <dir>` / `wapps projects list` komutları registry'yi yönetsin. İlk sürümde dosyayı elle yazmak yeterli.

### Fix 3 — `--no-sync` repo-dışı cwd'de sağlam

`cmd/root.go` git auto-sync preflight (`--no-sync` ile atlanıyor, satır 98). configRoot bir git repo'su iken cwd değilse: git işlemleri **configRoot üzerinden** çalışmalı (cwd üzerinden değil), ya da `--no-sync`/`--project` ile preflight güvenle atlanabilmeli. En azından: `--config`/`--project` verildiğinde git preflight cwd yerine configRoot'u kullansın.

## Kabul kriterleri

Aşağıdakiler **herhangi bir cwd'den** (örn. `/tmp`) geçmeli:
1. `wapps secrets list --config <abs>/vaulter/.wapps.yaml` → isim listesi döner (boş değil).
2. `wapps secrets get coolify_uuid_vaulter_app --config <abs>/vaulter/.wapps.yaml` → değer döner.
3. `wapps secrets get coolify_uuid_vaulter_app --project vaulter` → aynı değer.
4. `wapps secrets exec --project vaulter -- printenv coolify_uuid_vaulter_app` → değer (exec env enjeksiyonu).
5. Proje dizinindeyken parametresiz `wapps secrets list` → AYNEN çalışır (regresyon yok).
6. `--config` + `--project` birlikte → hata.
7. Mutlak `dest` içeren bir `.wapps.yaml` → davranış değişmez (Join sadece relative'e uygulanır).

Testler: `cmd/secrets/*_test.go` ve `internal/config/wapps_yaml_test.go` paternini izle. Yeni test: geçici dizin yapısı (configRoot ≠ cwd) kurup `t.Chdir(tmpOther)` ile başka cwd'den `--config`/`--project` üzerinden okuma. `WAPPS_SECRETS_PASSPHRASE` test fixture'ı zaten var (sync_test.go).

## Geriye dönük uyumluluk
- Parametresiz, proje-dizininde kullanım birebir korunur (configRoot = cwd).
- Mutlak yollar etkilenmez.
- `projects.yaml` yoksa `--project` dışındaki her şey eskisi gibi.

## Kapsam dışı
- Secret VALUE'larını log'a basmak (asla). `get` zaten stdout'a tek değer basıyor; `--project` bunu değiştirmez.
- Master passphrase yönetimi (Keychain "Wapps Master" + `.zshrc` auto-load mevcut; non-login shell'de `export WAPPS_SECRETS_PASSPHRASE="$(security find-generic-password -s 'Wapps Master' -w)"`).
- Yeni şifreleme/age değişikliği yok.

## İlgili
- 3 arşiv: `infra-tofu/projects/{vaulter,vibe-pro,lab}/.wapps.yaml` → `secrets/all.enc.age`.
- AYRI bir gap (bu spec'in dışında ama ilgili): **Coolify API `coolify_token` hiçbir arşivde yok** (sadece UUID'ler). Taze token üretilip `wapps secrets set coolify_token` ile vaulter arşivine eklenmeli — hem kalıcı olur hem renders prod fix'ini açar. `LUMIRA_REVENUECAT_API_KEY` arşivde var ama boş/placeholder.
- Ara çözüm (implementasyona kadar): `~/.zshrc` → `wsget(){ (cd ~/Documents/Projects/infra-tofu/projects/"$1" && wapps secrets get "$2"); }`
