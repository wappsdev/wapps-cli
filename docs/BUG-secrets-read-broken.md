# BUG: `wapps secrets get/exec/env` arşivdeki secret'ı veremiyor

**Durum:** ✅ ÇÖZÜLDÜ (#1 gerçek bug, düzeltildi) + #2 yanlış teşhisti (prefix meselesi). Bkz. aşağıdaki "Çözüm" bölümü.

---

## Çözüm (sonraki session)

### #1 — `get` array-değerli anahtarda çöküyordu → DÜZELTİLDİ

`readKey` (cmd/secrets/get.go) arşivin TAMAMINI `map[string]struct{Value string}`'e
unmarshal ediyordu; arşivde array değerli bir anahtar (`vaulter_traefik_cert_paths`)
olunca, istenen string anahtara ulaşmadan patlıyordu. Fix: değerleri
`map[string]json.RawMessage` olarak oku, sadece istenen anahtarı `unwrapArchiveValue`
ile çöz (string → verbatim, array/map → compact JSON). Artık `get` herhangi bir
arşiv tipinde çalışıyor. Regression testleri: `TestGet_StringKeyWithArrayKeyPresent`,
`TestGet_ArrayKeyReturnsCompactJSON`.

### #2 — `exec`/`env` ad-hoc anahtarları "düşürüyor" → YANLIŞ TEŞHİS

Doc "exec/env kaynaklardan yeniden derliyor" diyordu; **yanlış**. `exec`/`env`
arşivi DOĞRUDAN okuyor (`resolveArchivePath` → decrypt → `buildExecEnv`), import-env'li
anahtarlar dahil HEPSİNİ enjekte ediyor. `printenv LUMIRA_REVENUECAT_WEBHOOK_SECRET`
boş çünkü `exec`/`env` default prefix'i `TF_VAR_` — gerçek değişken
`TF_VAR_LUMIRA_REVENUECAT_WEBHOOK_SECRET`. Doğru kullanım:
```
wapps secrets exec --project vaulter --prefix '' -- printenv LUMIRA_REVENUECAT_WEBHOOK_SECRET
```
Anahtar düşmüyor, sadece prefix'li. Kanıt testi: `TestExec_IncludesImportEnvKeyWithPrefix`
(hem prefix'li hem `--prefix ''` halini doğruluyor). Kalıcılık için vaulter
`.wapps.yaml`'a bir `.env.shared` file kaynağı eklemek hâlâ önerilir (ayrı, operasyonel iş).

---

## (Orijinal sorun açıklaması — referans için)

**Durum:** problem tespit edildi, **çözüm sonraki session'da.** Bu doküman sadece sorunu anlatır.

## Belirti

vaulter arşivinde bir secret `wapps secrets list` ile **görünüyor** ama okuma komutlarının hiçbiri değeri vermiyor:

```
$ export WAPPS_SECRETS_PASSPHRASE="$(security find-generic-password -w -s 'Wapps Master')"
$ wapps secrets list  --project vaulter | grep REVENUECAT
LUMIRA_REVENUECAT_WEBHOOK_SECRET      # ← arşivde VAR
LUMIRA_REVENUECAT_API_KEY

$ wapps secrets get   LUMIRA_REVENUECAT_WEBHOOK_SECRET --project vaulter
Error: secrets.get: unmarshal: json: cannot unmarshal array into Go struct field .value of type string

$ wapps secrets exec  --project vaulter -- printenv LUMIRA_REVENUECAT_WEBHOOK_SECRET
# (boş — hiçbir şey basmıyor)
```

Yani `import-env` / `set` ile eklenen secret'lar **kör noktada**: listede var, okunamıyor. Sonuç olarak şu an pratikte tek güvenilir okuma kaynağı operasyonel hedef (prod DB / Coolify env) oluyor.

## İki ayrı kök neden

**1) `get` array-değerli bir anahtarda çöküyor.**
Arşivde değeri **array** olan bir anahtar var (`vaulter_traefik_cert_paths`). `get` arşivin tamamını `.value` = `string` varsayan bir struct'a unmarshal etmeye çalışıyor; array görünce istenen anahtara ulaşmadan patlıyor. Aynı kök neden `secrets env`'i de eskiden çökertiyordu (bilinen).
→ *Fix yönü:* değer tipini esnek karşıla (string | array | any), ya da unmarshal'ı **sadece istenen anahtara** kapsa.

**2) `exec`/`env` ad-hoc anahtarları düşürüyor.**
vaulter `.wapps.yaml`'ın tek kaynağı `tofu` (TF_VAR_ prefix). `exec`/`env` env'i **kaynaklardan yeniden derliyor**, bu yüzden `import-env` ile eklenen (tofu var'ı OLMAYAN) anahtarlar — örn. `LUMIRA_REVENUECAT_WEBHOOK_SECRET` — sonuçta yok oluyor. (`list` direkt arşivi okuduğu için onları görüyor; uyumsuzluk burada.)
→ *Fix yönü:* ya `.wapps.yaml`'a bir `.env.shared` dosya kaynağı ekleyip ad-hoc anahtarları kalıcılaştır, ya da `exec`/`env`'i committed arşivi **doğrudan oku** (kaynaklardan yeniden derleme yerine), ya da en azından arşivde olup kaynakta olmayan anahtarları koru + uyar.

## Repro
```
export WAPPS_SECRETS_PASSPHRASE="$(security find-generic-password -w -s 'Wapps Master')"
wapps secrets get LUMIRA_REVENUECAT_WEBHOOK_SECRET --project vaulter   # → crash (#1)
wapps secrets exec --project vaulter -- printenv LUMIRA_REVENUECAT_WEBHOOK_SECRET   # → boş (#2)
```

## Geçici workaround
Operasyonel kaynaktan oku (ör. payments per-app config DB satırı / Coolify env). wapps okuma yolu düzelene kadar `import-env`'li secret'lar için bunu kullan.
