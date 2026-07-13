package secrets

// store_backend.go, `.wapps.yaml` `backend:` anahtarı `store` olduğunda secrets
// verb'lerini (exec/apply/get/env/set/sync) secrets-gate Worker istemcisine
// (internal/store) yönlendirir. `backend` yoksa veya `legacy-git` ise (DEFAULT)
// verb'ler eski age-arşiv yolunda kalır (byte-for-byte değişmez).
//
// SERVER-DECRYPT v2 (SPEC §2.7/§7.4): Worker PLAINTEXT döner — istemcide yerel
// KEK/unwrap/kimlik YOKTUR. CLI yalnızca çeker + enjekte eder (exec/apply child
// env'ine / 0600 hedef dosyalara; agent-mode gate + scrubber sözleşmesi AYNEN).
// Kimlik = CF Access oturumu (`wapps login`, §7.2) veya CI service token env'i;
// geçersiz/dolmuş oturum SESSION_EXPIRED ile istek ağ'a çıkmadan yüzeye çıkar.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// storeBackendConfig, geçerli .wapps.yaml `backend: store` ise cfg'i döner; aksi
// halde (backend yok / legacy-git / config yok / bozuk-legacy) (nil, nil). Yalnızca
// bir PARSE hatası yayılır (loudly fail-closed). Her verb bunu ilk adım olarak
// çağırır: nil → legacy yol; non-nil → store yol.
func storeBackendConfig() (*config.WappsYAML, error) {
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil {
		return nil, err
	}
	if cfg == nil || !cfg.IsStoreBackend() {
		return nil, nil
	}
	return cfg, nil
}

// openStore, backend:store verb'lerinin okuma/yazma için kullandığı internal/store
// istemcisini kurar. PAKET-DÜZEYİ SEAM (üretimde openWorkerStore; testte çağrıları
// gözleyen bir fake ile değiştirilir).
var openStore = openWorkerStore

// openWorkerStore, gerçek üretim istemcisini kurar (SPEC §7.4):
//   - BaseURL = WAPPS_SECRETS_GATE (yoksa OD-4 varsayılanı gw.meapps.dev);
//   - Doer = session.HTTPClient() → WAPPS_MTLS_CERT/KEY doluysa client-cert'li
//     taşıma (P1.9 CI mTLS); yanlış-konfig SERVICE_MISCONFIGURED (fail-closed);
//   - Auth = session.Auth() → CI service-token env'i veya `wapps login` oturumu;
//     geçerli kimlik yoksa SESSION_EXPIRED (istek ağ'a çıkmadan).
func openWorkerStore(cfg *config.WappsYAML) (store.Store, error) {
	doer, err := session.HTTPClient()
	if err != nil {
		return nil, err
	}
	return store.New(store.Config{
		BaseURL: session.GateURL(),
		Doer:    doer,
		Auth:    session.Auth(),
	}), nil
}

// storeValues, backend:store'da verilen anahtarları (boşsa principal'ın
// OKUNABİLİR tüm kümesi) Worker'dan PLAINTEXT çeker (SPEC §7.4 read: bulk POST
// /read; all-or-nothing). Değerler yalnızca süreç belleğinde yaşar.
func storeValues(ctx context.Context, cfg *config.WappsYAML, keys []string) (map[string]string, error) {
	st, err := openStore(cfg)
	if err != nil {
		return nil, err
	}
	res, err := st.Read(ctx, cfg.Project, keys)
	if err != nil {
		return nil, err
	}
	return res.Values, nil
}

// storeCommit, backend:store'da bir dizi anahtarı TEK atomik epoch'ta yazar
// (POST /import; writer DO serileştirir, §7.6). opts, bilgilendirici audit
// etiketlerini taşır (sync → key.sync, §6.4).
func storeCommit(ctx context.Context, cfg *config.WappsYAML, sets map[string]string, opts store.WriteOpts) error {
	if len(sets) == 0 {
		return clierr.New(clierr.Internal, "store commit: no changes")
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	return st.Import(ctx, cfg.Project, sets, opts)
}

// valuesToArchiveMap, düz metin değer haritasını tofu-output-şekilli arşiv zarf
// haritasına ({"KEY":{"value":"..."}}) çevirir. decryptArchive'in döndürdüğü tiple
// birebir aynıdır; böylece store yolu, arşiv-tüketen makineyi (ör. Coolify sync'in
// prefix-match/diff/push hattı) DEĞİŞTİRMEDEN besleyebilir (P1.6).
func valuesToArchiveMap(values map[string]string) (map[string]json.RawMessage, error) {
	envelopes := make(map[string]json.RawMessage, len(values))
	for k, v := range values {
		b, err := json.Marshal(map[string]string{"value": v})
		if err != nil {
			return nil, fmt.Errorf("store: envelope %s: %w", k, err)
		}
		envelopes[k] = b
	}
	return envelopes, nil
}

// valuesToArchiveJSON, düz metin değer haritasını tofu-output-şekilli arşiv JSON'una
// ({"KEY":{"value":"..."}}) çevirir; böylece store yolu, mevcut (legacy ile paylaşılan)
// env/target yazıcılarını (execEnvAndValues, writeTofuOutputsAsEnv, applyTargets)
// yeniden kullanır — çıktı biçimi iki backend'de birebir aynı kalır.
func valuesToArchiveJSON(values map[string]string) ([]byte, error) {
	envelopes, err := valuesToArchiveMap(values)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelopes)
}

// mergedToSets, kaynaklardan (sources) okunmuş {"value":...} zarflarını store
// Import için düz metin harita'ya çevirir (sync store yolu).
func mergedToSets(merged map[string]json.RawMessage) (map[string]string, error) {
	sets := make(map[string]string, len(merged))
	for k, raw := range merged {
		var env struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("store: source key %s malformed: %w", k, err)
		}
		sets[k] = rawValueToString(env.Value)
	}
	return sets, nil
}

// --- verb store yolları -----------------------------------------------------

// runExecStore, exec'in backend:store yoludur: store'dan değerleri çeker ve
// alt-süreci — legacy ile AYNI scrubber sözleşmesiyle (§7.4.3) — enjekte
// edilmiş env ile çalıştırır. intentName yalnızca doğrulanır (v2'de deploy'un
// ayrı bir tazelik yolu yoktur — her okuma taze, sunucudan).
func runExecStore(args []string, prefix, intentName string, cfg *config.WappsYAML, out, errW io.Writer, runner execRunner) error {
	if _, err := intent.Parse(intentName); err != nil {
		return err
	}
	values, err := storeValues(context.Background(), cfg, nil)
	if err != nil {
		return err
	}
	archiveJSON, err := valuesToArchiveJSON(values)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	injected, scrub, err := execEnvAndValues(archiveJSON, prefix)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	// Ortak inject→scrub→run→flush→exit bloğu (P1.1) — legacy exec ile AYNI
	// scrubber sözleşmesi ve exit-code yansıtması.
	return runWithInjectedEnv(args, injected, scrub, out, errW, runner)
}

// runApplyStore, apply'ın backend:store yoludur: store'dan değerleri çeker ve
// bildirilen consumption target'larını (legacy ile aynı idempotent yazıcı) yazar.
func runApplyStore(cfg *config.WappsYAML, stdoutW io.Writer) error {
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("apply: no targets declared in %s — add a 'targets:' block or use 'wapps secrets env --write <file>' for one-off writes", wappsYAMLPath)
	}
	values, err := storeValues(context.Background(), cfg, nil)
	if err != nil {
		return err
	}
	archiveJSON, err := valuesToArchiveJSON(values)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	return applyTargets(cfg, archiveJSON, stdoutW)
}

// runListStore, list'in backend:store yoludur: anahtar ADLARINI metadata
// düzleminden çeker (GET /keys, SPEC §7.4 — Store.Read ÇAĞRILMAZ, audit'e
// value.read düşmez; liste Worker'da principal'ın read grant'ına filtrelenir
// §4.3.3). Çıktı legacy list ile birebir aynı: satır başına bir ad, sıralı.
func runListStore(cfg *config.WappsYAML, w io.Writer) error {
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	res, err := st.Keys(context.Background(), cfg.Project)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(res.Keys))
	for _, k := range res.Keys {
		names = append(names, k.KeyName)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintln(w, n)
	}
	return nil
}

// getStore, get'in backend:store yoludur: yalnızca istenen anahtarı çeker
// (blast-radius min) ve düz metin değeri döner (RunE agent-modu red'i AYNI kalır).
func getStore(cfg *config.WappsYAML, key string) (string, error) {
	values, err := storeValues(context.Background(), cfg, []string{key})
	if err != nil {
		return "", err
	}
	v, ok := values[key]
	if !ok {
		return "", clierr.Newf(clierr.NotFound, "key %q not returned by the store", key)
	}
	return v, nil
}

// runEnvStore, env'in backend:store yoludur: store'dan değerleri çeker ve export
// satırlarını stdout'a (veya --write dosyasına, AI-safe) yazar.
func runEnvStore(cfg *config.WappsYAML, writePath, prefix string, stdoutW io.Writer) error {
	values, err := storeValues(context.Background(), cfg, nil)
	if err != nil {
		return err
	}
	archiveJSON, err := valuesToArchiveJSON(values)
	if err != nil {
		return fmt.Errorf("env: %w", err)
	}
	if writePath == "" {
		return writeTofuOutputsAsEnv(archiveJSON, prefix, stdoutW)
	}
	return writeEnvFileAtomic(writePath, archiveJSON, prefix)
}

// runSetStore, set'in backend:store yoludur: değeri (legacy ile aynı --from-file /
// no-echo prompt kuralıyla) yakalar ve tek-anahtar PUT ile yazar (git drift
// preflight'ı YOK — store yazımları CAS'ı sunucuda çözer, git değil).
func runSetStore(key string, cfg *config.WappsYAML, opts setOptions) error {
	value, err := captureSetValue(key, opts)
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	if err := st.Set(context.Background(), cfg.Project, key, value, store.WriteOpts{}); err != nil {
		return err
	}
	fmt.Printf("✓ Set %s (store: %s)\n", key, cfg.Project)
	return nil
}

// runSyncStore, sync'in backend:store yoludur: kaynakları (sources) okur+merge eder
// ve tüm anahtarları TEK bir atomik import'ta store'a yazar. X-Wapps-Intent: sync
// etiketi audit satırlarını key.sync yapar (§6.4 — rotate-plan oracle'ı için).
func runSyncStore(ctx context.Context, cfg *config.WappsYAML, lookup func(string) string) error {
	if hasTofuSource(cfg.Sources) {
		if err := preflightTofuEnv(lookup); err != nil {
			return err
		}
	}
	merged, err := readAndMerge(ctx, cfg.ResolvedSources())
	if err != nil {
		return err
	}
	sets, err := mergedToSets(merged)
	if err != nil {
		return err
	}
	if len(sets) == 0 {
		return fmt.Errorf("secrets.sync: no source keys to commit to the store")
	}
	if err := storeCommit(ctx, cfg, sets, store.WriteOpts{Sync: true}); err != nil {
		return err
	}
	fmt.Printf("✓ Committed %d keys to the store for %s\n", len(sets), cfg.Project)
	return nil
}

// captureSetValue, set değer-yakalamasını uygular (--from-file veya no-echo prompt),
// legacy runSet ile AYNI kuralları izler: boş değer reddedilir; non-TTY uyarısı basılır.
// Store ve (potansiyel) legacy set'in paylaştığı asgari yakalama; legacy runSet kendi
// inline kopyasını byte-for-byte korur.
func captureSetValue(key string, opts setOptions) (string, error) {
	var value string
	tty := true
	if opts.fromFile != "" {
		raw, rerr := os.ReadFile(opts.fromFile)
		if rerr != nil {
			return "", fmt.Errorf("secrets.set: read --from-file: %w", rerr)
		}
		value = trimTrailingNewline(string(raw))
	} else {
		v, isTTY, perr := opts.promptValue(fmt.Sprintf("Value for %s: ", key))
		if perr != nil {
			return "", fmt.Errorf("secrets.set: read value: %w", perr)
		}
		value, tty = v, isTTY
	}
	if value == "" {
		return "", fmt.Errorf("secrets.set: empty value rejected (use a placeholder if you need to declare an empty var)")
	}
	if !tty {
		fmt.Fprintln(os.Stderr, "⚠ stdin is not a TTY — value may have been recorded in shell history")
	}
	return value, nil
}

// trimTrailingNewline, sondaki \r\n dizisini soyar (printf %s ... > file kalıbıyla uyum).
func trimTrailingNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
