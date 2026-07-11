package secrets

// store_backend.go, `.wapps.yaml` `backend:` anahtarı `store` olduğunda secrets
// verb'lerini (exec/apply/get/env/set/sync) never-trust-Worker STORE'una
// (internal/store) yönlendirir. `backend` yoksa veya `legacy-git` ise (DEFAULT)
// verb'ler eski age-arşiv yolunda kalır (byte-for-byte değişmez) — yönlendirme
// kararı her verb'ün başında storeBackendConfig() ile verilir.
//
// YAZILIM (CI/test) yolu artık uçtan uca round-trippable: `wapps secrets enroll`
// yerel bir 0600 kimlik deposu (~/.config/wapps/identity.json) yazar; localDecrypt
// Identity/localSigningKey bunu yükler ve store snapshot'ı YEREL X25519 kimlikle
// çözülür (§7.1: CLI çözer, Worker DEĞİL). Oturum bearer'ı out-of-band da sağlanabilir
// (WAPPS_SESSION_TOKEN veya session.json) — böylece bir test/CI, canlı tarayıcı
// login'i OLMADAN gate'e bearer sunabilir. GERÇEK interaktif `wapps login` (cloudflared)
// canlı CF Access hesabı gerektiren TEK insan adımıdır ve bir stub olarak kalır.
//
// Kimlik/oturum GERÇEKTEN yoksa store yolu NET, EYLEMLİ bir clierr yüzeye çıkarır
// (oturum yoksa AUTH_EXPIRED → "run wapps login"; yerel kimlik yoksa IDENTITY_MISSING
// → "run wapps secrets enroll"). DONANIM (SE/YubiKey) yolu arayüzlü kalır (kapsam dışı).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/store"
	"github.com/wappsdev/wapps-cli/internal/witness"
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
// gözleyen bir fake ile değiştirilir). intent parametresi, deploy'da HTTPWitness'in
// wire'lanıp lanmayacağını belirler (dev'de tanık ilgisizdir).
var openStore = openWorkerStore

// openWorkerStore, gerçek üretim istemcisini kurar (SPEC §7.3):
//   - BaseURL = WAPPS_SECRETS_GATE (secrets-gate Worker kökü);
//   - Auth = sessionAuth → geçerli oturum yoksa AUTH_EXPIRED (istek ağ'a çıkmadan);
//   - Witness = deploy intent + WITNESS_ORIGIN varsa gerçek HTTPWitness (fresh-or-fail
//     escrow-tanık çapraz kontrolü, §7.3.4/§9.3); origin yoksa nil → store deploy'da
//     WITNESS_NOT_WIRED döner (ama oturum yoksa AUTH_EXPIRED önce ateşlenir).
//
// Yerel çözme/imzalama kimliği enroll'ün yazdığı 0600 kimlik deposundan yüklenir
// (localDecryptIdentity/localSigningKey); kimlik yoksa okuma IDENTITY_MISSING, yazma
// da IDENTITY_MISSING ile yüzeye çıkar.
func openWorkerStore(cfg *config.WappsYAML, in intent.Intent) (store.Store, error) {
	var wit intent.Witness
	if in == intent.Deploy {
		if origin := os.Getenv("WITNESS_ORIGIN"); origin != "" {
			wit = witness.NewHTTPWitness(origin, cfg.Project)
		}
	}
	return store.New(store.Config{
		BaseURL: os.Getenv("WAPPS_SECRETS_GATE"),
		Auth:    sessionAuth,
		Witness: wit,
		Now:     time.Now,
	}), nil
}

// sessionAuth, her Worker isteğine oturum kimliğini (bearer) iliştirir (SPEC §6/§7.2).
// Geçerli bir oturum yoksa AUTH_EXPIRED — do() bu hatayı yayar ve istek ağ'a HİÇ
// çıkmaz (temiz, eylemli mesaj). Oturum, GERÇEK `wapps login` (cloudflared) dosyasından
// VEYA out-of-band (WAPPS_SESSION_TOKEN / session.json{token}) yüklenir — böylece
// CI/test canlı tarayıcı login'i olmadan bir bearer sunabilir (loadSession, status.go).
func sessionAuth(req *http.Request) error {
	s, ok := loadSession()
	if !ok || s.expired(time.Now().Unix()) {
		return clierr.New(clierr.AuthExpired, "no valid CF Access session for the secrets gate")
	}
	// Varsa bearer'ı sun (gate doğrular); token'sız (yalnızca expires_at) oturumlar
	// header eklemez — gerçek gate CF Access JWT'sini kenar katmanından zaten görür.
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	return nil
}

// localDecryptIdentity, yerel enrolled X25519 çözme kimliğini kimlik deposundan
// yükler (SPEC §7.1: CLI çözer). Kimlik GERÇEKTEN yoksa (nil, nil) — çağıran bunu
// eylemli IDENTITY_MISSING'e çevirir; bozuk/gevşek-izinli dosya net bir clierr döner.
func localDecryptIdentity() (*cryptoid.X25519Identity, error) {
	pid, err := loadPersistedIdentity()
	if err != nil {
		return nil, err
	}
	if pid == nil {
		return nil, nil
	}
	id, perr := cryptoid.ParseX25519Identity(pid.EncSecret)
	if perr != nil {
		return nil, clierr.Wrapf(clierr.IdentityMissing, perr, "identity file encryption key is malformed")
	}
	return id, nil
}

// localSigningKey, yerel enrolled writer (daily/automation) imzalama anahtarını
// kimlik deposundan yükler (store commit imzası). Yoksa (nil, nil); bozuksa clierr.
func localSigningKey() (cryptoid.SigningKey, error) {
	pid, err := loadPersistedIdentity()
	if err != nil {
		return nil, err
	}
	if pid == nil {
		return nil, nil
	}
	sk, serr := pid.Writer.toSigningKey()
	if serr != nil {
		return nil, clierr.Wrapf(clierr.IdentityMissing, serr, "identity file writer key is malformed")
	}
	return sk, nil
}

// storeValues, backend:store'da verilen anahtarları (boşsa identity'nin granted
// tüm kümesi) çeker + yerel kimlikle çözer. WorkerStore.Fetch okur (çevrimiçi-first
// conditional GET + ciphertext cache; deploy'da fresh-or-fail liveness receipt +
// tanık çapraz kontrolü), SONRA snapshot yerel X25519 kimlikle çözülür. Oturum yoksa
// Fetch AUTH_EXPIRED; yerel kimlik yoksa IDENTITY_MISSING (doğru koşum-zamanı yüzeyi).
func storeValues(ctx context.Context, cfg *config.WappsYAML, in intent.Intent, keys []string) (map[string][]byte, error) {
	st, err := openStore(cfg, in)
	if err != nil {
		return nil, err
	}
	snap, err := st.Fetch(ctx, cfg.Project, store.FetchOpts{Intent: in, Keys: keys})
	if err != nil {
		return nil, err
	}
	id, err := localDecryptIdentity()
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, clierr.New(clierr.IdentityMissing,
			"no local decryption identity; the fetched store snapshot cannot be decrypted")
	}
	return snap.DecryptAll(id, keys)
}

// storeCommit, backend:store'da bir dizi anahtarı epoch+1 CAS ile yazar
// (WorkerStore.Commit; çevrimdışıysa fail-closed, 412'de auto-rebase). Yerel
// imzalama anahtarı yoksa (Writer=nil) store.Commit IDENTITY_MISSING döner.
func storeCommit(ctx context.Context, cfg *config.WappsYAML, in intent.Intent, sets map[string][]byte) error {
	if len(sets) == 0 {
		return clierr.New(clierr.Internal, "store commit: no changes")
	}
	writer, err := localSigningKey()
	if err != nil {
		return err
	}
	if writer == nil {
		return clierr.New(clierr.IdentityMissing,
			"no local signing identity; the store commit cannot be signed")
	}
	st, err := openStore(cfg, in)
	if err != nil {
		return err
	}
	_, err = st.Commit(ctx, cfg.Project, store.ManifestDelta{
		Sets:   sets,
		Writer: writer,
		Intent: in,
	})
	return err
}

// valuesToArchiveJSON, düz metin değer haritasını tofu-output-şekilli arşiv JSON'una
// ({"KEY":{"value":"..."}}) çevirir; böylece store yolu, mevcut (legacy ile paylaşılan)
// env/target yazıcılarını (execEnvAndValues, writeTofuOutputsAsEnv, applyTargets)
// yeniden kullanır — çıktı biçimi iki backend'de birebir aynı kalır.
func valuesToArchiveJSON(values map[string][]byte) ([]byte, error) {
	envelopes := make(map[string]json.RawMessage, len(values))
	for k, v := range values {
		b, err := json.Marshal(map[string]string{"value": string(v)})
		if err != nil {
			return nil, fmt.Errorf("store: envelope %s: %w", k, err)
		}
		envelopes[k] = b
	}
	return json.Marshal(envelopes)
}

// mergedToSets, kaynaklardan (sources) okunmuş {"value":...} zarflarını store
// Commit için düz metin bayt haritasına çevirir (sync store yolu).
func mergedToSets(merged map[string]json.RawMessage) (map[string][]byte, error) {
	sets := make(map[string][]byte, len(merged))
	for k, raw := range merged {
		var env struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("store: source key %s malformed: %w", k, err)
		}
		sets[k] = []byte(rawValueToString(env.Value))
	}
	return sets, nil
}

// --- verb store yolları -----------------------------------------------------

// runExecStore, exec'in backend:store yoludur: store'dan değerleri çeker
// (deploy'da fresh-or-fail) ve alt-süreci — legacy ile AYNI scrubber sözleşmesiyle
// (§7.4.3) — enjekte edilmiş env ile çalıştırır.
func runExecStore(args []string, prefix, intentName string, cfg *config.WappsYAML, out, errW io.Writer, runner execRunner) error {
	in, err := intent.Parse(intentName)
	if err != nil {
		return err
	}
	values, err := storeValues(context.Background(), cfg, in, nil)
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
	mergedEnv := append(os.Environ(), injected...)
	scrubVals := agentmode.FilterScrubbable(scrub, errW)
	so := agentmode.NewScrubber(out, scrubVals)
	se := agentmode.NewScrubber(errW, scrubVals)
	exitCode, runErr := runner(args[0], args[1:], mergedEnv, so, se)
	_ = so.Flush()
	_ = se.Flush()
	if runErr != nil {
		return fmt.Errorf("exec: %w", runErr)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// runApplyStore, apply'ın backend:store yoludur: store'dan değerleri çeker ve
// bildirilen consumption target'larını (legacy ile aynı idempotent yazıcı) yazar.
func runApplyStore(cfg *config.WappsYAML, stdoutW io.Writer) error {
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("apply: no targets declared in %s — add a 'targets:' block or use 'wapps secrets env --write <file>' for one-off writes", wappsYAMLPath)
	}
	values, err := storeValues(context.Background(), cfg, intent.Dev, nil)
	if err != nil {
		return err
	}
	archiveJSON, err := valuesToArchiveJSON(values)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	return applyTargets(cfg, archiveJSON, stdoutW)
}

// getStore, get'in backend:store yoludur: yalnızca istenen anahtarı çeker (blast-
// radius min §7.3.3) ve düz metin değeri döner (RunE agent-modu red'i AYNI kalır).
func getStore(cfg *config.WappsYAML, key string) (string, error) {
	values, err := storeValues(context.Background(), cfg, intent.Dev, []string{key})
	if err != nil {
		return "", err
	}
	v, ok := values[key]
	if !ok {
		return "", clierr.Newf(clierr.GrantDenied, "key %q not in the granted set for this identity", key)
	}
	return string(v), nil
}

// runEnvStore, env'in backend:store yoludur: store'dan değerleri çeker ve export
// satırlarını stdout'a (veya --write dosyasına, AI-safe) yazar.
func runEnvStore(cfg *config.WappsYAML, writePath, prefix string, stdoutW io.Writer) error {
	values, err := storeValues(context.Background(), cfg, intent.Dev, nil)
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
// no-echo prompt kuralıyla) yakalar ve WorkerStore.Commit ile yazar (git drift
// preflight'ı YOK — store yazımları CAS ile eşzamanlılığı çözer, git değil).
func runSetStore(key string, cfg *config.WappsYAML, opts setOptions) error {
	value, err := captureSetValue(key, opts)
	if err != nil {
		return err
	}
	if err := storeCommit(context.Background(), cfg, intent.Dev, map[string][]byte{key: []byte(value)}); err != nil {
		return err
	}
	fmt.Printf("✓ Set %s (store: %s)\n", key, cfg.Project)
	return nil
}

// runSyncStore, sync'in backend:store yoludur: kaynakları (sources) okur+merge eder
// ve tüm anahtarları TEK bir epoch+1 commit'te store'a yazar (WorkerStore.Commit).
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
	if err := storeCommit(ctx, cfg, intent.Dev, sets); err != nil {
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
