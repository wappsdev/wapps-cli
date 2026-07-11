package secrets

// store_backend_test.go, backend:store yönlendirmesini bir FAKE store (çağrıları
// gözler) + geçici bir backend:store .wapps.yaml ile doğrular (canlı oturum YOK).
// İki eksen kanıtlanır:
//   1. backend:store → exec/apply/get/env/set/sync internal/store'a yönlenir
//      (Read/Set/Import gözlenir; PLAINTEXT değerler enjekte edilir §2.7; agent-modu
//      korunur), oturum yokluğu NET SESSION_EXPIRED clierr ile yüzeye çıkar.
//   2. backend yok / legacy-git → legacy age-arşiv yolu DEĞİŞMEDEN çalışır (fake
//      store ASLA çağrılmaz).

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// --- fake store (internal/store.Store'u gözlemleyerek uygular) --------------

type readCall struct {
	project string
	keys    []string
}

type importCall struct {
	project string
	values  map[string]string
	opts    store.WriteOpts
}

type setCall struct {
	project, key, value string
	opts                store.WriteOpts
}

// fakeStore, store.Store'un çağrı-gözleyen bir uygulamasıdır.
type fakeStore struct {
	keysCalls   int
	readCalls   []readCall
	importCalls []importCall
	setCalls    []setCall
	values      map[string]string
	readErr     error
	writeErr    error
	// importNoop true ise Import çağrıyı KAYDEDER ama f.values'a yazmaz —
	// migrate import'un round-trip verify başarısızlık yolunu simüle eder.
	importNoop bool
	// whoami/whoamiErr, migrate export'un rollback-tamlık kanıtını (storeWhoami)
	// sürer. whoami nil ise varsayılan root-admin kimliği döner (tam okuma).
	whoami    *store.WhoamiResult
	whoamiErr error
}

// Whoami, cmd/secrets'taki storeWhoami arayüzünü uygular (export tamlık kanıtı).
func (f *fakeStore) Whoami(_ context.Context) (*store.WhoamiResult, error) {
	if f.whoamiErr != nil {
		return nil, f.whoamiErr
	}
	if f.whoami != nil {
		return f.whoami, nil
	}
	return &store.WhoamiResult{Principal: "test-admin", IsRootAdmin: true}, nil
}

func (f *fakeStore) Keys(_ context.Context, project string) (*store.KeysResult, error) {
	f.keysCalls++
	out := &store.KeysResult{Project: project, Epoch: 1}
	for k := range f.values {
		out.Keys = append(out.Keys, store.KeyInfo{KeyName: k, KeyVersion: 1})
	}
	return out, nil
}

func (f *fakeStore) Read(_ context.Context, project string, keys []string) (*store.ReadResult, error) {
	f.readCalls = append(f.readCalls, readCall{project: project, keys: keys})
	if f.readErr != nil {
		return nil, f.readErr
	}
	vals := map[string]string{}
	if len(keys) == 0 {
		for k, v := range f.values {
			vals[k] = v
		}
	} else {
		for _, k := range keys {
			if v, ok := f.values[k]; ok {
				vals[k] = v
			}
		}
	}
	return &store.ReadResult{Epoch: 1, Values: vals}, nil
}

func (f *fakeStore) Set(_ context.Context, project, key, value string, opts store.WriteOpts) error {
	f.setCalls = append(f.setCalls, setCall{project: project, key: key, value: value, opts: opts})
	return f.writeErr
}

func (f *fakeStore) Import(_ context.Context, project string, values map[string]string, opts store.WriteOpts) error {
	f.importCalls = append(f.importCalls, importCall{project: project, values: values, opts: opts})
	if f.writeErr != nil {
		return f.writeErr
	}
	// Gerçekçi davranış: başarılı import store durumunu günceller (migrate
	// import'un round-trip verify'ı bunu okur). importNoop verify-fail simüle eder.
	if !f.importNoop {
		for k, v := range values {
			f.values[k] = v
		}
	}
	return nil
}

func (f *fakeStore) Delete(_ context.Context, _, _ string) error { return f.writeErr }

// installFakeStore, openStore seam'ini fake ile değiştirir + temizlikte geri alır.
func installFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	f := &fakeStore{values: map[string]string{}}
	prev := openStore
	openStore = func(_ *config.WappsYAML) (store.Store, error) { return f, nil }
	t.Cleanup(func() { openStore = prev })
	return f
}

// setupStoreProject, geçici bir cwd'de backend:store .wapps.yaml yazar. XDG izole
// edilir (gerçek oturum dosyası sızmasın); out-of-band oturum token'ı temizlenir.
func setupStoreProject(t *testing.T, extraYAML string) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("CF_ACCESS_CLIENT_ID", "")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "")
	tmp := t.TempDir()
	t.Chdir(tmp)
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })
	yaml := "version: 2\nbackend: store\nproject: testproj\n" + extraYAML
	if err := os.WriteFile(filepath.Join(tmp, ".wapps.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("write .wapps.yaml: %v", err)
	}
	return tmp
}

// --- routing: reads ----------------------------------------------------------

// exec, backend:store'da PLAINTEXT değerleri store'dan çeker ve child env'e
// enjekte eder (yerel decrypt YOK, §2.7).
func TestExec_StoreBackend_InjectsPlaintextValues(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "hunter2"

	r := &fakeRunner{returnCode: 0}
	if err := runExec([]string{"printenv"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("runExec (store): %v", err)
	}
	if len(f.readCalls) != 1 {
		t.Fatalf("store Read should be called exactly once, got %d", len(f.readCalls))
	}
	if f.readCalls[0].project != "testproj" {
		t.Errorf("Read project: got %q, want testproj", f.readCalls[0].project)
	}
	found := false
	for _, e := range r.gotEnv {
		if e == "TF_VAR_DB_PASSWORD=hunter2" {
			found = true
		}
	}
	if !found {
		t.Errorf("plaintext store value must be injected; env=%v", r.gotEnv)
	}
}

// Okuma hatası (örn. SESSION_EXPIRED) → subprocess ÇALIŞMAZ, hata aynen yüzer.
func TestExec_StoreBackend_ReadErrorStopsSubprocess(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.readErr = clierr.New(clierr.SessionExpired, "no valid CF Access session")

	r := &fakeRunner{returnCode: 0}
	err := runExec([]string{"printenv"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner)
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("want SESSION_EXPIRED, got: %v", err)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not run when the store read fails; got %q", r.gotName)
	}
}

func TestApply_StoreBackend_WriteFailsClean(t *testing.T) {
	setupStoreProject(t, "targets:\n  - path: .env.local\n")
	f := installFakeStore(t)
	f.readErr = clierr.New(clierr.SessionExpired, "no valid CF Access session")

	err := runApply(&bytes.Buffer{})
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("want SESSION_EXPIRED, got: %v", err)
	}
	if len(f.readCalls) != 1 {
		t.Fatalf("store Read should be called once, got %d", len(f.readCalls))
	}
	// Target dosyası ASLA yazılmamalı (okuma başarısız).
	if _, statErr := os.Stat(".env.local"); !os.IsNotExist(statErr) {
		t.Error(".env.local must not be written when the store read fails")
	}
}

func TestGet_StoreBackend_ScopesToSingleKey(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "hunter2"

	var out bytes.Buffer
	if err := runGet("DB_PASSWORD", &out); err != nil {
		t.Fatalf("runGet (store): %v", err)
	}
	if len(f.readCalls) != 1 {
		t.Fatalf("store Read should be called once, got %d", len(f.readCalls))
	}
	// get, blast-radius min için YALNIZCA istenen anahtarı çeker.
	keys := f.readCalls[0].keys
	if len(keys) != 1 || keys[0] != "DB_PASSWORD" {
		t.Errorf("get must scope Read to the single key: got %v", keys)
	}
	if out.String() != "hunter2\n" && out.String() != "hunter2" {
		t.Errorf("get must print the plaintext value; got %q", out.String())
	}
}

func TestEnv_StoreBackend_RoutesToStore(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["API_KEY"] = "abc"

	var out bytes.Buffer
	if err := runEnv("", "TF_VAR_", &out); err != nil {
		t.Fatalf("runEnv (store): %v", err)
	}
	if len(f.readCalls) != 1 {
		t.Fatalf("store Read should be called once, got %d", len(f.readCalls))
	}
	if !bytes.Contains(out.Bytes(), []byte("TF_VAR_API_KEY")) {
		t.Errorf("env output missing exported key; got %q", out.String())
	}
}

// list, backend:store'da anahtar ADLARINI metadata düzleminden (GET /keys) çeker:
// passphrase/arşiv GEREKMEZ, Store.Read ASLA çağrılmaz (audit'e value.read düşmez),
// çıktı legacy ile aynı biçimdedir (satır başına bir ad, sıralı).
func TestList_StoreBackend_ListsNamesViaKeysMetadata(t *testing.T) {
	setupStoreProject(t, "")
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "") // store yolu passphrase istememeli
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "hunter2"
	f.values["API_KEY"] = "abc"

	var out bytes.Buffer
	if err := runList(&out); err != nil {
		t.Fatalf("runList (store): %v", err)
	}
	if f.keysCalls != 1 {
		t.Fatalf("store Keys should be called exactly once, got %d", f.keysCalls)
	}
	if len(f.readCalls) != 0 {
		t.Fatalf("list is metadata-plane: Store.Read must NEVER be called, got %d", len(f.readCalls))
	}
	if out.String() != "API_KEY\nDB_PASSWORD\n" {
		t.Errorf("list output: got %q, want sorted names one per line", out.String())
	}
	// Değerler ASLA çıktıya sızmamalı.
	if bytes.Contains(out.Bytes(), []byte("hunter2")) {
		t.Error("list leaked a secret value")
	}
}

// legacy backend'de list, age arşivinden okumaya devam eder (fake store'a gitmez).
func TestList_LegacyBackend_DoesNotRouteToStore(t *testing.T) {
	execTestSetup(t, map[string]string{"DB_PASSWORD": "hunter2"})
	f := installFakeStore(t)

	var out bytes.Buffer
	if err := runList(&out); err != nil {
		t.Fatalf("legacy runList: %v", err)
	}
	if f.keysCalls != 0 {
		t.Fatalf("legacy backend must NOT route list to the store; keysCalls=%d", f.keysCalls)
	}
	if out.String() != "DB_PASSWORD\n" {
		t.Errorf("legacy list output: got %q", out.String())
	}
}

// diff, backend:store'da FAIL LOUD olur (NOT_AVAILABLE): git-ref karşılaştırması
// store'da tanımsızdır; legacy arşive/passphrase'e DOKUNULMAZ — bayat bir legacy
// arşivin sessizce diff'lenmesi (P2) bu şekilde imkansızlaşır.
func TestDiff_StoreBackend_FailsLoudNotAvailable(t *testing.T) {
	setupStoreProject(t, "")
	installFakeStore(t)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "irrelevant")

	gitShow := func(ref, path string) ([]byte, error) {
		t.Fatalf("diff must not touch git archive history in store mode (asked for %s:%s)", ref, path)
		return nil, nil
	}
	err := runDiff("HEAD~1", gitShow, io.Discard)
	if !clierr.Is(err, clierr.NotAvailable) {
		t.Fatalf("want NOT_AVAILABLE, got: %v", err)
	}
}

// TRANSCRIPT-LEAK KANARYASI (store yolu, §7.4.3): store'dan çekilmiş bir değeri
// echo'layan alt-süreç, o değeri yakalanan stdout/stderr'e ASLA sızdıramaz —
// scrubber onu *** yapar. Legacy exec'teki kanaryanın store-backend eşleniği.
func TestExec_StoreBackend_ScrubsChildOutput(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	secret := "sk_live_store_supersecret_1234567890"
	f.values["STRIPE_KEY"] = secret

	var out, errB bytes.Buffer
	leaky := func(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
		var val string
		for _, e := range env {
			if after, ok := strings.CutPrefix(e, "TF_VAR_STRIPE_KEY="); ok {
				val = after
			}
		}
		// Sızdıran bir araç gibi değeri iki akışa da bas — hatta parçalı.
		_, _ = stdout.Write([]byte("connecting with " + val))
		_, _ = stdout.Write([]byte(" ... done\n"))
		_, _ = stderr.Write([]byte("auth failed for " + val + "\n"))
		return 0, nil
	}

	if err := runExec([]string{"leak"}, "TF_VAR_", "dev", false, false, &out, &errB, leaky); err != nil {
		t.Fatalf("runExec (store): %v", err)
	}
	for name, buf := range map[string]*bytes.Buffer{"stdout": &out, "stderr": &errB} {
		if bytes.Contains(buf.Bytes(), []byte(secret)) {
			t.Fatalf("SECRET LEAKED into %s transcript: %q", name, buf.String())
		}
		if !bytes.Contains(buf.Bytes(), []byte("***")) {
			t.Fatalf("expected *** redaction on %s, got: %q", name, buf.String())
		}
	}
}

// --- routing: writes ---------------------------------------------------------

func TestSet_StoreBackend_RoutesToSet(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	// Değer --from-file ile yakalanır (TTY gerekmez).
	valFile := filepath.Join(t.TempDir(), "val")
	if err := os.WriteFile(valFile, []byte("s3cr3t\n"), 0600); err != nil {
		t.Fatalf("write val file: %v", err)
	}

	if err := runSet("DB_PASSWORD", setOptions{fromFile: valFile}); err != nil {
		t.Fatalf("runSet (store) should succeed with the fake set: %v", err)
	}
	if len(f.setCalls) != 1 {
		t.Fatalf("store Set should be called once, got %d", len(f.setCalls))
	}
	c := f.setCalls[0]
	if c.project != "testproj" || c.key != "DB_PASSWORD" {
		t.Errorf("Set target: got %s/%s", c.project, c.key)
	}
	// Sondaki newline soyulmuş olmalı.
	if c.value != "s3cr3t" {
		t.Errorf("Set value: got %q, want s3cr3t", c.value)
	}
	// Store yolunda age-arşivi YAZILMAMALI.
	if _, statErr := os.Stat("secrets/all.enc.age"); !os.IsNotExist(statErr) {
		t.Error("store set must not write the legacy archive")
	}
}

func TestSync_StoreBackend_ImportsWithSyncIntent(t *testing.T) {
	dir := setupStoreProject(t, "sources:\n  - type: file\n    path: .env.shared\n")
	if err := os.WriteFile(filepath.Join(dir, ".env.shared"), []byte("API_KEY=abc123\n"), 0600); err != nil {
		t.Fatalf("seed file source: %v", err)
	}
	f := installFakeStore(t)

	if err := runSync(context.Background(), os.Getenv); err != nil {
		t.Fatalf("runSync (store) should succeed with the fake import: %v", err)
	}
	if len(f.importCalls) != 1 {
		t.Fatalf("store Import should be called once, got %d", len(f.importCalls))
	}
	c := f.importCalls[0]
	if got := c.values["API_KEY"]; got != "abc123" {
		t.Errorf("Import value: got %q, want abc123", got)
	}
	// sync yazımları X-Wapps-Intent: sync etiketi taşımalı (audit key.sync, §6.4).
	if !c.opts.Sync {
		t.Errorf("sync import must carry the Sync intent flag")
	}
}

// --- agent-mode guards precede store routing ----------------------------------

// backend:store olsa bile --break-glass ajan modunda store'a ULAŞMADAN reddedilir.
func TestExec_StoreBackend_BreakGlassAgentRefusedBeforeStore(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	err := runExec([]string{"true"}, "TF_VAR_", "dev", true /*breakGlass*/, true /*isAgent*/, io.Discard, io.Discard, (&fakeRunner{}).runner)
	if !clierr.Is(err, clierr.BreakGlassRefused) {
		t.Fatalf("want BREAK_GLASS_REFUSED, got: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Errorf("store must not be reached when break-glass is refused; reads=%d", len(f.readCalls))
	}
}

// --- legacy default is untouched -----------------------------------------------

// backend YOK (version:1) → legacy age-arşiv yolu kullanılır; fake store ASLA
// çağrılmaz. Enjekte edilen env, legacy arşivinden gelir.
func TestExec_LegacyBackend_DoesNotRouteToStore(t *testing.T) {
	execTestSetup(t, map[string]string{"DB_PASSWORD": "hunter2"})
	f := installFakeStore(t)

	r := &fakeRunner{returnCode: 0}
	if err := runExec([]string{"printenv"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("legacy runExec: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Fatalf("legacy backend must NOT route to the store; reads=%d", len(f.readCalls))
	}
	found := false
	for _, e := range r.gotEnv {
		if e == "TF_VAR_DB_PASSWORD=hunter2" {
			found = true
		}
	}
	if !found {
		t.Errorf("legacy archive env missing; env=%v", r.gotEnv)
	}
}

// --- real wiring: default openStore builds a real WorkerStore -------------------

// Fake OVERRIDE YOK: gerçek openWorkerStore bir WorkerStore kurar; oturum yokluğunda
// Read → session.Auth → SESSION_EXPIRED ("run wapps login"). Bu, üretim yolunun
// gerçekten internal/store'u çalıştırdığını kanıtlar (fake seam değil).
func TestExec_StoreBackend_RealWiringSurfacesSessionExpired(t *testing.T) {
	setupStoreProject(t, "")
	// Kullanılmayan bir gate: Auth (oturum yok) ağ'a çıkmadan önce ateşler.
	t.Setenv("WAPPS_SECRETS_GATE", "http://127.0.0.1:1")

	r := &fakeRunner{returnCode: 0}
	err := runExec([]string{"true"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner)
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("real store wiring should surface SESSION_EXPIRED (no session), got: %v", err)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not run; got %q", r.gotName)
	}
}
