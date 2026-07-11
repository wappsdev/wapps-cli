package secrets

// store_backend_test.go, backend:store yönlendirmesini bir FAKE store (çağrıları
// gözler) + geçici bir backend:store .wapps.yaml ile doğrular (canlı oturum YOK).
// İki eksen kanıtlanır:
//   1. backend:store → exec/apply/get/env/set/sync internal/store'a yönlenir (Fetch/
//      Commit gözlenir, intent + kapsam-anahtarları taşınır, agent-modu + fresh-or-fail
//      korunur), oturum/kimlik yokluğu NET clierr ile yüzeye çıkar.
//   2. backend yok / legacy-git → legacy age-arşiv yolu DEĞİŞMEDEN çalışır (fake store
//      ASLA çağrılmaz).

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// --- fake store (internal/store.Store'u gözlemleyerek uygular) --------------

type fetchCall struct {
	project string
	opts    store.FetchOpts
}

type commitCall struct {
	project string
	delta   store.ManifestDelta
}

// fakeStore, store.Store'un çağrı-gözleyen bir uygulamasıdır. Fetch varsayılan
// olarak boş-ama-non-nil bir snapshot döner (verb yolu ardından yerel-kimlik
// yokluğunda IDENTITY_MISSING'e düşer); Commit varsayılan olarak başarı döner.
type fakeStore struct {
	fetchCalls  []fetchCall
	commitCalls []commitCall
	fetchErr    error
	commitErr   error
}

func (f *fakeStore) Fetch(_ context.Context, project string, opts store.FetchOpts) (*store.VerifiedSnapshot, error) {
	f.fetchCalls = append(f.fetchCalls, fetchCall{project: project, opts: opts})
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return &store.VerifiedSnapshot{Project: project, Epoch: 1}, nil
}

func (f *fakeStore) Commit(_ context.Context, project string, delta store.ManifestDelta) (*store.CommitResult, error) {
	f.commitCalls = append(f.commitCalls, commitCall{project: project, delta: delta})
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &store.CommitResult{EpochBefore: 0, EpochAfter: 1}, nil
}

// installFakeStore, openStore seam'ini fake ile değiştirir + temizlikte geri alır.
func installFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	f := &fakeStore{}
	prev := openStore
	openStore = func(_ *config.WappsYAML, _ intent.Intent) (store.Store, error) { return f, nil }
	t.Cleanup(func() { openStore = prev })
	return f
}

// setupStoreProject, geçici bir cwd'de backend:store .wapps.yaml yazar (override YOK,
// passphrase YOK — store yolu bunlara ihtiyaç duymaz). extraYAML, project satırından
// sonra eklenir (ör. sources / targets blokları). XDG'yi izole bir temp'e çeker ki
// testler HERMETİK olsun: geliştiricinin gerçek ~/.config/wapps/identity.json'ı bu
// testlere sızmasın (yoksa localDecryptIdentity onu yükler ve IDENTITY_MISSING beklentisi
// bozulur). Out-of-band oturum token'ı da temizlenir (kalıntı env sızması olmasın).
func setupStoreProject(t *testing.T, extraYAML string) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
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

// --- routing: reads --------------------------------------------------------

func TestExec_StoreBackend_RoutesToStore(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	r := &fakeRunner{returnCode: 0}
	err := runExec([]string{"printenv"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner)

	// Oturum/kimlik yok → IDENTITY_MISSING (doğru koşum-zamanı yüzeyi).
	if !clierr.Is(err, clierr.IdentityMissing) {
		t.Fatalf("want IDENTITY_MISSING, got: %v", err)
	}
	if len(f.fetchCalls) != 1 {
		t.Fatalf("store Fetch should be called exactly once, got %d", len(f.fetchCalls))
	}
	if f.fetchCalls[0].project != "testproj" {
		t.Errorf("Fetch project: got %q, want testproj", f.fetchCalls[0].project)
	}
	if f.fetchCalls[0].opts.Intent != intent.Dev {
		t.Errorf("Fetch intent: got %q, want dev", f.fetchCalls[0].opts.Intent)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not run when the store read fails; got %q", r.gotName)
	}
}

// fresh-or-fail: exec --intent deploy backend:store'da store'un GERÇEK yoluna
// yönlenir (legacy NOT_AVAILABLE fail-loud'una DEĞİL) ve Deploy intent'i taşınır.
func TestExec_StoreBackend_DeployIntentRoutesFreshOrFail(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	r := &fakeRunner{returnCode: 0}
	err := runExec([]string{"tofu", "apply"}, "TF_VAR_", "deploy", false, false, io.Discard, io.Discard, r.runner)

	if clierr.Is(err, clierr.NotAvailable) {
		t.Fatalf("under backend:store, deploy must NOT hit the legacy fail-loud NOT_AVAILABLE: %v", err)
	}
	if !clierr.Is(err, clierr.IdentityMissing) {
		t.Fatalf("want IDENTITY_MISSING (store path), got: %v", err)
	}
	if len(f.fetchCalls) != 1 {
		t.Fatalf("store Fetch should be called once, got %d", len(f.fetchCalls))
	}
	if f.fetchCalls[0].opts.Intent != intent.Deploy {
		t.Errorf("deploy intent must reach the store: got %q, want deploy", f.fetchCalls[0].opts.Intent)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not run; got %q", r.gotName)
	}
}

func TestApply_StoreBackend_RoutesToStore(t *testing.T) {
	setupStoreProject(t, "targets:\n  - path: .env.local\n")
	f := installFakeStore(t)

	err := runApply(&bytes.Buffer{})
	if !clierr.Is(err, clierr.IdentityMissing) {
		t.Fatalf("want IDENTITY_MISSING, got: %v", err)
	}
	if len(f.fetchCalls) != 1 {
		t.Fatalf("store Fetch should be called once, got %d", len(f.fetchCalls))
	}
	// Target dosyası ASLA yazılmamalı (fetch decrypt'ten önce başarısız oldu).
	if _, statErr := os.Stat(".env.local"); !os.IsNotExist(statErr) {
		t.Error(".env.local must not be written when the store read fails")
	}
}

func TestGet_StoreBackend_RoutesToStoreWithScopedKey(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	var out bytes.Buffer
	err := runGet("DB_PASSWORD", &out)
	if !clierr.Is(err, clierr.IdentityMissing) {
		t.Fatalf("want IDENTITY_MISSING, got: %v", err)
	}
	if len(f.fetchCalls) != 1 {
		t.Fatalf("store Fetch should be called once, got %d", len(f.fetchCalls))
	}
	// get, blast-radius min için YALNIZCA istenen anahtarı çeker (§7.3.3).
	keys := f.fetchCalls[0].opts.Keys
	if len(keys) != 1 || keys[0] != "DB_PASSWORD" {
		t.Errorf("get must scope Fetch to the single key: got %v", keys)
	}
	if out.Len() != 0 {
		t.Errorf("no value must be printed on a failed store read; got %q", out.String())
	}
}

func TestEnv_StoreBackend_RoutesToStore(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	var out bytes.Buffer
	err := runEnv("", "TF_VAR_", &out)
	if !clierr.Is(err, clierr.IdentityMissing) {
		t.Fatalf("want IDENTITY_MISSING, got: %v", err)
	}
	if len(f.fetchCalls) != 1 {
		t.Fatalf("store Fetch should be called once, got %d", len(f.fetchCalls))
	}
	if f.fetchCalls[0].opts.Intent != intent.Dev {
		t.Errorf("env intent: got %q, want dev", f.fetchCalls[0].opts.Intent)
	}
}

// --- routing: writes -------------------------------------------------------

func TestSet_StoreBackend_RoutesToCommit(t *testing.T) {
	setupStoreProject(t, "")
	// Commit imza için yerel bir writer kimliği gerektirir (§7.1) → enroll (software).
	enrollForTest(t, "machine:ci-set", "machine", false)
	f := installFakeStore(t)

	// Değer --from-file ile yakalanır (TTY gerekmez).
	valFile := filepath.Join(t.TempDir(), "val")
	if err := os.WriteFile(valFile, []byte("s3cr3t\n"), 0600); err != nil {
		t.Fatalf("write val file: %v", err)
	}

	err := runSet("DB_PASSWORD", setOptions{fromFile: valFile})
	if err != nil {
		t.Fatalf("runSet (store) should succeed with the fake commit: %v", err)
	}
	if len(f.commitCalls) != 1 {
		t.Fatalf("store Commit should be called once, got %d", len(f.commitCalls))
	}
	c := f.commitCalls[0]
	if c.project != "testproj" {
		t.Errorf("Commit project: got %q, want testproj", c.project)
	}
	if c.delta.Intent != intent.Dev {
		t.Errorf("Commit intent: got %q, want dev", c.delta.Intent)
	}
	got, ok := c.delta.Sets["DB_PASSWORD"]
	if !ok {
		t.Fatalf("Commit delta missing DB_PASSWORD; sets=%v", c.delta.Sets)
	}
	// Sondaki newline soyulmuş olmalı.
	if string(got) != "s3cr3t" {
		t.Errorf("Commit value: got %q, want s3cr3t", string(got))
	}
	// Store yolunda dosya-kaynağı / age-arşivi YAZILMAMALI.
	if _, statErr := os.Stat("secrets/all.enc.age"); !os.IsNotExist(statErr) {
		t.Error("store set must not write the legacy archive")
	}
}

func TestSync_StoreBackend_RoutesToCommit(t *testing.T) {
	dir := setupStoreProject(t, "sources:\n  - type: file\n    path: .env.shared\n")
	if err := os.WriteFile(filepath.Join(dir, ".env.shared"), []byte("API_KEY=abc123\n"), 0600); err != nil {
		t.Fatalf("seed file source: %v", err)
	}
	// Commit imza için yerel bir writer kimliği gerektirir (§7.1) → enroll (software).
	enrollForTest(t, "machine:ci-sync", "machine", false)
	f := installFakeStore(t)

	err := runSync(context.Background(), os.Getenv)
	if err != nil {
		t.Fatalf("runSync (store) should succeed with the fake commit: %v", err)
	}
	if len(f.commitCalls) != 1 {
		t.Fatalf("store Commit should be called once, got %d", len(f.commitCalls))
	}
	got, ok := f.commitCalls[0].delta.Sets["API_KEY"]
	if !ok {
		t.Fatalf("Commit delta missing API_KEY; sets=%v", f.commitCalls[0].delta.Sets)
	}
	if string(got) != "abc123" {
		t.Errorf("Commit value: got %q, want abc123", string(got))
	}
}

// --- agent-mode + fresh-or-fail guards precede store routing ----------------

// backend:store olsa bile --break-glass ajan modunda store'a ULAŞMADAN reddedilir.
func TestExec_StoreBackend_BreakGlassAgentRefusedBeforeStore(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	err := runExec([]string{"true"}, "TF_VAR_", "dev", true /*breakGlass*/, true /*isAgent*/, io.Discard, io.Discard, (&fakeRunner{}).runner)
	if !clierr.Is(err, clierr.BreakGlassRefused) {
		t.Fatalf("want BREAK_GLASS_REFUSED, got: %v", err)
	}
	if len(f.fetchCalls) != 0 {
		t.Errorf("store must not be reached when break-glass is refused; fetches=%d", len(f.fetchCalls))
	}
}

// --- legacy default is untouched -------------------------------------------

// backend YOK (version:1) → legacy age-arşiv yolu kullanılır; fake store ASLA
// çağrılmaz. Enjekte edilen env, legacy arşivinden gelir.
func TestExec_LegacyBackend_DoesNotRouteToStore(t *testing.T) {
	execTestSetup(t, map[string]string{"DB_PASSWORD": "hunter2"})
	f := installFakeStore(t)

	r := &fakeRunner{returnCode: 0}
	if err := runExec([]string{"printenv"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("legacy runExec: %v", err)
	}
	if len(f.fetchCalls) != 0 {
		t.Fatalf("legacy backend must NOT route to the store; fetches=%d", len(f.fetchCalls))
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

// --- real wiring: default openStore builds a real WorkerStore --------------

// Fake OVERRIDE YOK: gerçek openWorkerStore bir WorkerStore kurar; oturum yokluğunda
// Fetch → sessionAuth → AUTH_EXPIRED ("run wapps login"). Bu, üretim yolunun
// gerçekten internal/store'u çalıştırdığını kanıtlar (fake seam değil).
func TestExec_StoreBackend_RealWiringSurfacesAuthExpired(t *testing.T) {
	setupStoreProject(t, "")

	// İzole edilmiş ev dizini: minimal roots.json (loadPins geçsin diye) + oturum YOK.
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if err := os.MkdirAll(filepath.Join(xdg, "wapps"), 0700); err != nil {
		t.Fatalf("mkdir xdg/wapps: %v", err)
	}
	roots := `{"schema":"wapps-pins/v1","genesis":{"admin_epoch":1,"sha256":"00"},"last_verified":{"admin_epoch":1,"sha256":"00"}}`
	if err := os.WriteFile(filepath.Join(xdg, "wapps", "roots.json"), []byte(roots), 0600); err != nil {
		t.Fatalf("seed roots.json: %v", err)
	}
	// Kullanılmayan bir gate: Auth (oturum yok) ağ'a çıkmadan önce ateşler.
	t.Setenv("WAPPS_SECRETS_GATE", "http://127.0.0.1:1")

	r := &fakeRunner{returnCode: 0}
	err := runExec([]string{"true"}, "TF_VAR_", "dev", false, false, io.Discard, io.Discard, r.runner)
	if !clierr.Is(err, clierr.AuthExpired) {
		t.Fatalf("real store wiring should surface AUTH_EXPIRED (no session), got: %v", err)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not run; got %q", r.gotName)
	}
}
