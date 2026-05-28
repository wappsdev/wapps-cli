package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/coolify"
)

// fakeCoolify captures calls so tests can assert without HTTP.
type fakeCoolify struct {
	listResult []coolify.EnvEntry
	listErr    error
	upserts    []upsertCall
	upsertErr  error
	deletes    []deleteCall
	deleteErr  error
}

type upsertCall struct {
	key, value  string
	isBuildtime bool
}

type deleteCall struct {
	envUUID string
}

func (f *fakeCoolify) ListAppEnvs(string) ([]coolify.EnvEntry, error) {
	return f.listResult, f.listErr
}

func (f *fakeCoolify) UpsertAppEnv(_, key, value string, isBuildtime bool) error {
	f.upserts = append(f.upserts, upsertCall{key, value, isBuildtime})
	return f.upsertErr
}

func (f *fakeCoolify) DeleteAppEnv(_, envUUID string) error {
	f.deletes = append(f.deletes, deleteCall{envUUID})
	return f.deleteErr
}

func setupCoolifyTest(t *testing.T, archive map[string]string, current []coolify.EnvEntry) (*fakeCoolify, coolifyOptions) {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	if err := os.WriteFile(".wapps.yaml", []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`), 0644); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	envelope := make(map[string]json.RawMessage)
	for k, v := range archive {
		b, _ := json.Marshal(map[string]string{"value": v})
		envelope[k] = b
	}
	raw, _ := json.Marshal(envelope)
	if err := ageutil.EncryptWriteAtomic("secrets/all.enc.age", raw, pp); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fake := &fakeCoolify{listResult: current}
	opts := coolifyOptions{
		appUUID:  "app-1",
		apiToken: "tok-xyz",
		apiURL:   "http://unused",
		stdoutW:  os.Stdout,
		newClient: func(string, string) coolifyAPI {
			return fake
		},
	}
	return fake, opts
}

func TestRunSyncCoolify_DryRunDefault_NoMutations(t *testing.T) {
	fake, opts := setupCoolifyTest(t,
		map[string]string{"DB_PASSWORD": "secret", "NEW_KEY": "v"},
		[]coolify.EnvEntry{{UUID: "e1", Key: "DB_PASSWORD", Value: "old"}, {UUID: "e2", Key: "STALE", Value: "x"}},
	)
	opts.force = false // dry-run

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}

	if len(fake.upserts) != 0 {
		t.Errorf("dry-run should NOT upsert, got %d calls", len(fake.upserts))
	}
	if len(fake.deletes) != 0 {
		t.Errorf("dry-run should NOT delete, got %d calls", len(fake.deletes))
	}
}

func TestRunSyncCoolify_ForceApplies(t *testing.T) {
	fake, opts := setupCoolifyTest(t,
		map[string]string{
			"DB_PASSWORD": "new-value", // CHANGE
			"NEW_KEY":     "v",         // ADD
			// SAME_KEY identical
			"SAME_KEY": "same",
		},
		[]coolify.EnvEntry{
			{UUID: "e1", Key: "DB_PASSWORD", Value: "old-value"},
			{UUID: "e2", Key: "STALE", Value: "x"},
			{UUID: "e3", Key: "SAME_KEY", Value: "same"},
		},
	)
	opts.force = true

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}

	// 2 upserts: NEW_KEY (add) + DB_PASSWORD (change). SAME_KEY is noop.
	if len(fake.upserts) != 2 {
		t.Fatalf("expected 2 upserts, got %d: %+v", len(fake.upserts), fake.upserts)
	}
	gotKeys := map[string]bool{}
	for _, u := range fake.upserts {
		gotKeys[u.key] = true
		if u.isBuildtime {
			t.Errorf("Coolify sync should NOT push as buildtime: %+v", u)
		}
	}
	if !gotKeys["NEW_KEY"] || !gotKeys["DB_PASSWORD"] {
		t.Errorf("missing expected upserts: %v", gotKeys)
	}

	// 1 delete: STALE
	if len(fake.deletes) != 1 || fake.deletes[0].envUUID != "e2" {
		t.Errorf("expected delete of e2, got %+v", fake.deletes)
	}
}

func TestRunSyncCoolify_RequiresApp(t *testing.T) {
	_, opts := setupCoolifyTest(t, nil, nil)
	opts.appUUID = ""

	err := runSyncCoolify(opts)
	if err == nil {
		t.Fatal("expected error: --app required")
	}
	if !strings.Contains(err.Error(), "--app") {
		t.Errorf("error should mention --app: %v", err)
	}
}

func TestRunSyncCoolify_RequiresToken(t *testing.T) {
	_, opts := setupCoolifyTest(t, nil, nil)
	opts.apiToken = ""

	err := runSyncCoolify(opts)
	if err == nil {
		t.Fatal("expected error: token required")
	}
	if !strings.Contains(err.Error(), "COOLIFY_API_TOKEN") {
		t.Errorf("error should name env var: %v", err)
	}
}

func TestRunSyncCoolify_RequiresWappsYAML(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "x")
	opts := coolifyOptions{
		appUUID:   "app-1",
		apiToken:  "tok",
		apiURL:    "http://unused",
		stdoutW:   os.Stdout,
		newClient: func(string, string) coolifyAPI { return &fakeCoolify{} },
	}

	err := runSyncCoolify(opts)
	if err == nil {
		t.Fatal("expected error: .wapps.yaml required")
	}
	if !strings.Contains(err.Error(), ".wapps.yaml") {
		t.Errorf("error should mention config file: %v", err)
	}
}

func TestRunSyncCoolify_RequiresPassphrase(t *testing.T) {
	_, opts := setupCoolifyTest(t, map[string]string{"K": "v"}, nil)
	os.Unsetenv("WAPPS_SECRETS_PASSPHRASE")

	err := runSyncCoolify(opts)
	if err == nil {
		t.Fatal("expected error: passphrase required")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Errorf("error should name env var: %v", err)
	}
}

func TestRunSyncCoolify_PropagatesListErr(t *testing.T) {
	fake, opts := setupCoolifyTest(t, map[string]string{"K": "v"}, nil)
	fake.listErr = errors.New("network unreachable")

	err := runSyncCoolify(opts)
	if err == nil {
		t.Fatal("expected ListAppEnvs error propagation")
	}
	if !strings.Contains(err.Error(), "network unreachable") {
		t.Errorf("error chain lost network error: %v", err)
	}
}

func TestComputeCoolifyDiff_EmptyBothSides(t *testing.T) {
	diff := computeCoolifyDiff(map[string]string{}, nil, true)
	if len(diff.add)+len(diff.change)+len(diff.remove)+len(diff.noop) != 0 {
		t.Errorf("expected fully empty diff, got %+v", diff)
	}
}

func TestComputeCoolifyDiff_PureAdd(t *testing.T) {
	diff := computeCoolifyDiff(map[string]string{"FOO": "bar"}, nil, true)
	if len(diff.add) != 1 || diff.add["FOO"] != "bar" {
		t.Errorf("add: %v", diff.add)
	}
	if len(diff.change) != 0 || len(diff.remove) != 0 {
		t.Errorf("expected pure add, got %+v", diff)
	}
}

func TestComputeCoolifyDiff_PureRemove(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{},
		[]coolify.EnvEntry{{UUID: "u1", Key: "GONE", Value: "x"}},
		true, // deleteUnmanaged
	)
	if len(diff.remove) != 1 || diff.remove["GONE"] != "u1" {
		t.Errorf("remove: %v", diff.remove)
	}
}

// TestComputeCoolifyDiff_DeleteUnmanagedFalse_NoRemove proves the additive
// merge mode: Coolify-only keys are NOT bucketed for removal when
// deleteUnmanaged is false (the multi-app default).
func TestComputeCoolifyDiff_DeleteUnmanagedFalse_NoRemove(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"KEEP": "v"},
		[]coolify.EnvEntry{{UUID: "u1", Key: "COOLIFY_ONLY", Value: "x"}},
		false, // deleteUnmanaged off
	)
	if len(diff.remove) != 0 {
		t.Errorf("delete_unmanaged=false must leave remove empty, got: %v", diff.remove)
	}
	if len(diff.add) != 1 || diff.add["KEEP"] != "v" {
		t.Errorf("add bucket wrong: %v", diff.add)
	}
}

func TestComputeCoolifyDiff_ChangeAndNoop(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"A": "new", "B": "same"},
		[]coolify.EnvEntry{{UUID: "u1", Key: "A", Value: "old"}, {UUID: "u2", Key: "B", Value: "same"}},
		true,
	)
	if len(diff.change) != 1 || diff.change["A"].newValue != "new" {
		t.Errorf("change: %v", diff.change)
	}
	if len(diff.noop) != 1 || diff.noop[0] != "B" {
		t.Errorf("noop: %v", diff.noop)
	}
}

func TestArchiveToFlatMap_StringValue(t *testing.T) {
	archive := map[string]json.RawMessage{
		"FOO": json.RawMessage(`{"value":"bar"}`),
	}
	got := archiveToFlatMap(archive, "")
	if got["FOO"] != "bar" {
		t.Errorf("got %v, want FOO=bar", got)
	}
}

func TestArchiveToFlatMap_ListValueEmitsCompactJSON(t *testing.T) {
	archive := map[string]json.RawMessage{
		"PATHS": json.RawMessage(`{"value":["a","b"]}`),
	}
	got := archiveToFlatMap(archive, "")
	if got["PATHS"] != `["a","b"]` {
		t.Errorf("list value: %q", got["PATHS"])
	}
}

func TestArchiveToFlatMap_PrefixApplied(t *testing.T) {
	archive := map[string]json.RawMessage{
		"DB_PASSWORD": json.RawMessage(`{"value":"x"}`),
	}
	got := archiveToFlatMap(archive, "PROD_")
	if _, ok := got["PROD_DB_PASSWORD"]; !ok {
		t.Errorf("prefix not applied, got: %v", got)
	}
}

func TestApplyCoolifyDiff_OrdersAddChangeRemove(t *testing.T) {
	fake := &fakeCoolify{}
	diff := coolifyDiff{
		add:    map[string]string{"NEW": "v"},
		change: map[string]coolifyChange{"EXISTING": {newValue: "n"}},
		remove: map[string]string{"GONE": "u1"},
	}
	if err := applyCoolifyDiff(fake, "app-1", diff, nil); err != nil {
		t.Fatalf("applyCoolifyDiff: %v", err)
	}
	if len(fake.upserts) != 2 {
		t.Errorf("expected 2 upserts, got %d", len(fake.upserts))
	}
	if len(fake.deletes) != 1 {
		t.Errorf("expected 1 delete, got %d", len(fake.deletes))
	}
}

func TestApplyCoolifyDiff_StopsOnFirstError(t *testing.T) {
	fake := &fakeCoolify{upsertErr: errors.New("api blew up")}
	diff := coolifyDiff{
		add:    map[string]string{"A": "1", "B": "2"},
		change: map[string]coolifyChange{},
		remove: map[string]string{},
	}
	err := applyCoolifyDiff(fake, "app", diff, nil)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	// First add should have been attempted, but flow stops there.
	if len(fake.upserts) > 1 {
		t.Errorf("should stop on first failure, got %d attempts", len(fake.upserts))
	}
}

// TestApplyCoolifyDiff_WritesToInjectedWriter is the regression for the
// os.Stdout-bypass fix: the "✓ Applied" summary must go through the writer
// the caller passed in (test buffer in tests, opts.stdoutW in production),
// not the hard-coded process stdout. Earlier the line would always land on
// real stdout regardless of who called applyCoolifyDiff.
func TestApplyCoolifyDiff_WritesToInjectedWriter(t *testing.T) {
	fake := &fakeCoolify{}
	diff := coolifyDiff{
		add:    map[string]string{"NEW": "v"},
		change: map[string]coolifyChange{},
		remove: map[string]string{},
	}
	// Use an os.File backed by a pipe so we can read what was written without
	// real stdout being involved.
	r, w, _ := os.Pipe()
	if err := applyCoolifyDiff(fake, "app", diff, w); err != nil {
		t.Fatalf("applyCoolifyDiff: %v", err)
	}
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "Applied") {
		t.Errorf("expected 'Applied' on injected writer, got: %q", out)
	}
}

// ---- archiveToAppMap (prefix-strip) ----

func TestArchiveToAppMap_StripsPrefix(t *testing.T) {
	archive := map[string]json.RawMessage{
		"KREEVA_WEB_VITE_API_URL": json.RawMessage(`{"value":"https://api"}`),
		"KREEVA_WEB_TOKEN":        json.RawMessage(`{"value":"t"}`),
		"ROYCO_API_DB":            json.RawMessage(`{"value":"pg"}`), // other app
		"lab_01_ipv4":             json.RawMessage(`{"value":"1.2.3.4"}`), // tofu output
	}
	got := archiveToAppMap(archive, "KREEVA_WEB_")
	if len(got) != 2 {
		t.Fatalf("expected 2 keys for KREEVA_WEB_, got %d: %v", len(got), got)
	}
	if got["VITE_API_URL"] != "https://api" {
		t.Errorf("prefix not stripped correctly: %v", got)
	}
	if _, leaked := got["ROYCO_API_DB"]; leaked {
		t.Error("other app's key leaked in")
	}
	if _, leaked := got["lab_01_ipv4"]; leaked {
		t.Error("tofu output leaked in")
	}
}

func TestArchiveToAppMap_NoMatchReturnsEmpty(t *testing.T) {
	archive := map[string]json.RawMessage{
		"ROYCO_API_DB": json.RawMessage(`{"value":"pg"}`),
	}
	got := archiveToAppMap(archive, "KREEVA_WEB_")
	if len(got) != 0 {
		t.Errorf("expected empty map for non-matching prefix, got %v", got)
	}
}

func TestArchiveToAppMap_SkipsExactPrefixMatch(t *testing.T) {
	// A key equal to the prefix strips to "" — never a valid env name.
	archive := map[string]json.RawMessage{
		"KREEVA_WEB_":     json.RawMessage(`{"value":"oops"}`),
		"KREEVA_WEB_REAL": json.RawMessage(`{"value":"ok"}`),
	}
	got := archiveToAppMap(archive, "KREEVA_WEB_")
	if _, bad := got[""]; bad {
		t.Error("empty env key must be skipped")
	}
	if got["REAL"] != "ok" || len(got) != 1 {
		t.Errorf("expected only REAL, got %v", got)
	}
}

// ---- multi-app dispatch ----

// multiAppFake records per-UUID calls and serves per-UUID current state.
type multiAppFake struct {
	current   map[string][]coolify.EnvEntry // uuid → current envs
	listErr   map[string]error              // uuid → injected list error
	upsertErr map[string]error              // uuid → injected upsert error
	upserts   map[string][]upsertCall       // uuid → upserts
	deletes   map[string][]deleteCall       // uuid → deletes
}

func newMultiAppFake() *multiAppFake {
	return &multiAppFake{
		current:   map[string][]coolify.EnvEntry{},
		listErr:   map[string]error{},
		upsertErr: map[string]error{},
		upserts:   map[string][]upsertCall{},
		deletes:   map[string][]deleteCall{},
	}
}

func (f *multiAppFake) ListAppEnvs(uuid string) ([]coolify.EnvEntry, error) {
	if err := f.listErr[uuid]; err != nil {
		return nil, err
	}
	return f.current[uuid], nil
}
func (f *multiAppFake) UpsertAppEnv(uuid, key, value string, isBuildtime bool) error {
	f.upserts[uuid] = append(f.upserts[uuid], upsertCall{key, value, isBuildtime})
	return f.upsertErr[uuid]
}
func (f *multiAppFake) DeleteAppEnv(uuid, envUUID string) error {
	f.deletes[uuid] = append(f.deletes[uuid], deleteCall{envUUID})
	return nil
}

// setupMultiApp writes an archive with multi-app keys + a coolify_sync block,
// and returns the fake + base opts pointing at it.
func setupMultiApp(t *testing.T, archive map[string]string, yamlCoolifySync string) (*multiAppFake, coolifyOptions) {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	yaml := "version: 1\nsources:\n  - type: file\n    path: .env.shared\n" + yamlCoolifySync
	if err := os.WriteFile(".wapps.yaml", []byte(yaml), 0644); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	envelope := make(map[string]json.RawMessage)
	for k, v := range archive {
		b, _ := json.Marshal(map[string]string{"value": v})
		envelope[k] = b
	}
	raw, _ := json.Marshal(envelope)
	if err := ageutil.EncryptWriteAtomic("secrets/all.enc.age", raw, pp); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fake := newMultiAppFake()
	opts := coolifyOptions{
		allApps:  true,
		apiToken: "tok",
		apiURL:   "http://unused",
		stdoutW:  &bytes.Buffer{},
		newClient: func(string, string) coolifyAPI { return fake },
	}
	return fake, opts
}

func TestRunSyncCoolifyAllApps_EachAppGetsOnlyItsSubset(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{
			"KREEVA_WEB_TOKEN": "kt",
			"ROYCO_API_DB":     "rdb",
			"lab_01_ipv4":      "1.2.3.4", // unmapped tofu output
		},
		`coolify_sync:
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
    - uuid: royco-uuid
      archive_prefix: "ROYCO_API_"
`)
	opts.force = true

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}

	// kreeva gets TOKEN (stripped), royco gets DB (stripped); lab_01_* nowhere.
	if len(fake.upserts["kreeva-uuid"]) != 1 || fake.upserts["kreeva-uuid"][0].key != "TOKEN" {
		t.Errorf("kreeva upserts wrong: %+v", fake.upserts["kreeva-uuid"])
	}
	if len(fake.upserts["royco-uuid"]) != 1 || fake.upserts["royco-uuid"][0].key != "DB" {
		t.Errorf("royco upserts wrong: %+v", fake.upserts["royco-uuid"])
	}
	// No app should ever receive the tofu output.
	for uuid, ups := range fake.upserts {
		for _, u := range ups {
			if strings.Contains(u.key, "ipv4") || strings.Contains(u.key, "lab_01") {
				t.Errorf("tofu output leaked to %s: %+v", uuid, u)
			}
		}
	}
}

func TestRunSyncCoolifyAllApps_DeleteUnmanagedFalse_NeverDeletes(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{"KREEVA_WEB_TOKEN": "kt"},
		`coolify_sync:
  delete_unmanaged: false
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
`)
	// Coolify has a key the archive doesn't — must NOT be deleted.
	fake.current["kreeva-uuid"] = []coolify.EnvEntry{{UUID: "x1", Key: "MANUAL_COOLIFY_KEY", Value: "v"}}
	opts.force = true

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}
	if len(fake.deletes["kreeva-uuid"]) != 0 {
		t.Errorf("delete_unmanaged=false must never delete, got: %+v", fake.deletes["kreeva-uuid"])
	}
}

func TestRunSyncCoolifyAllApps_DeleteUnmanagedTrue_DeletesCoolifyOnly(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{"KREEVA_WEB_TOKEN": "kt"},
		`coolify_sync:
  delete_unmanaged: true
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
`)
	fake.current["kreeva-uuid"] = []coolify.EnvEntry{{UUID: "x1", Key: "ORPHAN", Value: "v"}}
	opts.force = true

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}
	if len(fake.deletes["kreeva-uuid"]) != 1 || fake.deletes["kreeva-uuid"][0].envUUID != "x1" {
		t.Errorf("delete_unmanaged=true must delete orphan, got: %+v", fake.deletes["kreeva-uuid"])
	}
}

func TestRunSyncCoolifyAllApps_DryRunNoMutations(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{"KREEVA_WEB_TOKEN": "kt"},
		`coolify_sync:
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
`)
	opts.force = false

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}
	if len(fake.upserts["kreeva-uuid"]) != 0 {
		t.Errorf("dry-run must not upsert, got: %+v", fake.upserts["kreeva-uuid"])
	}
}

func TestRunSyncCoolifyAllApps_ZeroMatchSkipsApp(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{"ROYCO_API_DB": "v"}, // nothing matches KREEVA_WEB_
		`coolify_sync:
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
`)
	opts.force = true
	buf := &bytes.Buffer{}
	opts.stdoutW = buf

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}
	// App skipped → never listed, never mutated.
	if len(fake.upserts["kreeva-uuid"]) != 0 {
		t.Errorf("zero-match app should not be mutated")
	}
	if !strings.Contains(buf.String(), "0 keys matched") {
		t.Errorf("should warn about 0-key match, got: %q", buf.String())
	}
}

func TestRunSyncCoolifyAllApps_OneAppFails_OthersRun_NonZeroExit(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{"KREEVA_WEB_TOKEN": "kt", "ROYCO_API_DB": "rdb"},
		`coolify_sync:
  apps:
    - uuid: dead-uuid
      archive_prefix: "KREEVA_WEB_"
    - uuid: royco-uuid
      archive_prefix: "ROYCO_API_"
`)
	fake.listErr["dead-uuid"] = errors.New("HTTP 404")
	opts.force = true

	err := runSyncCoolify(opts)
	if err == nil {
		t.Fatal("expected non-zero exit when one app fails")
	}
	if !strings.Contains(err.Error(), "dead-uuid") {
		t.Errorf("error should name failed app, got: %v", err)
	}
	// The healthy app must still have been applied.
	if len(fake.upserts["royco-uuid"]) != 1 {
		t.Errorf("healthy app should still run despite sibling failure, got: %+v", fake.upserts["royco-uuid"])
	}
}

// TestRunSyncCoolifyAllApps_ApplyFailure_IsolatedAndIdempotentHint verifies
// that an apply error on one app (a) doesn't stop sibling apps, (b) yields a
// non-zero exit, and (c) prints the re-run/idempotent recovery hint.
func TestRunSyncCoolifyAllApps_ApplyFailure_IsolatedAndIdempotentHint(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{"KREEVA_WEB_TOKEN": "kt", "ROYCO_API_DB": "rdb"},
		`coolify_sync:
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
    - uuid: royco-uuid
      archive_prefix: "ROYCO_API_"
`)
	fake.upsertErr["kreeva-uuid"] = errors.New("coolify 500")
	opts.force = true
	buf := &bytes.Buffer{}
	opts.stdoutW = buf

	err := runSyncCoolify(opts)
	if err == nil || !strings.Contains(err.Error(), "kreeva-uuid") {
		t.Fatalf("expected non-zero exit naming failed app, got: %v", err)
	}
	// Sibling app still applied.
	if len(fake.upserts["royco-uuid"]) != 1 {
		t.Errorf("healthy app should still apply, got: %+v", fake.upserts["royco-uuid"])
	}
	// Operator told it's safe to re-run.
	if !strings.Contains(buf.String(), "idempotent") {
		t.Errorf("apply-failure message should mention idempotent re-run, got: %q", buf.String())
	}
}

func TestRunSyncCoolify_AppAndAllAppsMutuallyExclusive(t *testing.T) {
	_, opts := setupMultiApp(t, map[string]string{"X_Y": "v"},
		`coolify_sync:
  apps:
    - uuid: u
      archive_prefix: "X_"
`)
	opts.appUUID = "some-app"
	opts.allApps = true

	err := runSyncCoolify(opts)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual-exclusivity error, got: %v", err)
	}
}

func TestRunSyncCoolifyAllApps_NoAppsConfigured_Errors(t *testing.T) {
	_, opts := setupMultiApp(t, map[string]string{"X_Y": "v"}, "") // no coolify_sync block
	opts.force = false

	err := runSyncCoolify(opts)
	if err == nil || !strings.Contains(err.Error(), "no apps configured") {
		t.Errorf("expected 'no apps configured' error, got: %v", err)
	}
}
