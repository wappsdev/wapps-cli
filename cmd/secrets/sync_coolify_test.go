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
`), 0o644); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if err := os.MkdirAll("secrets", 0o755); err != nil {
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
	fake, opts := setupCoolifyTest(
		t,
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
	fake, opts := setupCoolifyTest(
		t,
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
	diff := computeCoolifyDiff(map[string]string{}, nil, true, nil)
	if len(diff.add)+len(diff.change)+len(diff.remove)+len(diff.noop) != 0 {
		t.Errorf("expected fully empty diff, got %+v", diff)
	}
}

func TestComputeCoolifyDiff_PureAdd(t *testing.T) {
	diff := computeCoolifyDiff(map[string]string{"FOO": "bar"}, nil, true, nil)
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
		nil,
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
		nil,
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
		nil,
	)
	if len(diff.change) != 1 || diff.change["A"].newValue != "new" {
		t.Errorf("change: %v", diff.change)
	}
	if len(diff.noop) != 1 || diff.noop[0] != "B" {
		t.Errorf("noop: %v", diff.noop)
	}
}

// TestComputeCoolifyDiff_SkipsCoolifyManaged is the ADDENDUM core: an
// is_coolify=true env must never appear in add/change/remove, even when the
// archive carries a stale copy of it (which would otherwise become a change
// or, after filtering current, a spurious add).
func TestComputeCoolifyDiff_SkipsCoolifyManaged(t *testing.T) {
	diff := computeCoolifyDiff(
		// archive has a stale copy of the managed key + a real one
		map[string]string{"SERVICE_URL_API": "https://stale", "REAL": "v"},
		[]coolify.EnvEntry{
			{UUID: "u1", Key: "SERVICE_URL_API", Value: "https://live", IsCoolify: true},
			{UUID: "u2", Key: "REAL", Value: "old"},
		},
		true, // even with destructive mode on
		nil,
	)
	if _, bad := diff.change["SERVICE_URL_API"]; bad {
		t.Error("managed key must not be a change")
	}
	if _, bad := diff.add["SERVICE_URL_API"]; bad {
		t.Error("stale archive copy of a managed key must not become an add")
	}
	if _, bad := diff.remove["SERVICE_URL_API"]; bad {
		t.Error("managed key must not be removed even under delete_unmanaged")
	}
	if diff.skippedManaged != 1 {
		t.Errorf("skippedManaged should be 1, got %d", diff.skippedManaged)
	}
	// The real key still diffs normally.
	if diff.change["REAL"].newValue != "v" {
		t.Errorf("real key should still change: %v", diff.change)
	}
}

// TestComputeCoolifyDiff_ManagedCoolifyOnly_NotRemoved covers the case the
// ADDENDUM calls out: a managed key that exists ONLY on Coolify (not in the
// archive) must not be removed under delete_unmanaged=true.
func TestComputeCoolifyDiff_ManagedCoolifyOnly_NotRemoved(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"REAL": "v"},
		[]coolify.EnvEntry{
			{UUID: "u1", Key: "SERVICE_FQDN_API", Value: "x.sslip.io", IsCoolify: true},
			{UUID: "u2", Key: "REAL", Value: "v"},
		},
		true,
		nil,
	)
	if len(diff.remove) != 0 {
		t.Errorf("managed Coolify-only key must not be removed, got: %v", diff.remove)
	}
	if diff.skippedManaged != 1 {
		t.Errorf("skippedManaged should be 1, got %d", diff.skippedManaged)
	}
}

// TestComputeCoolifyDiff_SkipsPreviewDuplicate is ADDENDUM 2: Coolify returns
// the same key twice (runtime is_preview=false + preview is_preview=true) with
// different values. The diff must compare the archive against the RUNTIME
// value, not the preview value — otherwise every preview-dup key shows
// perpetual false drift.
func TestComputeCoolifyDiff_SkipsPreviewDuplicate(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"DATABASE_URL": "runtime-val"}, // archive = runtime value
		[]coolify.EnvEntry{
			{UUID: "r1", Key: "DATABASE_URL", Value: "runtime-val", IsPreview: false},
			{UUID: "p1", Key: "DATABASE_URL", Value: "preview-val", IsPreview: true},
		},
		true,
		nil,
	)
	if len(diff.change) != 0 {
		t.Errorf("preview dup must not cause a change (runtime matches), got: %v", diff.change)
	}
	if len(diff.noop) != 1 || diff.noop[0] != "DATABASE_URL" {
		t.Errorf("runtime entry should noop, got: %+v", diff.noop)
	}
	if diff.skippedPreview != 1 {
		t.Errorf("skippedPreview should be 1, got %d", diff.skippedPreview)
	}
}

// TestComputeCoolifyDiff_PreviewDupOrderIndependent guards the original bug:
// the naive last-write-wins map made the result depend on Coolify's return
// order. With the preview filter, the runtime entry wins regardless of order.
func TestComputeCoolifyDiff_PreviewDupOrderIndependent(t *testing.T) {
	for _, order := range [][]coolify.EnvEntry{
		{{Key: "K", Value: "rt", IsPreview: false}, {Key: "K", Value: "pv", IsPreview: true}},
		{{Key: "K", Value: "pv", IsPreview: true}, {Key: "K", Value: "rt", IsPreview: false}},
	} {
		diff := computeCoolifyDiff(map[string]string{"K": "rt"}, order, true, nil)
		if len(diff.change) != 0 {
			t.Errorf("order %v: runtime matches, expected no change, got %v", order, diff.change)
		}
	}
}

// TestComputeCoolifyDiff_PreviewOnlyKeyAbsentFromCurrent: a key existing ONLY
// as a preview entry is treated as absent from current — so if the archive
// has it, it's an add (a runtime env we should create), not a comparison
// against the preview value.
func TestComputeCoolifyDiff_PreviewOnlyKeyAbsentFromCurrent(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"PREVIEW_ONLY": "v"},
		[]coolify.EnvEntry{{UUID: "p1", Key: "PREVIEW_ONLY", Value: "other", IsPreview: true}},
		true,
		nil,
	)
	if _, ok := diff.add["PREVIEW_ONLY"]; !ok {
		t.Errorf("preview-only key should be absent from current → add, got: %+v", diff)
	}
	if len(diff.change) != 0 {
		t.Errorf("must not compare against preview value, got: %v", diff.change)
	}
}

// TestComputeCoolifyDiff_ExcludeKeys drops deny-listed keys from both sides
// and counts the exclusion only when it actually matched something.
func TestComputeCoolifyDiff_ExcludeKeys(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"SENTRY_RELEASE": "v2", "REAL": "v"},
		[]coolify.EnvEntry{
			{UUID: "u1", Key: "SENTRY_RELEASE", Value: "v1"}, // would be a change
			{UUID: "u2", Key: "REAL", Value: "v"},
		},
		true,
		map[string]bool{"SENTRY_RELEASE": true, "NEVER_PRESENT": true},
	)
	if _, bad := diff.change["SENTRY_RELEASE"]; bad {
		t.Error("excluded key must not be a change")
	}
	// Only SENTRY_RELEASE actually matched; NEVER_PRESENT shouldn't inflate count.
	if diff.skippedExcluded != 1 {
		t.Errorf("skippedExcluded should be 1 (only matched keys count), got %d", diff.skippedExcluded)
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
		"ROYCO_API_DB":            json.RawMessage(`{"value":"pg"}`),      // other app
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
	if err := os.WriteFile(".wapps.yaml", []byte(yaml), 0o644); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if err := os.MkdirAll("secrets", 0o755); err != nil {
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
		allApps:   true,
		apiToken:  "tok",
		apiURL:    "http://unused",
		stdoutW:   &bytes.Buffer{},
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

// TestRunSyncCoolifyAllApps_SkipsManagedAndExcluded is the end-to-end check:
// a managed (is_coolify) key and an exclude_keys entry are never upserted,
// even with --force.
func TestRunSyncCoolifyAllApps_SkipsManagedAndExcluded(t *testing.T) {
	fake, opts := setupMultiApp(t,
		map[string]string{
			"KREEVA_WEB_SERVICE_URL_API": "https://stale", // managed (live), stale archive copy
			"KREEVA_WEB_SENTRY_RELEASE":  "abc123",        // excluded
			"KREEVA_WEB_REAL":            "v",             // genuine
		},
		`coolify_sync:
  exclude_keys:
    - SENTRY_RELEASE
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
`)
	fake.current["kreeva-uuid"] = []coolify.EnvEntry{
		{UUID: "c1", Key: "SERVICE_URL_API", Value: "https://live", IsCoolify: true},
	}
	opts.force = true
	buf := &bytes.Buffer{}
	opts.stdoutW = buf

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify: %v", err)
	}

	for _, u := range fake.upserts["kreeva-uuid"] {
		if u.key == "SERVICE_URL_API" {
			t.Error("managed key was upserted (should be skipped)")
		}
		if u.key == "SENTRY_RELEASE" {
			t.Error("excluded key was upserted (should be skipped)")
		}
	}
	// REAL is the only genuine push.
	if len(fake.upserts["kreeva-uuid"]) != 1 || fake.upserts["kreeva-uuid"][0].key != "REAL" {
		t.Errorf("only REAL should be pushed, got: %+v", fake.upserts["kreeva-uuid"])
	}
	out := buf.String()
	if !strings.Contains(out, "Coolify-managed") {
		t.Errorf("should report skipped managed keys, got: %q", out)
	}
	if !strings.Contains(out, "excluded") {
		t.Errorf("should report skipped excluded keys, got: %q", out)
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

// ---- backend:store source (P1.6) ----

// TestRunSyncCoolify_StoreBackend_PushesStoreValues, P1.6'nın çekirdeği:
// backend:store'da arşiv/passphrase OLMADAN değerler fake store'dan çekilir ve
// mevcut diff/push makinesiyle Coolify'a itilir. WAPPS_SECRETS_PASSPHRASE boş —
// store yolu onu ASLA istememeli (retirement günü kırılmaması bunun kanıtı).
func TestRunSyncCoolify_StoreBackend_PushesStoreValues(t *testing.T) {
	setupStoreProject(t, "")
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "") // store yolu passphrase istememeli
	f := installFakeStore(t)
	f.values["DB_PASSWORD"] = "new-value" // CHANGE
	f.values["NEW_KEY"] = "v"             // ADD

	fake := &fakeCoolify{listResult: []coolify.EnvEntry{
		{UUID: "e1", Key: "DB_PASSWORD", Value: "old-value"},
		{UUID: "e2", Key: "STALE", Value: "x"},
	}}
	opts := coolifyOptions{
		appUUID:   "app-1",
		apiToken:  "tok",
		apiURL:    "http://unused",
		force:     true,
		stdoutW:   &bytes.Buffer{},
		newClient: func(string, string) coolifyAPI { return fake },
	}

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify (store): %v", err)
	}
	// Değerler store'dan TEK bulk Read ile gelmiş olmalı (tüm okunabilir küme).
	if len(f.readCalls) != 1 {
		t.Fatalf("store Read should be called exactly once, got %d", len(f.readCalls))
	}
	if f.readCalls[0].project != "testproj" {
		t.Errorf("Read project: got %q, want testproj", f.readCalls[0].project)
	}
	if len(f.readCalls[0].keys) != 0 {
		t.Errorf("coolify sync must bulk-read the full set, got keys %v", f.readCalls[0].keys)
	}
	// Mevcut diff makinesi AYNEN çalışmalı: 2 upsert (add+change) + 1 delete (mirror).
	if len(fake.upserts) != 2 {
		t.Fatalf("expected 2 upserts, got %d: %+v", len(fake.upserts), fake.upserts)
	}
	got := map[string]string{}
	for _, u := range fake.upserts {
		got[u.key] = u.value
	}
	if got["DB_PASSWORD"] != "new-value" || got["NEW_KEY"] != "v" {
		t.Errorf("store values must feed the push unchanged, got: %v", got)
	}
	if len(fake.deletes) != 1 || fake.deletes[0].envUUID != "e2" {
		t.Errorf("single-app mirror must still delete STALE (e2), got: %+v", fake.deletes)
	}
	// Store yolunda diskte arşiv OLUŞMAMALI.
	if _, statErr := os.Stat("secrets/all.enc.age"); !os.IsNotExist(statErr) {
		t.Error("store-backed coolify sync must not touch a legacy archive")
	}
}

// Store okuma hatası (örn. SESSION_EXPIRED) → Coolify istemcisi HİÇ kurulmaz,
// hata aynen yüzer (ağ'a/coolify API'sine çıkılmadan fail-fast).
func TestRunSyncCoolify_StoreBackend_ReadErrorStopsBeforeCoolify(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.readErr = errors.New("SESSION_EXPIRED: no valid CF Access session")

	clientBuilt := false
	opts := coolifyOptions{
		appUUID:  "app-1",
		apiToken: "tok",
		apiURL:   "http://unused",
		force:    true,
		stdoutW:  &bytes.Buffer{},
		newClient: func(string, string) coolifyAPI {
			clientBuilt = true
			return &fakeCoolify{}
		},
	}

	err := runSyncCoolify(opts)
	if err == nil || !strings.Contains(err.Error(), "SESSION_EXPIRED") {
		t.Fatalf("store read error must propagate, got: %v", err)
	}
	if clientBuilt {
		t.Error("Coolify client must not be built when the store read fails")
	}
}

// Multi-app (--all-apps) store yolunda da coolify_sync.apps archive_prefix
// semantiği AYNEN korunur: her app yalnızca kendi prefix'inin soyulmuş alt
// kümesini alır (lab 13-app senaryosunun birim eşleniği).
func TestRunSyncCoolifyAllApps_StoreBackend_PrefixStripPreserved(t *testing.T) {
	setupStoreProject(t, `coolify_sync:
  apps:
    - uuid: kreeva-uuid
      archive_prefix: "KREEVA_WEB_"
    - uuid: royco-uuid
      archive_prefix: "ROYCO_API_"
`)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "")
	f := installFakeStore(t)
	f.values["KREEVA_WEB_TOKEN"] = "kt"
	f.values["ROYCO_API_DB"] = "rdb"
	f.values["lab_01_ipv4"] = "1.2.3.4" // eşleşmeyen tofu çıktısı — hiçbir app'e gitmemeli

	fake := newMultiAppFake()
	opts := coolifyOptions{
		allApps:   true,
		apiToken:  "tok",
		apiURL:    "http://unused",
		force:     true,
		stdoutW:   &bytes.Buffer{},
		newClient: func(string, string) coolifyAPI { return fake },
	}

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("runSyncCoolify (store, all-apps): %v", err)
	}
	if len(fake.upserts["kreeva-uuid"]) != 1 || fake.upserts["kreeva-uuid"][0].key != "TOKEN" {
		t.Errorf("kreeva upserts wrong: %+v", fake.upserts["kreeva-uuid"])
	}
	if len(fake.upserts["royco-uuid"]) != 1 || fake.upserts["royco-uuid"][0].key != "DB" {
		t.Errorf("royco upserts wrong: %+v", fake.upserts["royco-uuid"])
	}
	for uuid, ups := range fake.upserts {
		for _, u := range ups {
			if strings.Contains(u.key, "lab_01") || strings.Contains(u.key, "ipv4") {
				t.Errorf("tofu output leaked to %s: %+v", uuid, u)
			}
		}
	}
}

// Legacy (backend yok) coolify sync store'a ASLA gitmez — arşiv+passphrase yolu
// byte-for-byte korunur (fake store kurulu olsa bile Read çağrılmaz).
func TestRunSyncCoolify_LegacyBackend_DoesNotRouteToStore(t *testing.T) {
	_, opts := setupCoolifyTest(
		t,
		map[string]string{"DB_PASSWORD": "secret"},
		[]coolify.EnvEntry{{UUID: "e1", Key: "DB_PASSWORD", Value: "old"}},
	)
	f := installFakeStore(t)
	opts.force = false // dry-run yeterli — yönlendirme kanıtı Read sayısında

	if err := runSyncCoolify(opts); err != nil {
		t.Fatalf("legacy runSyncCoolify: %v", err)
	}
	if len(f.readCalls) != 0 {
		t.Fatalf("legacy coolify sync must NOT route to the store; reads=%d", len(f.readCalls))
	}
}
