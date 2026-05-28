package secrets

import (
	"encoding/json"
	"errors"
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
	diff := computeCoolifyDiff(map[string]string{}, nil)
	if len(diff.add)+len(diff.change)+len(diff.remove)+len(diff.noop) != 0 {
		t.Errorf("expected fully empty diff, got %+v", diff)
	}
}

func TestComputeCoolifyDiff_PureAdd(t *testing.T) {
	diff := computeCoolifyDiff(map[string]string{"FOO": "bar"}, nil)
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
	)
	if len(diff.remove) != 1 || diff.remove["GONE"] != "u1" {
		t.Errorf("remove: %v", diff.remove)
	}
}

func TestComputeCoolifyDiff_ChangeAndNoop(t *testing.T) {
	diff := computeCoolifyDiff(
		map[string]string{"A": "new", "B": "same"},
		[]coolify.EnvEntry{{UUID: "u1", Key: "A", Value: "old"}, {UUID: "u2", Key: "B", Value: "same"}},
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
		change: map[string]coolifyChange{"EXISTING": {oldValue: "o", newValue: "n"}},
		remove: map[string]string{"GONE": "u1"},
	}
	if err := applyCoolifyDiff(fake, "app-1", diff); err != nil {
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
	err := applyCoolifyDiff(fake, "app", diff)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	// First add should have been attempted, but flow stops there.
	if len(fake.upserts) > 1 {
		t.Errorf("should stop on first failure, got %d attempts", len(fake.upserts))
	}
}
