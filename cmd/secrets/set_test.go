package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// happyPathPrompt returns a fixed value, simulating a successful TTY read.
func happyPathPrompt(val string) func(string) (string, bool, error) {
	return func(prompt string) (string, bool, error) {
		return val, true, nil
	}
}

func cleanDrift(string) (bool, error)  { return false, nil }
func dirtyDrift(string) (bool, error)  { return true, nil }
func driftErr(string) (bool, error)    { return false, errors.New("git fetch failed") }

func setUpSetTestRepo(t *testing.T, opts struct {
	yamlContent  string
	envContent   string
	archiveSeed  map[string]string // KEY → VALUE; seeded into archive before set
	passphrase   string
}) string {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	if opts.passphrase == "" {
		opts.passphrase = "test-pp"
	}
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", opts.passphrase)

	if opts.yamlContent != "" {
		if err := os.WriteFile(".wapps.yaml", []byte(opts.yamlContent), 0644); err != nil {
			t.Fatalf("write yaml: %v", err)
		}
	}
	if opts.envContent != "" {
		if err := os.WriteFile(".env.shared", []byte(opts.envContent), 0644); err != nil {
			t.Fatalf("write env: %v", err)
		}
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	if opts.archiveSeed != nil {
		envelope := make(map[string]json.RawMessage)
		for k, v := range opts.archiveSeed {
			b, _ := json.Marshal(map[string]string{"value": v})
			envelope[k] = b
		}
		raw, _ := json.Marshal(envelope)
		enc, err := ageutil.Encrypt(raw, opts.passphrase)
		if err != nil {
			t.Fatalf("encrypt seed: %v", err)
		}
		if err := os.WriteFile("secrets/all.enc.age", enc, 0600); err != nil {
			t.Fatalf("write seed archive: %v", err)
		}
	}
	return tmp
}

func TestRunSet_HappyPath_FirstSet(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
	})

	err := runSet("DB_PASSWORD", setOptions{
		promptValue: happyPathPrompt("hunter2"),
		driftCheck:  cleanDrift,
	})
	if err != nil {
		t.Fatalf("runSet: %v", err)
	}

	// Archive should contain the key.
	enc, err := os.ReadFile("secrets/all.enc.age")
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	dec, err := ageutil.Decrypt(enc, "test-pp")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var archive map[string]json.RawMessage
	if err := json.Unmarshal(dec, &archive); err != nil {
		t.Fatalf("parse archive: %v", err)
	}
	if string(archive["DB_PASSWORD"]) != `{"value":"hunter2"}` {
		t.Errorf("archive DB_PASSWORD = %s, want envelope", archive["DB_PASSWORD"])
	}

	// File source should also contain it, with header.
	envFile, err := os.ReadFile(".env.shared")
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	content := string(envFile)
	if !strings.HasPrefix(content, "# wapps-managed") {
		t.Errorf("file source missing header:\n%s", content)
	}
	if !strings.Contains(content, "DB_PASSWORD='hunter2'") {
		t.Errorf("file source missing DB_PASSWORD line:\n%s", content)
	}
}

func TestRunSet_PreservesExistingKeys(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
		envContent:  "STRIPE_KEY=sk_test\nDB_PASSWORD=old\n",
		archiveSeed: map[string]string{"STRIPE_KEY": "sk_test", "DB_PASSWORD": "old"},
	})

	// Update DB_PASSWORD via set
	err := runSet("DB_PASSWORD", setOptions{
		promptValue: happyPathPrompt("new-rotated"),
		driftCheck:  cleanDrift,
	})
	if err != nil {
		t.Fatalf("runSet: %v", err)
	}

	envFile, _ := os.ReadFile(".env.shared")
	content := string(envFile)
	if !strings.Contains(content, "STRIPE_KEY='sk_test'") {
		t.Errorf("STRIPE_KEY lost from file source:\n%s", content)
	}
	if !strings.Contains(content, "DB_PASSWORD='new-rotated'") {
		t.Errorf("DB_PASSWORD not updated:\n%s", content)
	}
	if strings.Contains(content, "DB_PASSWORD='old'") {
		t.Errorf("old DB_PASSWORD value not replaced:\n%s", content)
	}
}

func TestRunSet_RequiresWappsYAML(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test")

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  cleanDrift,
	})
	if err == nil {
		t.Fatal("expected error: set requires .wapps.yaml")
	}
	if !strings.Contains(err.Error(), ".wapps.yaml") {
		t.Errorf("error should mention .wapps.yaml, got: %v", err)
	}
}

func TestRunSet_ErrorOnZeroFileSources(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: tofu
`,
	})

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  cleanDrift,
	})
	if err == nil {
		t.Fatal("expected error: no file source")
	}
	if !strings.Contains(err.Error(), "no file source") {
		t.Errorf("error should explain no file source, got: %v", err)
	}
}

func TestRunSet_ErrorOnMultipleFileSources(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
  - type: file
    path: .env.local
`,
	})

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  cleanDrift,
	})
	if err == nil {
		t.Fatal("expected error: multiple file sources")
	}
	if !strings.Contains(err.Error(), "multiple file sources") {
		t.Errorf("error should explain ambiguity, got: %v", err)
	}
}

func TestRunSet_RefusesOnDirtyDrift(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
	})

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  dirtyDrift,
	})
	if err == nil {
		t.Fatal("expected error on dirty drift")
	}
	if !strings.Contains(err.Error(), "drift") && !strings.Contains(err.Error(), "git pull") {
		t.Errorf("error should mention drift/git pull, got: %v", err)
	}
}

func TestRunSet_PropagatesDriftCheckError(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
	})

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  driftErr,
	})
	if err == nil {
		t.Fatal("expected drift preflight error")
	}
	if !strings.Contains(err.Error(), "drift preflight") {
		t.Errorf("error should label preflight failure, got: %v", err)
	}
}

func TestRunSet_RequiresPassphrase(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
	})
	os.Unsetenv("WAPPS_SECRETS_PASSPHRASE")

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  cleanDrift,
	})
	if err == nil {
		t.Fatal("expected error when passphrase missing")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Errorf("error should name env var, got: %v", err)
	}
}

func TestRunSet_RejectsEmptyValue(t *testing.T) {
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
	})

	err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt(""),
		driftCheck:  cleanDrift,
	})
	if err == nil {
		t.Fatal("expected error on empty value")
	}
	if !strings.Contains(err.Error(), "empty value") {
		t.Errorf("error should mention empty value, got: %v", err)
	}
}

func TestRunSet_EmptyKeyArgument(t *testing.T) {
	// Cobra normally enforces ExactArgs(1); this guards the runSet entry
	// against an empty string slipping through (e.g., from a test or refactor).
	err := runSet("", setOptions{
		promptValue: happyPathPrompt("x"),
		driftCheck:  cleanDrift,
	})
	if err == nil {
		t.Fatal("expected error on empty KEY")
	}
}

func TestRunSet_ArchiveAtomicity(t *testing.T) {
	// After a successful set, only the final archive should exist — no .tmp
	// leftovers from the temp+rename dance.
	setUpSetTestRepo(t, struct {
		yamlContent  string
		envContent   string
		archiveSeed  map[string]string
		passphrase   string
	}{
		yamlContent: `
version: 1
sources:
  - type: file
    path: .env.shared
`,
	})

	if err := runSet("FOO", setOptions{
		promptValue: happyPathPrompt("bar"),
		driftCheck:  cleanDrift,
	}); err != nil {
		t.Fatalf("runSet: %v", err)
	}

	tmpPath := filepath.Join("secrets", "all.enc.age.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file %s should not persist after successful write", tmpPath)
	}
	envTmp := ".env.shared.tmp"
	if _, err := os.Stat(envTmp); !os.IsNotExist(err) {
		t.Errorf("file source temp %s should not persist", envTmp)
	}
}
