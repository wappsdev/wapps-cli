package secrets

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

func TestRunImportEnv_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	yaml := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`)
	if err := os.WriteFile(".wapps.yaml", yaml, 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Pre-populate archive with one key so we can verify import MERGES rather
	// than replaces.
	pre := map[string]json.RawMessage{
		"EXISTING": json.RawMessage(`{"value":"keep"}`),
	}
	preRaw, _ := json.Marshal(pre)
	preEnc, _ := ageutil.Encrypt(preRaw, pp)
	if err := os.WriteFile("secrets/all.enc.age", preEnc, 0600); err != nil {
		t.Fatalf("write pre-archive: %v", err)
	}

	// Input env file.
	input := []byte(`
# comment lines are skipped
STRIPE_KEY=sk_test_xyz
DB_PASSWORD="hunter2"
export OAUTH_CLIENT=client123
`)
	if err := os.WriteFile("import.env", input, 0644); err != nil {
		t.Fatalf("write import: %v", err)
	}

	err := runImportEnv("import.env", func(k string) string {
		if k == "WAPPS_SECRETS_PASSPHRASE" {
			return pp
		}
		return ""
	})
	if err != nil {
		t.Fatalf("runImportEnv: %v", err)
	}

	// Decrypt + verify all 4 keys present (1 pre-existing + 3 imported).
	enc, _ := os.ReadFile("secrets/all.enc.age")
	dec, _ := ageutil.Decrypt(enc, pp)
	var archive map[string]json.RawMessage
	if err := json.Unmarshal(dec, &archive); err != nil {
		t.Fatalf("parse archive: %v", err)
	}
	wantKeys := []string{"EXISTING", "STRIPE_KEY", "DB_PASSWORD", "OAUTH_CLIENT"}
	for _, k := range wantKeys {
		if _, ok := archive[k]; !ok {
			t.Errorf("missing %s after import", k)
		}
	}
	if string(archive["EXISTING"]) != `{"value":"keep"}` {
		t.Errorf("EXISTING was clobbered: %s", archive["EXISTING"])
	}
	if string(archive["STRIPE_KEY"]) != `{"value":"sk_test_xyz"}` {
		t.Errorf("STRIPE_KEY envelope: %s", archive["STRIPE_KEY"])
	}
}

func TestRunImportEnv_RequiresWappsYAML(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	if err := os.WriteFile("any.env", []byte("FOO=bar\n"), 0644); err != nil {
		t.Fatalf("write env: %v", err)
	}

	err := runImportEnv("any.env", func(string) string { return "x" })
	if err == nil {
		t.Fatal("expected error: import-env requires .wapps.yaml")
	}
	if !strings.Contains(err.Error(), ".wapps.yaml") {
		t.Errorf("error should mention .wapps.yaml, got: %v", err)
	}
}

func TestRunImportEnv_RejectsMalformedFile(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test")

	if err := os.WriteFile(".wapps.yaml", []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile("broken.env", []byte("VALID=ok\nMISSING_EQUALS_SIGN\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := runImportEnv("broken.env", os.Getenv)
	if err == nil {
		t.Fatal("expected error on malformed env")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error should pinpoint bad line, got: %v", err)
	}
}

func TestRunImportEnv_MissingFile(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test")

	if err := os.WriteFile(".wapps.yaml", []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	err := runImportEnv("nope.env", os.Getenv)
	if err == nil {
		t.Fatal("expected error: input file missing")
	}
}

func TestRunImportEnv_EmptyFileNoOpButNoError(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "test"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	if err := os.WriteFile(".wapps.yaml", []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile("blank.env", []byte("# only comments\n\n# blank\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := runImportEnv("blank.env", func(k string) string {
		if k == "WAPPS_SECRETS_PASSPHRASE" {
			return pp
		}
		return ""
	})
	if err != nil {
		t.Errorf("empty-keys file should NOT error, got: %v", err)
	}
}
