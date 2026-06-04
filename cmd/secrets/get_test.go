package secrets

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

func setupEncryptedArchive(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	plaintext := []byte(`{"jwt_key":{"value":"abc-123","sensitive":true},"db_password":{"value":"pgpass","sensitive":true}}`)
	enc, err := ageutil.Encrypt(plaintext, "test-pass")
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(tmp, "all.enc.age")
	os.WriteFile(archivePath, enc, 0600)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test-pass")
	return archivePath
}

func TestGetReturnsSingleValue(t *testing.T) {
	archive := setupEncryptedArchive(t)
	val, err := readKey(archive, "jwt_key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "abc-123" {
		t.Errorf("Want abc-123, got %q", val)
	}
}

func TestGetMissingKeyError(t *testing.T) {
	archive := setupEncryptedArchive(t)
	_, err := readKey(archive, "nonexistent")
	if err == nil {
		t.Errorf("Expected error for missing key")
	}
}

// setupMixedArchive seeds an archive that mixes a string value, an array value
// (the real-world vaulter_traefik_cert_paths shape), and an import-env-style
// plain string secret. Returns the absolute archive path.
func setupMixedArchive(t *testing.T) string {
	t.Helper()
	plaintext := []byte(`{
		"jwt_key": {"value":"abc-123","sensitive":true},
		"vaulter_traefik_cert_paths": {"value":["/c/a.crt","/c/b.crt"],"type":["tuple"]},
		"LUMIRA_REVENUECAT_WEBHOOK_SECRET": {"value":"whsec_live_xyz"}
	}`)
	enc, err := ageutil.Encrypt(plaintext, "test-pass")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "all.enc.age")
	if err := os.WriteFile(archivePath, enc, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test-pass")
	return archivePath
}

// Regression for BUG-secrets-read-broken #1: get must NOT crash when a
// different key in the archive holds an array value. Before the fix, readKey
// unmarshaled the whole archive into a value-is-string struct and failed
// before ever reaching the requested string key.
func TestGet_StringKeyWithArrayKeyPresent(t *testing.T) {
	archive := setupMixedArchive(t)

	// The import-env'd plain string secret reads cleanly...
	got, err := readKey(archive, "LUMIRA_REVENUECAT_WEBHOOK_SECRET")
	if err != nil {
		t.Fatalf("readKey crashed on archive containing an array value: %v", err)
	}
	if got != "whsec_live_xyz" {
		t.Errorf("got %q, want whsec_live_xyz", got)
	}

	// ...and an ordinary string key still works.
	if got, _ := readKey(archive, "jwt_key"); got != "abc-123" {
		t.Errorf("jwt_key = %q, want abc-123", got)
	}
}

// get on an array-valued key returns its compact JSON (not a crash, not empty).
func TestGet_ArrayKeyReturnsCompactJSON(t *testing.T) {
	archive := setupMixedArchive(t)
	got, err := readKey(archive, "vaulter_traefik_cert_paths")
	if err != nil {
		t.Fatalf("readKey on array key: %v", err)
	}
	if got != `["/c/a.crt","/c/b.crt"]` {
		t.Errorf("array value = %q, want compact JSON array", got)
	}
}

// Regression for BUG-secrets-read-broken #2 (clarifying the misdiagnosis):
// exec/env read the archive DIRECTLY, so an import-env'd key IS injected — it
// just carries the default TF_VAR_ prefix. Proves the key isn't "dropped".
func TestExec_IncludesImportEnvKeyWithPrefix(t *testing.T) {
	archive := setupMixedArchive(t)
	dec, err := decryptArchiveAt(t, archive)
	if err != nil {
		t.Fatal(err)
	}
	withPrefix, err := buildExecEnv(dec, "TF_VAR_")
	if err != nil {
		t.Fatalf("buildExecEnv: %v", err)
	}
	if !containsEnv(withPrefix, "TF_VAR_LUMIRA_REVENUECAT_WEBHOOK_SECRET=whsec_live_xyz") {
		t.Errorf("import-env'd key missing under default prefix; env=%v", withPrefix)
	}
	// With an empty prefix it's the bare name (what the operator expected).
	plain, _ := buildExecEnv(dec, "")
	if !containsEnv(plain, "LUMIRA_REVENUECAT_WEBHOOK_SECRET=whsec_live_xyz") {
		t.Errorf("import-env'd key missing under empty prefix; env=%v", plain)
	}
}

// rawValueToString edge cases: null and a value-less envelope must return ""
// (legacy parity), never a raw JSON blob — important for `get` not printing
// envelope internals to stdout.
func TestRawValueToString_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"hello"`, "hello"},
		{"null", `null`, ""},
		{"absent (empty raw)", ``, ""},
		{"array", `["a","b"]`, `["a","b"]`},
		{"number", `42`, "42"},
		{"bool", `true`, "true"},
		{"object", `{"k":"v"}`, `{"k":"v"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rawValueToString(json.RawMessage(c.raw)); got != c.want {
				t.Errorf("rawValueToString(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func decryptArchiveAt(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	enc, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ageutil.Decrypt(enc, "test-pass")
}

func containsEnv(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}

func TestListReturnsAllNames(t *testing.T) {
	archive := setupEncryptedArchive(t)
	buf := &bytes.Buffer{}
	if err := listKeys(archive, buf); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, want := range []string{"jwt_key", "db_password"} {
		if !strings.Contains(output, want) {
			t.Errorf("List missing %q in:\n%s", want, output)
		}
	}
}
