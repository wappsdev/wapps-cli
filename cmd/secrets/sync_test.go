package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

func TestRunSync_LegacyPath_NoWappsYAML(t *testing.T) {
	// chdir to a temp dir with NO .wapps.yaml — runSync should fall back to
	// the legacy tofu-only path. Since we can't easily inject tofu.Output here,
	// we just verify that without the required env, preflight fails as expected
	// (which proves we took the legacy branch).
	tmp := t.TempDir()
	t.Chdir(tmp)

	err := runSync(context.Background(), func(string) string { return "" })
	if err == nil {
		t.Fatal("expected preflight error in legacy path with empty env")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected legacy preflight error, got: %v", err)
	}
}

func TestRunSync_ConfigPath_FileOnlyNoTofuPreflight(t *testing.T) {
	// vaulter-api scenario: file source only, no tofu. Preflight should NOT
	// fire (empty env is OK) and runSync should produce an encrypted archive
	// from the .env.shared file alone.
	tmp := t.TempDir()
	t.Chdir(tmp)

	yaml := []byte(`
version: 1
dest: secrets/all.enc.age
sources:
  - type: file
    path: .env.shared
`)
	if err := os.WriteFile(".wapps.yaml", yaml, 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile(".env.shared", []byte("STRIPE_KEY=sk_test\nDB_PASSWORD=hunter2\n"), 0644); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	envMap := map[string]string{
		"WAPPS_SECRETS_PASSPHRASE": "test-pp-123",
	}
	err := runSync(context.Background(), func(k string) string { return envMap[k] })
	if err != nil {
		t.Fatalf("runSync should succeed with file-only config, got: %v", err)
	}

	// Verify archive contents.
	enc, err := os.ReadFile("secrets/all.enc.age")
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	dec, err := ageutil.Decrypt(enc, "test-pp-123")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(dec, &got); err != nil {
		t.Fatalf("parse archive json: %v\nraw: %s", err, dec)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 keys in archive, got %d: %v", len(got), got)
	}
	if string(got["STRIPE_KEY"]) != `{"value":"sk_test"}` {
		t.Errorf("STRIPE_KEY envelope wrong: %s", got["STRIPE_KEY"])
	}
}

func TestRunSync_ConfigPath_TofuSourceRequiresPreflight(t *testing.T) {
	// vaulter scenario: tofu source present → preflight must fire and demand
	// AWS_*/TF_VAR_state_passphrase even though we never actually call tofu.
	tmp := t.TempDir()
	t.Chdir(tmp)

	yaml := []byte(`
version: 1
sources:
  - type: tofu
`)
	if err := os.WriteFile(".wapps.yaml", yaml, 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	err := runSync(context.Background(), func(string) string { return "" })
	if err == nil {
		t.Fatal("expected preflight error when tofu source declared with empty env")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected preflight to demand AWS_ACCESS_KEY_ID, got: %v", err)
	}
}

func TestRunSync_ConfigPath_RejectsBadYAML(t *testing.T) {
	// Broken .wapps.yaml should fail loudly, NOT silently fall back to legacy.
	// Silent fallback would overwrite a good archive with the wrong sources.
	tmp := t.TempDir()
	t.Chdir(tmp)
	if err := os.WriteFile(".wapps.yaml", []byte("version: 1\nsources:\n  - type: doppler\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	err := runSync(context.Background(), func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error on bad source type")
	}
	if !strings.Contains(err.Error(), "doppler") {
		t.Errorf("error should pinpoint bad type, got: %v", err)
	}
}

// hasTofuSource's dispatch behavior is covered end-to-end by
// TestRunSync_ConfigPath_FileOnlyNoTofuPreflight (file-only → no preflight)
// and TestRunSync_ConfigPath_TofuSourceRequiresPreflight (tofu → preflight),
// so a separate unit test would be redundant.

func TestPreflightTofuEnv_AllPresent(t *testing.T) {
	full := map[string]string{
		"AWS_ACCESS_KEY_ID":       "key",
		"AWS_SECRET_ACCESS_KEY":   "secret",
		"AWS_ENDPOINT_URL_S3":     "https://r2.example.com",
		"AWS_REGION":              "auto",
		"TF_VAR_state_passphrase": "passphrase",
	}
	if err := preflightTofuEnv(func(k string) string { return full[k] }); err != nil {
		t.Errorf("preflight should pass when all required env present, got: %v", err)
	}
}

func TestPreflightTofuEnv_MissingAWSCredsEmitsScript(t *testing.T) {
	partial := map[string]string{
		// AWS_ACCESS_KEY_ID intentionally missing
		"AWS_SECRET_ACCESS_KEY":   "secret",
		"AWS_ENDPOINT_URL_S3":     "https://r2.example.com",
		"AWS_REGION":              "auto",
		"TF_VAR_state_passphrase": "passphrase",
	}
	err := preflightTofuEnv(func(k string) string { return partial[k] })
	if err == nil {
		t.Fatal("expected error when AWS_ACCESS_KEY_ID missing, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected error to name AWS_ACCESS_KEY_ID, got: %v", err)
	}
	if !strings.Contains(msg, "WAPPS_R2_ACCESS_KEY_ID") {
		t.Errorf("expected error to include recovery hint mentioning WAPPS_R2_ACCESS_KEY_ID, got: %v", err)
	}
	if !strings.Contains(msg, "export AWS_ACCESS_KEY_ID=") {
		t.Errorf("expected error to include export snippet for AWS_ACCESS_KEY_ID, got: %v", err)
	}
}

func TestPreflightTofuEnv_MissingStatePassphraseEmitsScript(t *testing.T) {
	partial := map[string]string{
		"AWS_ACCESS_KEY_ID":     "key",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_ENDPOINT_URL_S3":   "https://r2.example.com",
		"AWS_REGION":            "auto",
		// TF_VAR_state_passphrase intentionally missing
	}
	err := preflightTofuEnv(func(k string) string { return partial[k] })
	if err == nil {
		t.Fatal("expected error when TF_VAR_state_passphrase missing, got nil")
	}
	if !strings.Contains(err.Error(), "TF_VAR_state_passphrase") {
		t.Errorf("expected error to name TF_VAR_state_passphrase, got: %v", err)
	}
}

func TestPreflightTofuEnv_AllMissingListsAll(t *testing.T) {
	err := preflightTofuEnv(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error when nothing set, got nil")
	}
	msg := err.Error()
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ENDPOINT_URL_S3",
		"AWS_REGION",
		"TF_VAR_state_passphrase",
	} {
		if !strings.Contains(msg, name) {
			t.Errorf("expected all-missing error to list %s, got: %v", name, err)
		}
	}
}

func TestSyncWritesEncryptedArchive(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test-pass-123")

	stubOutput := `{"jwt_key":{"value":"abc","sensitive":true,"type":"string"}}`
	stubFn := func() ([]byte, error) { return []byte(stubOutput), nil }

	if err := syncWithTofuOutput(stubFn, filepath.Join(tmp, "all.enc.age")); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	enc, err := os.ReadFile(filepath.Join(tmp, "all.enc.age"))
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	dec, err := ageutil.Decrypt(enc, "test-pass-123")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(dec) != stubOutput {
		t.Errorf("Want %s, got %s", stubOutput, dec)
	}
}
