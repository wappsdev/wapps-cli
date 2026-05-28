package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

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
