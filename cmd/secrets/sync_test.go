package secrets

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/config"
)

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

// --dry-run, emekliye ayrılan `verify`in yerini alır: hangi anahtarın YENİ,
// hangisinin DEĞİŞMİŞ olduğunu ADIYLA söyler ve store'a hiçbir şey yazmaz.
func TestRunSyncStore_DryRun_ReportsNamesAndWritesNothing(t *testing.T) {
	setupStoreProject(t, "sources:\n  - type: file\n    path: .env.shared\n")
	f := installFakeStore(t)
	f.values["SAME"] = "identical-val"
	f.values["DRIFTED"] = "old-value"

	if err := os.WriteFile(".env.shared", []byte("SAME=identical-val\nDRIFTED=new-value\nBRAND_NEW=x\n"), 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	var out bytes.Buffer
	if err := runSyncStore(context.Background(), mustLoadCfg(t), os.Getenv, true, &out); err != nil {
		t.Fatalf("dry-run sync: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "+ BRAND_NEW") {
		t.Errorf("new key must be marked +:\n%s", got)
	}
	if !strings.Contains(got, "~ DRIFTED") {
		t.Errorf("changed key must be marked ~:\n%s", got)
	}
	if strings.Contains(got, "SAME") {
		t.Errorf("unchanged keys must not be listed:\n%s", got)
	}
	// Değerler ASLA basılmaz.
	for _, v := range []string{"new-value", "old-value", "identical-val"} {
		if strings.Contains(got, v) {
			t.Errorf("dry-run leaked a value (%q):\n%s", v, got)
		}
	}
	if len(f.importCalls) != 0 {
		t.Errorf("--dry-run must not write, got %+v", f.importCalls)
	}
}

// Kaynaklar store ile birebir aynıysa "in sync" der.
func TestRunSyncStore_DryRun_InSync(t *testing.T) {
	setupStoreProject(t, "sources:\n  - type: file\n    path: .env.shared\n")
	f := installFakeStore(t)
	f.values["A"] = "1"

	if err := os.WriteFile(".env.shared", []byte("A=1\n"), 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	var out bytes.Buffer
	if err := runSyncStore(context.Background(), mustLoadCfg(t), os.Getenv, true, &out); err != nil {
		t.Fatalf("dry-run sync: %v", err)
	}
	if !strings.Contains(out.String(), "In sync") {
		t.Errorf("identical sources must report in-sync:\n%s", out.String())
	}
}

func mustLoadCfg(t *testing.T) *config.WappsYAML {
	t.Helper()
	cfg, err := requireStoreConfig("test")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}
