package tofu

import (
	"strings"
	"testing"
)

func TestPreflightEnv_AllPresent(t *testing.T) {
	full := map[string]string{
		"AWS_ACCESS_KEY_ID":       "key",
		"AWS_SECRET_ACCESS_KEY":   "secret",
		"AWS_ENDPOINT_URL_S3":     "https://r2.example.com",
		"AWS_REGION":              "auto",
		"TF_VAR_state_passphrase": "passphrase",
	}
	if err := PreflightEnv(func(k string) string { return full[k] }); err != nil {
		t.Errorf("PreflightEnv should pass with all env present, got: %v", err)
	}
}

func TestPreflightEnv_NamesMissingVarsInOrder(t *testing.T) {
	err := PreflightEnv(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error when nothing set")
	}
	msg := err.Error()
	// All five required vars must appear in the missing list, in declaration
	// order — that lets the operator follow the recovery snippet top-down.
	want := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ENDPOINT_URL_S3",
		"AWS_REGION",
		"TF_VAR_state_passphrase",
	}
	for i, name := range want {
		idx := strings.Index(msg, name)
		if idx == -1 {
			t.Errorf("missing list missing %s", name)
			continue
		}
		if i > 0 {
			prevIdx := strings.Index(msg, want[i-1])
			if idx < prevIdx {
				t.Errorf("missing list out of order: %s before %s", want[i], want[i-1])
			}
		}
	}
}

func TestPreflightEnv_IncludesRecoverySnippet(t *testing.T) {
	err := PreflightEnv(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, frag := range []string{
		"set -a",
		"source ~/.config",
		"export AWS_ACCESS_KEY_ID=",
		"export TF_VAR_state_passphrase=",
	} {
		if !strings.Contains(msg, frag) {
			t.Errorf("recovery snippet missing fragment: %q\nfull error:\n%s", frag, msg)
		}
	}
}

func TestPreflightEnv_SingleMissingVarNamedSpecifically(t *testing.T) {
	partial := map[string]string{
		"AWS_ACCESS_KEY_ID":     "key",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_ENDPOINT_URL_S3":   "https://r2.example.com",
		"AWS_REGION":            "auto",
		// TF_VAR_state_passphrase intentionally missing
	}
	err := PreflightEnv(func(k string) string { return partial[k] })
	if err == nil {
		t.Fatal("expected error for single missing var")
	}
	if !strings.Contains(err.Error(), "TF_VAR_state_passphrase") {
		t.Errorf("error should name TF_VAR_state_passphrase, got: %v", err)
	}
	// Other vars should NOT appear in the missing list.
	missingSection := strings.Split(err.Error(), "Recovery")[0]
	if strings.Contains(missingSection, "AWS_ACCESS_KEY_ID") {
		t.Errorf("non-missing var AWS_ACCESS_KEY_ID appeared in missing list:\n%s", missingSection)
	}
}

// Süperset değişmezi: backend env kontratındaki (RequiredEnvVars) her
// değişken BootstrapEnvVars kataloğunda da bulunmak ZORUNDA — aksi halde
// `wapps dr bootstrap` ile başlatılan bir apply preflight'ta düşer.
func TestBootstrapEnvVars_SupersetOfRequired(t *testing.T) {
	catalog := make(map[string]BootstrapEnvVar, len(BootstrapEnvVars))
	for _, b := range BootstrapEnvVars {
		catalog[b.Name] = b
	}
	for _, r := range RequiredEnvVars {
		if _, ok := catalog[r.Name]; !ok {
			t.Errorf("superset invariant broken: required var %s missing from BootstrapEnvVars", r.Name)
		}
	}
}

// AWS_REGION sabittir (Cloudflare R2 → her zaman "auto") ve hiçbir
// koşulda promptlanmaz.
func TestBootstrapEnvVars_AWSRegionConstantNeverPrompted(t *testing.T) {
	var region *BootstrapEnvVar
	for i := range BootstrapEnvVars {
		if BootstrapEnvVars[i].Name == "AWS_REGION" {
			region = &BootstrapEnvVars[i]
			break
		}
	}
	if region == nil {
		t.Fatal("AWS_REGION missing from BootstrapEnvVars")
	}
	if region.Constant != "auto" {
		t.Errorf("AWS_REGION.Constant = %q, want \"auto\"", region.Constant)
	}
	if region.Promptable() {
		t.Error("AWS_REGION must NEVER be promptable — it is the constant 'auto'")
	}
}

// Provisioning input'ları katalogda bulunmalı ve promptable olmalı —
// dr bootstrap bunları TTY'den ister (mimari §3.3).
func TestBootstrapEnvVars_ProvisioningTokensPromptable(t *testing.T) {
	catalog := make(map[string]BootstrapEnvVar, len(BootstrapEnvVars))
	for _, b := range BootstrapEnvVars {
		catalog[b.Name] = b
	}
	for _, name := range []string{
		"TF_VAR_cloudflare_api_token",
		"TF_VAR_cloudflare_r2_api_token",
		"TF_VAR_hcloud_token",
		"TF_VAR_coolify_token",
	} {
		b, ok := catalog[name]
		if !ok {
			t.Errorf("provisioning input %s missing from BootstrapEnvVars", name)
			continue
		}
		if !b.Promptable() {
			t.Errorf("%s must be promptable (Constant=%q set)", name, b.Constant)
		}
	}
}

// Katalog hijyeni: isim tekrarı yok, her girdinin hint'i dolu (operatör
// prompt'ta ne girdiğini hint'ten anlar).
func TestBootstrapEnvVars_NoDuplicatesAndHintsPresent(t *testing.T) {
	seen := make(map[string]bool, len(BootstrapEnvVars))
	for _, b := range BootstrapEnvVars {
		if b.Name == "" {
			t.Error("empty Name in BootstrapEnvVars entry")
			continue
		}
		if seen[b.Name] {
			t.Errorf("duplicate BootstrapEnvVars entry: %s", b.Name)
		}
		seen[b.Name] = true
		if b.Hint == "" {
			t.Errorf("empty Hint for %s — operators need the hint at the prompt", b.Name)
		}
	}
}

func TestRequiredEnvVars_ContainsExpected(t *testing.T) {
	// Tests that callers (other packages) can iterate this list to know
	// what to display in their own doctor-style output.
	if len(RequiredEnvVars) != 5 {
		t.Errorf("RequiredEnvVars count = %d, want 5", len(RequiredEnvVars))
	}
	for _, r := range RequiredEnvVars {
		if r.Name == "" {
			t.Errorf("empty Name in RequiredEnvVars entry")
		}
		if r.Hint == "" {
			t.Errorf("empty Hint for %s — operators need the hint to recover", r.Name)
		}
	}
}
