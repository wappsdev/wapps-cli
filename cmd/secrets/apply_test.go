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

// applySetup writes archive + .wapps.yaml with given targets and returns tmp dir.
// yamlExtra is appended after sources block (e.g., "targets:\n  - path: .env.local").
func applySetup(t *testing.T, archive map[string]string, yamlExtra string) string {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	pp := "apply-test-pp"
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)

	envelope := make(map[string]json.RawMessage)
	for k, v := range archive {
		b, _ := json.Marshal(map[string]string{"value": v})
		envelope[k] = b
	}
	raw, _ := json.Marshal(envelope)
	enc, err := ageutil.Encrypt(raw, pp)
	if err != nil {
		t.Fatalf("encrypt seed: %v", err)
	}
	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile("secrets/all.enc.age", enc, 0600); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	if err := os.WriteFile(".env.shared", []byte(""), 0600); err != nil {
		t.Fatalf("seed file source: %v", err)
	}
	yaml := "version: 1\nsources:\n  - type: file\n    path: .env.shared\n" + yamlExtra
	if err := os.WriteFile(".wapps.yaml", []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return tmp
}

func TestRunApply_WritesTargetFile(t *testing.T) {
	tmp := applySetup(t, map[string]string{"FOO": "bar"},
		"targets:\n  - path: .env.local\n")

	var stdout bytes.Buffer
	if err := runApply(&stdout); err != nil {
		t.Fatalf("runApply: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, ".env.local"))
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	// targets: deklare edilmiş, default_prefix yok → plain (yeni codepath
	// için doğal default). CLI env --write'ın TF_VAR_ default'u burada
	// geçerli değil; o flag default'u, yaml schema default'u değil.
	if !strings.Contains(string(data), "export FOO='bar'") {
		t.Errorf("target should contain plain export by default, got:\n%s", data)
	}
	if !strings.Contains(stdout.String(), "wrote .env.local") {
		t.Errorf("stdout should report wrote, got: %q", stdout.String())
	}
}

func TestRunApply_DefaultPrefixApplied(t *testing.T) {
	applySetup(t, map[string]string{"FOO": "bar"},
		`default_prefix: ""
targets:
  - path: .env.local
`)

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("runApply: %v", err)
	}

	data, _ := os.ReadFile(".env.local")
	if !strings.Contains(string(data), "export FOO='bar'") {
		t.Errorf("default_prefix='' should produce plain export, got:\n%s", data)
	}
	if strings.Contains(string(data), "TF_VAR_") {
		t.Errorf("TF_VAR_ should not appear when default_prefix='', got:\n%s", data)
	}
}

func TestRunApply_PerTargetPrefixOverridesDefault(t *testing.T) {
	applySetup(t, map[string]string{"DB_URL": "postgres://x"},
		`default_prefix: ""
targets:
  - path: .env.local
  - path: tf.tfvars
    prefix: "TF_VAR_"
`)

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("runApply: %v", err)
	}

	envLocal, _ := os.ReadFile(".env.local")
	if !strings.Contains(string(envLocal), "export DB_URL='postgres://x'") {
		t.Errorf(".env.local should use empty prefix:\n%s", envLocal)
	}
	tfvars, _ := os.ReadFile("tf.tfvars")
	if !strings.Contains(string(tfvars), "export TF_VAR_DB_URL='postgres://x'") {
		t.Errorf("tf.tfvars should use TF_VAR_ prefix:\n%s", tfvars)
	}
}

func TestRunApply_NoTargets_Errors(t *testing.T) {
	applySetup(t, map[string]string{"FOO": "bar"}, "")

	err := runApply(&bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when no targets declared")
	}
	if !strings.Contains(err.Error(), "no targets") {
		t.Errorf("error should explain missing targets, got: %v", err)
	}
}

func TestRunApply_NoPassphrase_Errors(t *testing.T) {
	applySetup(t, map[string]string{"FOO": "bar"},
		"targets:\n  - path: .env.local\n")
	os.Unsetenv("WAPPS_SECRETS_PASSPHRASE")

	err := runApply(&bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when passphrase missing")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Errorf("error should name env var: %v", err)
	}
}

func TestRunApply_Idempotent_SkipsUnchanged(t *testing.T) {
	applySetup(t, map[string]string{"FOO": "bar"},
		"targets:\n  - path: .env.local\n")

	// First run writes the file.
	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("first runApply: %v", err)
	}
	info1, err := os.Stat(".env.local")
	if err != nil {
		t.Fatalf("stat after first: %v", err)
	}
	mtime1 := info1.ModTime()

	// Modern filesystems (ext4, APFS) have nanosecond mtime resolution, so
	// two consecutive writes would show different mtimes without sleep. The
	// test assumes CI / dev machines aren't on legacy HFS+ or coarse-resolution
	// filesystems. If that assumption breaks, restore a small sleep here.

	// Second run: same content, must skip — mtime unchanged proves no write.
	var stdout bytes.Buffer
	if err := runApply(&stdout); err != nil {
		t.Fatalf("second runApply: %v", err)
	}
	info2, err := os.Stat(".env.local")
	if err != nil {
		t.Fatalf("stat after second: %v", err)
	}
	if !info2.ModTime().Equal(mtime1) {
		t.Errorf("idempotent run should not touch file (mtime changed: %v → %v)", mtime1, info2.ModTime())
	}
	if !strings.Contains(stdout.String(), "unchanged .env.local") {
		t.Errorf("stdout should report unchanged, got: %q", stdout.String())
	}
}

func TestRunApply_WritesWhenContentDiffers(t *testing.T) {
	applySetup(t, map[string]string{"FOO": "bar"},
		"targets:\n  - path: .env.local\n")

	// Pre-seed with stale content — apply must overwrite.
	if err := os.WriteFile(".env.local", []byte("export STALE='1'\n"), 0600); err != nil {
		t.Fatalf("seed stale: %v", err)
	}

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("runApply: %v", err)
	}

	data, _ := os.ReadFile(".env.local")
	if strings.Contains(string(data), "STALE") {
		t.Errorf("apply should have overwritten stale content, got:\n%s", data)
	}
	if !strings.Contains(string(data), "FOO='bar'") {
		t.Errorf("apply should write fresh content, got:\n%s", data)
	}
}

func TestRunApply_MultipleTargets_MtimeIndependent(t *testing.T) {
	// Only one target changes; the other should stay untouched.
	tmp := applySetup(t, map[string]string{"FOO": "bar", "BAZ": "qux"},
		"targets:\n  - path: .env.local\n  - path: .env.other\n")

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("first runApply: %v", err)
	}
	otherPath := filepath.Join(tmp, ".env.other")
	info1, _ := os.Stat(otherPath)

	// Corrupt only the first target — second should remain idempotent.
	if err := os.WriteFile(".env.local", []byte("garbage"), 0600); err != nil {
		t.Fatalf("corrupt first: %v", err)
	}

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("second runApply: %v", err)
	}
	info2, _ := os.Stat(otherPath)
	if !info2.ModTime().Equal(info1.ModTime()) {
		t.Errorf(".env.other should have been untouched (idempotent), mtime: %v → %v", info1.ModTime(), info2.ModTime())
	}
}

func TestRunApply_TargetMode0600(t *testing.T) {
	applySetup(t, map[string]string{"FOO": "bar"},
		"targets:\n  - path: .env.local\n")

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("runApply: %v", err)
	}

	info, err := os.Stat(".env.local")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("target mode = %o, want 0600 (plaintext secrets)", mode)
	}
}
