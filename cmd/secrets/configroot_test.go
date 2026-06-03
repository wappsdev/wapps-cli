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

// setupForeignProject builds a project dir (with .wapps.yaml + seeded archive),
// chdirs to an UNRELATED dir so cwd != configRoot, sets the passphrase, and
// wires the package config override to the project's .wapps.yaml (simulating
// what --config/--project do via root's PersistentPreRunE). Returns the project
// dir. The override is reset in cleanup so it can't leak into sibling tests.
//
// yamlExtra is appended after the file source block (e.g. a targets: block).
func setupForeignProject(t *testing.T, archive map[string]string, yamlExtra string) string {
	t.Helper()
	projDir := t.TempDir()
	otherDir := t.TempDir()
	pp := "cfgroot-pp"

	if err := os.MkdirAll(filepath.Join(projDir, "secrets"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	envelope := make(map[string]json.RawMessage)
	for k, v := range archive {
		b, _ := json.Marshal(map[string]string{"value": v})
		envelope[k] = b
	}
	raw, _ := json.Marshal(envelope)
	if err := ageutil.EncryptWriteAtomic(filepath.Join(projDir, "secrets", "all.enc.age"), raw, pp); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, ".env.shared"), []byte(""), 0600); err != nil {
		t.Fatalf("seed file source: %v", err)
	}
	yaml := "version: 1\nsources:\n  - type: file\n    path: .env.shared\n" + yamlExtra
	if err := os.WriteFile(filepath.Join(projDir, ".wapps.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)
	t.Chdir(otherDir) // cwd is deliberately NOT the project dir
	SetConfigPath(filepath.Join(projDir, ".wapps.yaml"))
	t.Cleanup(func() { SetConfigPath("") })
	return projDir
}

// Acceptance #1: list from a foreign cwd via --config → non-empty names.
func TestList_ConfigRootDifferentCwd(t *testing.T) {
	setupForeignProject(t, map[string]string{"alpha": "1", "beta": "2"}, "")

	var buf bytes.Buffer
	if err := listKeys(resolveArchivePath(), &buf); err != nil {
		t.Fatalf("listKeys: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "alpha") || !strings.Contains(got, "beta") {
		t.Errorf("list from foreign cwd missing keys, got:\n%s", got)
	}
}

// Acceptance #2: get from a foreign cwd via --config → value.
func TestGet_ConfigRootDifferentCwd(t *testing.T) {
	setupForeignProject(t, map[string]string{"coolify_uuid": "u-123"}, "")

	val, err := readKey(resolveArchivePath(), "coolify_uuid")
	if err != nil {
		t.Fatalf("readKey: %v", err)
	}
	if val != "u-123" {
		t.Errorf("got %q, want u-123", val)
	}
}

// Acceptance #4: exec from a foreign cwd injects the archive env into the
// subprocess. We use a fake execRunner that captures the env handed to it.
func TestExec_ConfigRootInjectsEnv(t *testing.T) {
	setupForeignProject(t, map[string]string{"coolify_uuid": "u-123"}, "")

	r := &fakeRunner{returnCode: 0}
	if err := runExec([]string{"true"}, "", r.runner); err != nil {
		t.Fatalf("runExec: %v", err)
	}
	found := false
	for _, kv := range r.gotEnv {
		if kv == "coolify_uuid=u-123" || kv == "TF_VAR_coolify_uuid=u-123" {
			found = true
		}
	}
	if !found {
		t.Errorf("exec env missing injected key; env=%v", r.gotEnv)
	}
}

// Acceptance #5 (regression): in the project dir, NO override → legacy behavior
// works byte-identically (configRoot == cwd).
func TestList_NoOverrideLegacy(t *testing.T) {
	projDir := t.TempDir()
	pp := "legacy-pp"
	if err := os.MkdirAll(filepath.Join(projDir, "secrets"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	envelope := map[string]json.RawMessage{"x": json.RawMessage(`{"value":"y"}`)}
	raw, _ := json.Marshal(envelope)
	if err := ageutil.EncryptWriteAtomic(filepath.Join(projDir, "secrets", "all.enc.age"), raw, pp); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, ".wapps.yaml"), []byte("version: 1\nsources:\n  - type: tofu\n"), 0644); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)
	t.Chdir(projDir)        // cwd IS the project dir
	SetConfigPath("")       // no override (legacy)
	t.Cleanup(func() { SetConfigPath("") })

	var buf bytes.Buffer
	if err := listKeys(resolveArchivePath(), &buf); err != nil {
		t.Fatalf("listKeys legacy: %v", err)
	}
	if !strings.Contains(buf.String(), "x") {
		t.Errorf("legacy list broke, got:\n%s", buf.String())
	}
}

// Acceptance #7-ish: an absolute dest in .wapps.yaml is read verbatim even
// under --config (no Join applied).
func TestRead_AbsoluteDestUnchanged(t *testing.T) {
	projDir := t.TempDir()
	otherDir := t.TempDir()
	pp := "abs-pp"
	// Archive lives at an absolute path OUTSIDE projDir/secrets.
	absArchive := filepath.Join(otherDir, "external.enc.age")
	envelope := map[string]json.RawMessage{"abskey": json.RawMessage(`{"value":"absval"}`)}
	raw, _ := json.Marshal(envelope)
	if err := ageutil.EncryptWriteAtomic(absArchive, raw, pp); err != nil {
		t.Fatalf("seed: %v", err)
	}
	yaml := "version: 1\ndest: " + absArchive + "\nsources:\n  - type: tofu\n"
	if err := os.WriteFile(filepath.Join(projDir, ".wapps.yaml"), []byte(yaml), 0644); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	thirdDir := t.TempDir()
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", pp)
	t.Chdir(thirdDir)
	SetConfigPath(filepath.Join(projDir, ".wapps.yaml"))
	t.Cleanup(func() { SetConfigPath("") })

	val, err := readKey(resolveArchivePath(), "abskey")
	if err != nil {
		t.Fatalf("readKey with absolute dest: %v", err)
	}
	if val != "absval" {
		t.Errorf("got %q, want absval", val)
	}
}

// apply target-location decision: a --config apply writes the target UNDER the
// project dir, not the foreign cwd.
func TestApply_TargetWrittenUnderConfigRoot(t *testing.T) {
	projDir := setupForeignProject(t, map[string]string{"FOO": "bar"},
		"default_prefix: \"\"\ntargets:\n  - path: .env.local\n")

	if err := runApply(&bytes.Buffer{}); err != nil {
		t.Fatalf("runApply: %v", err)
	}
	// Must land under projDir, NOT cwd.
	data, err := os.ReadFile(filepath.Join(projDir, ".env.local"))
	if err != nil {
		t.Fatalf(".env.local should exist under projDir: %v", err)
	}
	if !strings.Contains(string(data), "FOO='bar'") {
		t.Errorf("target content wrong:\n%s", data)
	}
	// And must NOT be written to cwd.
	if _, err := os.Stat(".env.local"); !os.IsNotExist(err) {
		t.Error(".env.local leaked into cwd (should be under configRoot)")
	}
}
