package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/config"
)

func TestRunInit_FreshRepoCreatesAllFiles(t *testing.T) {
	tmp := t.TempDir()

	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	for _, want := range []string{
		filepath.Join(tmp, ".wapps.yaml"),
		filepath.Join(tmp, "secrets"),
		filepath.Join(tmp, "secrets", ".gitignore"),
	} {
		if _, err := os.Stat(want); err != nil {
			t.Errorf("expected %s, stat err: %v", want, err)
		}
	}
}

func TestRunInit_GeneratedYAMLParsesAsValid(t *testing.T) {
	tmp := t.TempDir()
	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	cfg, err := config.Load(filepath.Join(tmp, ".wapps.yaml"))
	if err != nil {
		t.Fatalf("generated YAML failed to parse: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	if cfg.Dest != "secrets/all.enc.age" {
		t.Errorf("Dest = %q, want secrets/all.enc.age", cfg.Dest)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Type != "tofu" {
		t.Errorf("expected 1 tofu source, got: %+v", cfg.Sources)
	}
	if !cfg.RedactInLogs || !cfg.RequireCleanGit {
		t.Errorf("hardening defaults should be enabled by default")
	}
}

func TestRunInit_WithFileSourceAddsSecondSource(t *testing.T) {
	tmp := t.TempDir()
	if err := runInit(tmp, true, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	cfg, err := config.Load(filepath.Join(tmp, ".wapps.yaml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d: %+v", len(cfg.Sources), cfg.Sources)
	}
	if cfg.Sources[1].Type != "file" || cfg.Sources[1].Path != ".env.shared" {
		t.Errorf("file source malformed: %+v", cfg.Sources[1])
	}
}

func TestRunInit_RefusesToClobberExistingYAML(t *testing.T) {
	tmp := t.TempDir()
	yamlPath := filepath.Join(tmp, ".wapps.yaml")
	original := []byte("version: 1\nsources:\n  - type: file\n    path: .env.original\n")
	if err := os.WriteFile(yamlPath, original, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	got, _ := os.ReadFile(yamlPath)
	if string(got) != string(original) {
		t.Errorf("existing .wapps.yaml clobbered without --force:\nwant: %s\ngot:  %s", original, got)
	}
}

func TestRunInit_ForceOverwritesExisting(t *testing.T) {
	tmp := t.TempDir()
	yamlPath := filepath.Join(tmp, ".wapps.yaml")
	if err := os.WriteFile(yamlPath, []byte("old: junk\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := runInit(tmp, false, true); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	cfg, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("parse after --force: %v", err)
	}
	if cfg.Version != 1 || len(cfg.Sources) != 1 {
		t.Errorf("expected fresh template after --force, got: %+v", cfg)
	}
}

func TestRunInit_GitignoreExcludesRotationLog(t *testing.T) {
	tmp := t.TempDir()
	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(tmp, "secrets", ".gitignore"))
	if !strings.Contains(string(data), "rotation.log") {
		t.Errorf("gitignore missing rotation.log entry:\n%s", data)
	}
}

func TestRunInit_PreservesExistingGitignoreEntries(t *testing.T) {
	tmp := t.TempDir()
	secretsDir := filepath.Join(tmp, "secrets")
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	gitignorePath := filepath.Join(secretsDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("# operator-added entries\nlocal-secrets.txt\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	data, _ := os.ReadFile(gitignorePath)
	content := string(data)
	if !strings.Contains(content, "local-secrets.txt") {
		t.Errorf("operator-added entry lost:\n%s", content)
	}
	if !strings.Contains(content, "rotation.log") {
		t.Errorf("wapps entry not appended:\n%s", content)
	}
}

func TestRunInit_NoDuplicateRotationLogEntry(t *testing.T) {
	tmp := t.TempDir()
	// Run twice.
	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("second init: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(tmp, "secrets", ".gitignore"))
	count := strings.Count(string(data), "rotation.log")
	if count != 1 {
		t.Errorf("rotation.log entry appears %d times, want 1:\n%s", count, data)
	}
}

func TestRunInit_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("first init: %v", err)
	}
	// Second call should not error and should not clobber.
	if err := runInit(tmp, false, false); err != nil {
		t.Fatalf("second init: %v", err)
	}
}
