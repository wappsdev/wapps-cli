package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/cmd/secrets"
)

// resetRootFlags clears the package-global flag state the root command mutates,
// so tests don't leak --config/--project/override into one another.
func resetRootFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		cfgFile = ""
		projectName = ""
		noSync = false
		secrets.SetConfigPath("")
	})
}

// Acceptance #3: --project resolves to the project's .wapps.yaml, identical to
// what --config <dir>/.wapps.yaml would produce.
func TestResolveProjectFlag_ResolvesToConfigPath(t *testing.T) {
	resetRootFlags(t)
	xdg := t.TempDir()
	projDir := t.TempDir()
	regDir := filepath.Join(xdg, "wapps")
	if err := os.MkdirAll(regDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	reg := "projects:\n  vaulter: " + projDir + "\n"
	if err := os.WriteFile(filepath.Join(regDir, "projects.yaml"), []byte(reg), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)

	projectName = "vaulter"
	cfgFile = ""
	if err := resolveProjectFlag(); err != nil {
		t.Fatalf("resolveProjectFlag: %v", err)
	}
	want := filepath.Join(projDir, ".wapps.yaml")
	if cfgFile != want {
		t.Errorf("cfgFile = %q, want %q", cfgFile, want)
	}
}

// Acceptance #6 (programmatic guard): both --config and --project set → error.
func TestResolveProjectFlag_MutuallyExclusiveGuard(t *testing.T) {
	resetRootFlags(t)
	projectName = "vaulter"
	cfgFile = "/some/.wapps.yaml"
	err := resolveProjectFlag()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual-exclusivity error, got: %v", err)
	}
}

// Acceptance #6 (cobra-level): MarkFlagsMutuallyExclusive rejects --config +
// --project at parse time.
func TestRootCmd_ConfigAndProjectMutuallyExclusive(t *testing.T) {
	resetRootFlags(t)
	// Use a real subcommand so cobra runs full flag-group validation (which
	// fires before PersistentPreRunE/RunE). With no subcommand, root just
	// prints help and skips group validation.
	rootCmd.SetArgs([]string{"secrets", "list", "--config", "/tmp/a/.wapps.yaml", "--project", "vaulter", "--no-sync"})
	rootCmd.SetOut(new(strings.Builder))
	rootCmd.SetErr(new(strings.Builder))
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected cobra mutual-exclusivity error")
	}
	if !strings.Contains(err.Error(), "config") || !strings.Contains(err.Error(), "project") {
		t.Errorf("error should name both flags, got: %v", err)
	}
}

func TestResolveProjectFlag_UnknownProjectError(t *testing.T) {
	resetRootFlags(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // empty → no registry
	projectName = "ghost"
	cfgFile = ""
	err := resolveProjectFlag()
	if err == nil || !strings.Contains(err.Error(), `unknown project "ghost"`) {
		t.Errorf("expected unknown-project error, got: %v", err)
	}
}

// Fix 3: the git preflight skips cleanly when configRoot isn't a git repo,
// instead of erroring or warning.
func TestPersistentPreRun_SkipsWhenConfigRootNotRepo(t *testing.T) {
	resetRootFlags(t)
	projDir := t.TempDir() // a plain temp dir, NOT a git repo
	if err := os.WriteFile(filepath.Join(projDir, ".wapps.yaml"),
		[]byte("version: 1\nsources:\n  - type: tofu\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfgFile = filepath.Join(projDir, ".wapps.yaml")
	noSync = false

	// Invoke the preflight directly with the root command (Name() == "wapps",
	// no parent) so it proceeds past the doctor/git skips to the IsRepo guard.
	if err := rootCmd.PersistentPreRunE(rootCmd, nil); err != nil {
		t.Errorf("preflight should skip (not error) outside a git repo, got: %v", err)
	}
	// And it should have wired the override to the secrets package.
	// (No direct getter; behavior is covered by the secrets-package tests.)
}
