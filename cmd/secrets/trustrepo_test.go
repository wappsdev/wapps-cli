package secrets

import (
	"bytes"
	"errors"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
)

func storeCfg(t *testing.T) *config.WappsYAML {
	t.Helper()
	cfg, err := config.Parse([]byte("version: 2\nbackend: store\nproject: vaulter\nprofiles:\n  deploy: [DATABASE_URL]\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cfg
}

func TestTrustRepoCore_PinsOnConfirm(t *testing.T) {
	cfg := storeCfg(t)
	dir := t.TempDir()
	path := dir + "/repo-pins.json"
	repoID := "git@github.com:wappsdev/vaulter.git"

	var out bytes.Buffer
	err := trustRepoCore(cfg, repoID, path, func() bool { return true }, &out)
	if err != nil {
		t.Fatalf("trustRepoCore: %v", err)
	}

	// Bağlama artık pinli olmalı.
	store, err := binding.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cerr := store.Check(binding.Fingerprint(repoID), "vaulter"); cerr != nil {
		t.Fatalf("expected pinned binding to verify, got: %v", cerr)
	}
	if !bytes.Contains(out.Bytes(), []byte("vaulter")) {
		t.Errorf("output should name the project: %q", out.String())
	}
}

func TestTrustRepoCore_AbortsOnDecline(t *testing.T) {
	cfg := storeCfg(t)
	dir := t.TempDir()
	path := dir + "/repo-pins.json"

	var out bytes.Buffer
	err := trustRepoCore(cfg, "git@github.com:x/y.git", path, func() bool { return false }, &out)
	if !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("decline must abort with BINDING_UNPINNED, got: %v", err)
	}
	// Hiçbir pin yazılmamalı.
	store, _ := binding.Load(path)
	if cerr := store.Check(binding.Fingerprint("git@github.com:x/y.git"), "vaulter"); !errors.Is(cerr, binding.ErrUnpinned) {
		t.Errorf("declined binding must remain unpinned, got: %v", cerr)
	}
}

func TestRunTrustRepo_RefusedInAgentMode(t *testing.T) {
	err := runTrustRepo(&bytes.Buffer{}, bytes.NewReader(nil), true /*isAgent*/)
	if !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("agent trust-repo must be refused: %v", err)
	}
}
