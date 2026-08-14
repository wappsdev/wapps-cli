package secrets

// init_test.go, `wapps secrets init` sözleşmesini pinler: TEK bir .wapps.yaml
// yazılır (repoya şifreli hiçbir şey konmaz), üretilen dosya geçerli parse
// edilir, ve mevcut bir config --force olmadan ASLA ezilmez.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/config"
)

func TestRunInit_WritesOnlyTheConfig(t *testing.T) {
	tmp := t.TempDir()
	if err := runInitStore(tmp, "myproj", false); err != nil {
		t.Fatalf("runInitStore: %v", err)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != ".wapps.yaml" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("init must create exactly .wapps.yaml, got %v", names)
	}
}

func TestRunInit_GeneratedYAMLParsesAsValid(t *testing.T) {
	tmp := t.TempDir()
	if err := runInitStore(tmp, "myproj", false); err != nil {
		t.Fatalf("runInitStore: %v", err)
	}
	cfg, err := config.Load(filepath.Join(tmp, ".wapps.yaml"))
	if err != nil {
		t.Fatalf("generated config must parse: %v", err)
	}
	if cfg.Project != "myproj" {
		t.Errorf("project: got %q, want myproj", cfg.Project)
	}
}

// Proje adı verilmezse dizin adına düşer.
func TestRunInit_DefaultsProjectToDirName(t *testing.T) {
	base := t.TempDir()
	tmp := filepath.Join(base, "navlun-app")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runInitStore(tmp, "", false); err != nil {
		t.Fatalf("runInitStore: %v", err)
	}
	cfg, err := config.Load(filepath.Join(tmp, ".wapps.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "navlun-app" {
		t.Errorf("project should default to the dir name, got %q", cfg.Project)
	}
}

func TestRunInit_RefusesToClobberExistingYAML(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".wapps.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nproject: original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runInitStore(tmp, "other", false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("init must refuse to clobber, got %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "original") {
		t.Error("refused init must leave the existing file untouched")
	}
}

func TestRunInit_ForceOverwritesExisting(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".wapps.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nproject: original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runInitStore(tmp, "replacement", true); err != nil {
		t.Fatalf("--force init: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "replacement" {
		t.Errorf("--force must overwrite; project = %q", cfg.Project)
	}
}
