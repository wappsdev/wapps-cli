package projects

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRegistry(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "projects.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	return path
}

func TestResolveIn_HappyPath(t *testing.T) {
	path := writeRegistry(t, "projects:\n  vaulter: /abs/infra/vaulter\n  lab: /abs/infra/lab\n")
	dir, err := resolveIn(path, "vaulter")
	if err != nil {
		t.Fatalf("resolveIn: %v", err)
	}
	if dir != "/abs/infra/vaulter" {
		t.Errorf("got %q, want /abs/infra/vaulter", dir)
	}
}

func TestResolveIn_UnknownProject(t *testing.T) {
	path := writeRegistry(t, "projects:\n  vaulter: /abs/v\n")
	_, err := resolveIn(path, "nope")
	if err == nil {
		t.Fatal("expected error for unknown project")
	}
	// Spec-mandated message substring.
	if !strings.Contains(err.Error(), `unknown project "nope"`) ||
		!strings.Contains(err.Error(), "projects.yaml") {
		t.Errorf("error should match spec message, got: %v", err)
	}
}

func TestResolveIn_MissingRegistryFile(t *testing.T) {
	_, err := resolveIn(filepath.Join(t.TempDir(), "does-not-exist.yaml"), "vaulter")
	if err == nil {
		t.Fatal("expected error when registry missing")
	}
	if !strings.Contains(err.Error(), "unknown project") {
		t.Errorf("missing file should yield unknown-project error, got: %v", err)
	}
}

func TestResolveIn_MalformedRegistrySurfacesParseError(t *testing.T) {
	path := writeRegistry(t, "projects: [this is: not valid: mapping\n")
	_, err := resolveIn(path, "vaulter")
	if err == nil {
		t.Fatal("expected parse error for malformed registry")
	}
	if strings.Contains(err.Error(), "unknown project") {
		t.Errorf("malformed yaml should surface a parse error, not unknown-project: %v", err)
	}
}

func TestResolveIn_EmptyDirTreatedAsUnknown(t *testing.T) {
	path := writeRegistry(t, "projects:\n  vaulter: \"\"\n")
	_, err := resolveIn(path, "vaulter")
	if err == nil || !strings.Contains(err.Error(), "unknown project") {
		t.Errorf("empty dir should be unknown-project, got: %v", err)
	}
}

func TestResolveIn_ExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	path := writeRegistry(t, "projects:\n  vaulter: ~/infra/vaulter\n")
	dir, err := resolveIn(path, "vaulter")
	if err != nil {
		t.Fatalf("resolveIn: %v", err)
	}
	want := filepath.Join(home, "infra", "vaulter")
	if dir != want {
		t.Errorf("got %q, want %q (home expanded)", dir, want)
	}
}

func TestDefaultPath_HonorsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	p, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if p != "/tmp/xdg/wapps/projects.yaml" {
		t.Errorf("got %q, want XDG-based path", p)
	}
}
