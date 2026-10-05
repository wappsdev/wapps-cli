package secrets

// syncreads_test.go pins owner decision (B) of 2026-10-05: a source may still
// name a file outside the repository (relative "../" or absolute), but a human
// asked to bind an unpinned repository is shown every source a sync will read,
// resolved, with the ones outside the config root marked.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/config"
)

const outsideMark = " (outside the config root)"

// loadCfgIn writes yaml as dir/.wapps.yaml and loads it, so the config root is
// set exactly as in production.
func loadCfgIn(t *testing.T, dir, yaml string) *config.WappsYAML {
	t.Helper()
	p := filepath.Join(dir, ".wapps.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write .wapps.yaml: %v", err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

func TestSyncReadsBlock_ResolvesEverySourceAndMarksTheOutsideOnes(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := loadCfgIn(t, root, "version: 2\nproject: p\nsources:\n"+
		"  - type: file\n    path: sync.env\n"+
		"  - type: file\n    path: ./sub/../inside.env\n"+
		"  - type: file\n    path: ../other/.env\n"+
		"  - type: file\n    path: /etc/../abs/x.env\n"+
		"  - type: tofu\n"+
		"  - type: tofu\n    workdir: /tf\n")
	want := "  sync reads:\n" +
		"    file " + root + "/sync.env\n" +
		"    file " + root + "/inside.env\n" +
		"    file " + parent + "/other/.env" + outsideMark + "\n" +
		"    file /abs/x.env" + outsideMark + "\n" +
		"    tofu " + root + "\n" +
		"    tofu /tf" + outsideMark + "\n"
	if got := syncReadsBlock(cfg); got != want {
		t.Errorf("syncReadsBlock:\n got %q\nwant %q", got, want)
	}
}

func TestSyncReadsBlock_NoSourcesPrintsNothing(t *testing.T) {
	cfg := loadCfgIn(t, t.TempDir(), "version: 2\nproject: p\n")
	if got := syncReadsBlock(cfg); got != "" {
		t.Errorf("no sources must print nothing, got %q", got)
	}
}

func TestWithinRoot_IsLexicalAndComponentWise(t *testing.T) {
	cases := []struct {
		p, root string
		want    bool
	}{
		{"/a", "/a", true},
		{"/a/b", "/a", true},
		{"/ab", "/a", false},
		{"/", "/a", false},
		{"/x/y", "/", true},
	}
	for _, c := range cases {
		if got := withinRoot(c.p, c.root); got != c.want {
			t.Errorf("withinRoot(%q, %q) = %v, want %v", c.p, c.root, got, c.want)
		}
	}
}

func TestBindPromptText_ListsWhatSyncReads(t *testing.T) {
	root := t.TempDir()
	cfg := loadCfgIn(t, root, "version: 2\nproject: testproj\nsources:\n  - type: file\n    path: /abs.env\n")
	want := "This repo is not bound to a project yet.\n" +
		"  repo:    R\n" +
		"  project: testproj\n" +
		"  sync reads:\n" +
		"    file /abs.env" + outsideMark + "\n" +
		"Bind them? [y/N]: "
	if got := bindPromptText("R", cfg); got != want {
		t.Errorf("bindPromptText:\n got %q\nwant %q", got, want)
	}
}

func TestBindPromptText_WithoutSourcesIsUnchanged(t *testing.T) {
	cfg := loadCfgIn(t, t.TempDir(), "version: 2\nproject: testproj\n")
	want := "This repo is not bound to a project yet.\n  repo:    R\n  project: testproj\nBind them? [y/N]: "
	if got := bindPromptText("R", cfg); got != want {
		t.Errorf("bindPromptText:\n got %q\nwant %q", got, want)
	}
}

func TestTrustRepoCore_ListsWhatSyncReadsBeforeAsking(t *testing.T) {
	root := t.TempDir()
	cfg := loadCfgIn(t, root, "version: 2\nproject: testproj\nsources:\n  - type: file\n    path: ../up.env\n")
	var out bytes.Buffer
	_ = trustRepoCore(cfg, "R", filepath.Join(t.TempDir(), "pins.json"), func() bool { return false }, &out)
	want := "  backend: store\n  sync reads:\n    file " + filepath.Dir(root) + "/up.env" + outsideMark +
		"\nPin this binding? [y/N]: "
	if !strings.Contains(out.String(), want) {
		t.Errorf("trust-repo prompt must list the sources before asking:\n got %q\nwant it to contain %q", out.String(), want)
	}
}
