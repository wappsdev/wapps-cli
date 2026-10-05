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

// realTempDir is t.TempDir() with its symlinks resolved (macOS: /var ->
// /private/var), so a path built from it is the path the kernel opens and the
// listing shows no "->" target for it.
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSyncReadsBlock_ResolvesEverySourceAndMarksTheOutsideOnes(t *testing.T) {
	parent := realTempDir(t)
	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := loadCfgIn(t, root, "version: 2\nproject: p\nsources:\n"+
		"  - type: file\n    path: sync.env\n"+
		"  - type: file\n    path: ./sub/../inside.env\n"+
		"  - type: file\n    path: ../other/.env\n"+
		"  - type: file\n    path: /nonexistent-wapps/../abs/x.env\n"+
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
	root := realTempDir(t)
	cfg := loadCfgIn(t, root, "version: 2\nproject: testproj\nsources:\n  - type: file\n    path: ../up.env\n")
	var out bytes.Buffer
	_ = trustRepoCore(cfg, "R", filepath.Join(t.TempDir(), "pins.json"), func() bool { return false }, &out)
	want := "  backend: store\n  sync reads:\n    file " + filepath.Dir(root) + "/up.env" + outsideMark +
		"\nPin this binding? [y/N]: "
	if !strings.Contains(out.String(), want) {
		t.Errorf("trust-repo prompt must list the sources before asking:\n got %q\nwant it to contain %q", out.String(), want)
	}
}

// --- hardening: symlinks and terminal escapes --------------------------------
//
// The same vectors as rust/crates/cli/tests/syncreads.rs.

// symlinkFixture builds parent/repo (the config root) next to parent/outside
// (holding secret.env), with these links inside the root:
//
//	link.env    -> parent/outside/secret.env   (absolute, target exists)
//	dangling.env -> ../missing/id_rsa          (relative, target absent)
//	sub          -> parent/outside             (a directory)
//	alias.env   -> sync.env                    (stays inside)
func symlinkFixture(t *testing.T) (parent, root string) {
	t.Helper()
	parent = realTempDir(t)
	root = filepath.Join(parent, "repo")
	out := filepath.Join(parent, "outside")
	for _, d := range []string{root, out} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(out, "secret.env"), filepath.Join(root, "sync.env")} {
		if err := os.WriteFile(f, []byte("K=v\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"link.env":     filepath.Join(out, "secret.env"),
		"dangling.env": "../missing/id_rsa",
		"sub":          out,
		"alias.env":    "sync.env",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return parent, root
}

func TestSyncReadsBlock_DecidesContainmentOnTheResolvedPath(t *testing.T) {
	parent, root := symlinkFixture(t)
	cfg := loadCfgIn(t, root, "version: 2\nproject: p\nsources:\n"+
		"  - type: file\n    path: link.env\n"+
		"  - type: file\n    path: dangling.env\n"+
		"  - type: file\n    path: sub/deeper/x.env\n"+
		"  - type: file\n    path: alias.env\n"+
		"  - type: file\n    path: sync.env\n")
	want := "  sync reads:\n" +
		"    file " + root + "/link.env -> " + parent + "/outside/secret.env" + outsideMark + "\n" +
		"    file " + root + "/dangling.env -> " + parent + "/missing/id_rsa" + outsideMark + "\n" +
		"    file " + root + "/sub/deeper/x.env -> " + parent + "/outside/deeper/x.env" + outsideMark + "\n" +
		"    file " + root + "/alias.env -> " + root + "/sync.env\n" +
		"    file " + root + "/sync.env\n"
	if got := syncReadsBlock(cfg); got != want {
		t.Errorf("syncReadsBlock:\n got %q\nwant %q", got, want)
	}
}

func TestSyncReadsBlock_EscapesControlAndBidiCharacters(t *testing.T) {
	root := realTempDir(t)
	cfg := loadCfgIn(t, root, "version: 2\nproject: p\nsources:\n"+
		"  - type: file\n    path: \"a\\x1b[2K\\rfile ok.env\"\n"+
		"  - type: file\n    path: \"b\\nc.env\"\n"+
		"  - type: file\n    path: \"d\\u202eenv.txt\"\n")
	want := "  sync reads:\n" +
		"    file " + root + `/a\x1b[2K\rfile ok.env` + "\n" +
		"    file " + root + `/b\nc.env` + "\n" +
		"    file " + root + `/d\u202eenv.txt` + "\n"
	if got := syncReadsBlock(cfg); got != want {
		t.Errorf("syncReadsBlock:\n got %q\nwant %q", got, want)
	}
}

func TestVisible_KeepsPrintableTextAndEscapesTheRest(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain/path-1.env", "plain/path-1.env"},
		{`back\slash`, `back\slash`},
		{"caf\u00e9 \U0001f600", "caf\u00e9 \U0001f600"},
		{"\x1b[2K\r", `\x1b[2K\r`},
		{"a\nb\tc", `a\nb\tc`},
		{"\a\b\f\v\x00\x7f", `\a\b\f\v\x00\x7f`},
		{"\u0085\u009b", `\u0085\u009b`},
		{"\u00a0\u2028\u2029\u3000", `\u00a0\u2028\u2029\u3000`},
		{"x\u202ey\u2066z\u200b\ufeff", `x\u202ey\u2066z\u200b\ufeff`},
		{"\U000e0041", `\U000e0041`},
	}
	for _, c := range cases {
		if got := visible(c.in); got != c.want {
			t.Errorf("visible(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSyncReadsBlock_ALinkLoopEnds(t *testing.T) {
	root := realTempDir(t)
	for name, target := range map[string]string{"loop1": "loop2", "loop2": "loop1"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	cfg := loadCfgIn(t, root, "version: 2\nproject: p\nsources:\n  - type: file\n    path: loop1\n")
	want := "  sync reads:\n    file " + root + "/loop1 -> " + root + "/loop2\n"
	if got := syncReadsBlock(cfg); got != want {
		t.Errorf("syncReadsBlock:\n got %q\nwant %q", got, want)
	}
}

// Go only: a Rust &str is always UTF-8, so this vector has no twin.
func TestVisible_EscapesBytesThatAreNotUTF8(t *testing.T) {
	if got := visible("a\xffb"); got != `a\xffb` {
		t.Errorf("visible = %q", got)
	}
}
