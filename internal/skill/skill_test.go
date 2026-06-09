package skill

import (
	"os"
	"path/filepath"
	"testing"
)

// embeddedSkillMD returns the embedded SKILL.md content for assertions.
func embeddedSkillMD(t *testing.T) []byte {
	t.Helper()
	files, err := embeddedFiles()
	if err != nil {
		t.Fatalf("embeddedFiles: %v", err)
	}
	b, ok := files["SKILL.md"]
	if !ok {
		t.Fatalf("embedded assets missing SKILL.md (got %v)", keys(files))
	}
	if len(b) == 0 {
		t.Fatal("embedded SKILL.md is empty")
	}
	return b
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestFingerprintStableAndNonEmpty(t *testing.T) {
	a, err := Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || a != b {
		t.Fatalf("fingerprint not stable/non-empty: %q vs %q", a, b)
	}
}

func TestInstallUserSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	res, err := Install(Options{Scope: ScopeUser})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Mode != "symlink" {
		t.Fatalf("mode = %q, want symlink", res.Mode)
	}

	link := filepath.Join(home, ".claude", "skills", SkillName, "SKILL.md")
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("SKILL.md is not a symlink")
	}
	wantTarget := filepath.Join(home, ".config", "wapps", "skills", SkillName, "SKILL.md")
	if tgt, _ := os.Readlink(link); tgt != wantTarget {
		t.Fatalf("symlink target = %q, want %q", tgt, wantTarget)
	}
	got, err := os.ReadFile(link) // resolves through the symlink
	if err != nil {
		t.Fatalf("read through link: %v", err)
	}
	if string(got) != string(embeddedSkillMD(t)) {
		t.Fatal("linked content != embedded SKILL.md")
	}
}

func TestInstallIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := Install(Options{Scope: ScopeUser}); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	res, err := Install(Options{Scope: ScopeUser})
	if err != nil {
		t.Fatalf("install 2: %v", err)
	}
	link := filepath.Join(home, ".claude", "skills", SkillName, "SKILL.md")
	if len(res.Files) == 0 || res.Files[0] != link {
		t.Fatalf("second install files = %v", res.Files)
	}
	st, err := Status(Options{Scope: ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed || !st.UpToDate {
		t.Fatalf("status after idempotent install: installed=%v upToDate=%v", st.Installed, st.UpToDate)
	}
}

func TestInstallProjectCopyIsRealFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := t.TempDir()

	res, err := Install(Options{Scope: ScopeProject, ProjectDir: proj, Copy: true})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Mode != "copy" {
		t.Fatalf("mode = %q, want copy", res.Mode)
	}
	p := filepath.Join(proj, ".claude", "skills", SkillName, "SKILL.md")
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("copy mode produced a symlink, want real file")
	}
	got, _ := os.ReadFile(p)
	if string(got) != string(embeddedSkillMD(t)) {
		t.Fatal("copied content != embedded")
	}
}

func TestStatusDriftAndNeedsRefresh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := Install(Options{Scope: ScopeUser}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if NeedsRefresh() {
		t.Fatal("fresh install should not need refresh")
	}

	// Simulate a stale install: the materialized source (symlink target) carries
	// older content than the binary's embedded copy.
	src := filepath.Join(home, ".config", "wapps", "skills", SkillName, "SKILL.md")
	if err := os.WriteFile(src, []byte("OLD STALE CONTENT"), 0o644); err != nil {
		t.Fatalf("rewrite source: %v", err)
	}

	st, err := Status(Options{Scope: ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Installed {
		t.Fatal("should still be installed")
	}
	if st.UpToDate {
		t.Fatal("stale content should report not up to date")
	}
	if !NeedsRefresh() {
		t.Fatal("stale install should need refresh")
	}

	// Re-install repairs it (re-materializes the embedded content).
	if _, err := Install(Options{Scope: ScopeUser}); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if NeedsRefresh() {
		t.Fatal("reinstall should clear the drift")
	}
}

func TestUninstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := Install(Options{Scope: ScopeUser}); err != nil {
		t.Fatalf("install: %v", err)
	}
	removed, err := Uninstall(Options{Scope: ScopeUser})
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if removed == "" {
		t.Fatal("uninstall reported nothing removed")
	}
	if _, err := os.Lstat(removed); !os.IsNotExist(err) {
		t.Fatalf("dest still exists after uninstall: %v", err)
	}
	// Uninstalling again is a no-op.
	again, err := Uninstall(Options{Scope: ScopeUser})
	if err != nil || again != "" {
		t.Fatalf("second uninstall: removed=%q err=%v", again, err)
	}
}

func TestAutoRefresh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Never installed → no marker → auto-refresh must NOT create anything.
	if AutoRefresh() {
		t.Fatal("auto-refresh should be a no-op when never installed")
	}
	if _, err := os.Lstat(filepath.Join(home, ".claude", "skills", SkillName)); !os.IsNotExist(err) {
		t.Fatal("auto-refresh created an install out of nowhere")
	}

	// Install (symlink) → fresh, nothing to refresh.
	if _, err := Install(Options{Scope: ScopeUser}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if AutoRefresh() {
		t.Fatal("fresh install should not auto-refresh")
	}

	// Simulate an upgrade: source content + marker are from an older binary.
	srcDir := filepath.Join(home, ".config", "wapps", "skills", SkillName)
	if err := os.WriteFile(filepath.Join(srcDir, "SKILL.md"), []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, fingerprintFile), []byte("oldfingerprint"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !AutoRefresh() {
		t.Fatal("stale marker should trigger an auto-refresh")
	}
	// The symlinked content (read through ~/.claude link) is current again.
	link := filepath.Join(home, ".claude", "skills", SkillName, "SKILL.md")
	got, _ := os.ReadFile(link)
	if string(got) != string(embeddedSkillMD(t)) {
		t.Fatal("auto-refresh did not update the linked content")
	}
	// Idempotent afterwards.
	if AutoRefresh() {
		t.Fatal("second auto-refresh should be a no-op")
	}
}

func TestInstallReplacesStaleSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dest := filepath.Join(home, ".claude", "skills", SkillName)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-existing WRONG symlink (e.g. an older setup pointing at a repo path).
	if err := os.Symlink("/some/old/path/SKILL.md", filepath.Join(dest, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(Options{Scope: ScopeUser}); err != nil {
		t.Fatalf("install over stale link: %v", err)
	}
	st, err := Status(Options{Scope: ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if !st.UpToDate {
		t.Fatalf("install did not repair stale symlink: %+v", st)
	}
}
