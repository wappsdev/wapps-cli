package git

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDriftDetectsAhead(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	bare := filepath.Join(tmp, "bare.git")

	mustRun(t, "git", "init", "--bare", bare)
	mustRun(t, "git", "clone", bare, repo)
	mustRun(t, "git", "-C", repo, "config", "user.email", "test@x")
	mustRun(t, "git", "-C", repo, "config", "user.name", "test")
	mustRun(t, "git", "-C", repo, "config", "commit.gpgsign", "false")

	// Create initial file + push
	mustRun(t, "mkdir", "-p", filepath.Join(repo, "secrets"))
	mustRun(t, "sh", "-c", "echo a > "+filepath.Join(repo, "secrets/all.enc.age"))
	mustRun(t, "git", "-C", repo, "add", ".")
	mustRun(t, "git", "-C", repo, "commit", "-m", "init")
	mustRun(t, "git", "-C", repo, "push", "origin", "HEAD:main")
	mustRun(t, "git", "-C", repo, "branch", "--set-upstream-to=origin/main")

	// Detect drift — no changes since push, should be false
	drift, err := HasDrift(repo, "secrets/all.enc.age")
	if err != nil {
		t.Fatalf("HasDrift unexpected error: %v", err)
	}
	if drift {
		t.Errorf("Expected no drift on fresh push state")
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
