package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// HasDrift reports whether `file` differs between HEAD and origin/main.
// Errors are returned to the caller; the soft-fail (warn + proceed) is the
// caller's policy decision (see cmd/root.go PersistentPreRunE for the preflight
// soft-fail behavior).
func HasDrift(repoPath, file string) (bool, error) {
	if out, err := runGit(repoPath, "fetch", "--quiet"); err != nil {
		return false, fmt.Errorf("git.HasDrift: fetch: %w: %s", err, strings.TrimSpace(out))
	}
	localSha, err := fileSha(repoPath, file, "HEAD")
	if err != nil {
		return false, fmt.Errorf("git.HasDrift: local sha: %w", err)
	}
	remoteSha, err := fileSha(repoPath, file, "origin/main")
	if err != nil {
		return false, fmt.Errorf("git.HasDrift: remote sha: %w", err)
	}
	return localSha != remoteSha, nil
}

// Pull runs `git pull --rebase` in repoPath.
func Pull(repoPath string) error {
	out, err := runGit(repoPath, "pull", "--rebase")
	if err != nil {
		return fmt.Errorf("git.Pull: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// IsRepo returns true if repoPath is inside a git work tree.
func IsRepo(repoPath string) bool {
	_, err := runGit(repoPath, "rev-parse", "--is-inside-work-tree")
	return err == nil
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func fileSha(repoPath, file, ref string) (string, error) {
	out, err := runGit(repoPath, "rev-parse", ref+":"+file)
	if err != nil {
		// "exists in" and "Path 'X' does not exist in 'Y'" → file missing in that ref.
		// Return empty sha (treated as "no entry" by caller; missing-in-both = no drift).
		// Other git errors (bad revision, repo corruption, ambiguous ref) propagate up.
		o := strings.ToLower(out)
		if strings.Contains(o, "does not exist in") || strings.Contains(o, "exists on disk, but not in") {
			return "", nil
		}
		return "", fmt.Errorf("git.fileSha: %s:%s: %w: %s", ref, file, err, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}
