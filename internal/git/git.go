package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func HasDrift(repoPath, file string) (bool, error) {
	// 1. Fetch (best-effort — if offline, return false to skip drift check)
	if out, err := runGit(repoPath, "fetch", "--quiet"); err != nil {
		// Network failures shouldn't block local operations
		return false, fmt.Errorf("git fetch: %w: %s", err, out)
	}
	// 2. Compare local vs origin/main SHA for file
	localSha, err := fileSha(repoPath, file, "HEAD")
	if err != nil {
		return false, fmt.Errorf("local sha: %w", err)
	}
	remoteSha, err := fileSha(repoPath, file, "origin/main")
	if err != nil {
		return false, fmt.Errorf("remote sha: %w", err)
	}
	return localSha != remoteSha, nil
}

func Pull(repoPath string) error {
	out, err := runGit(repoPath, "pull", "--rebase")
	if err != nil {
		return fmt.Errorf("git pull: %w: %s", err, out)
	}
	return nil
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
		// File may not exist yet — return empty sha (treated as "no drift" by caller)
		if strings.Contains(out, "does not exist") || strings.Contains(out, "fatal:") {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(out), nil
}
