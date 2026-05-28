package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// HasDrift reports whether `file` differs between HEAD and the remote-
// tracking branch for the repo's default branch (origin/main, origin/master,
// or whatever `origin/HEAD` resolves to). Earlier versions hardcoded
// `origin/main`, which silently produced spurious drift=true on repos whose
// default is `master`/`trunk`/etc. — the local sha was real but the remote
// ref didn't exist, so fileSha returned "" and the comparison reported
// drift even when there was none.
//
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
	remoteRef, err := defaultRemoteRef(repoPath)
	if err != nil {
		return false, fmt.Errorf("git.HasDrift: resolve default remote ref: %w", err)
	}
	remoteSha, err := fileSha(repoPath, file, remoteRef)
	if err != nil {
		return false, fmt.Errorf("git.HasDrift: remote sha: %w", err)
	}
	return localSha != remoteSha, nil
}

// defaultRemoteRef returns the name of the remote-tracking branch that
// follows origin's HEAD (typically "origin/main", "origin/master", etc.).
// Falls back to "origin/main" if the symbolic ref isn't set so older repos
// with the previous hardcoded behavior keep working.
func defaultRemoteRef(repoPath string) (string, error) {
	out, err := runGit(repoPath, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
	if err != nil {
		// origin/HEAD may not be set on freshly cloned repos or test
		// fixtures. Fall back to origin/main — the previous behavior — so
		// we don't regress repos that worked before this change.
		return "origin/main", nil
	}
	return strings.TrimSpace(out), nil
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
	// Prefix the path with "./" so git treats it as cwd-relative regardless of
	// whether the caller invoked wapps from the git root or a subdirectory.
	// Without this, "HEAD:secrets/all.enc.age" is interpreted as git-root-relative,
	// which fails when the caller is inside a subproject (e.g.,
	// infra-tofu/projects/vaulter where the archive lives at
	// projects/vaulter/secrets/all.enc.age in git-root terms).
	path := file
	if !strings.HasPrefix(path, "./") && !strings.HasPrefix(path, "/") {
		path = "./" + path
	}
	out, err := runGit(repoPath, "rev-parse", ref+":"+path)
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
