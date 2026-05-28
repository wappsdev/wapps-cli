package secrets

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// gitShowRunner shells out to `git show <ref>:./<path>`. The ./ prefix makes
// the path cwd-relative regardless of whether wapps was invoked from the
// repo root or a subdirectory (same fix as internal/git.fileSha).
//
// Safety: exec.Command takes argv directly (no shell), and we refuse refs
// that start with '-' so a value like "--upload-pack=evil" can't slip past
// git's option parser. Git's own ref naming rules already forbid leading
// dashes (git-check-ref-format(1)), so this validation never rejects a
// legitimate ref. We don't use a `--` end-of-options separator here because
// after `--` git interprets positionals as pathspecs, not as `<ref>:<path>`
// object specs — that would silently break the command.
func gitShowRunner(ref, path string) ([]byte, error) {
	if strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("git show: ref %q starts with '-' (refusing — looks like a flag, not a revision)", ref)
	}
	gitPath := path
	if !strings.HasPrefix(gitPath, "./") && !strings.HasPrefix(gitPath, "/") {
		gitPath = "./" + gitPath
	}
	cmd := exec.Command("git", "show", ref+":"+gitPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git show %s:%s: %w: %s", ref, path, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
