// Package skill installs the "wapps-secrets" Claude Code skill that ships
// embedded in the wapps binary.
//
// Why embed: a Homebrew-installed binary has no repo checkout, so the skill
// files (SKILL.md and any future references) travel INSIDE the binary. On
// `wapps skill install` we materialize them to a stable on-disk source dir
// (~/.config/wapps/skills) and symlink them into ~/.claude/skills (user) or a
// repo's .claude/skills (project). The symlink source is refreshed on every
// install, so re-running after `brew upgrade wapps` updates the linked content
// in place — no stale skill.
//
// Apply-only safety note: this package never reads or prints secret values; it
// only writes the skill documentation files.
package skill

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

//go:embed all:assets
var assets embed.FS

// SkillName is the directory name under .claude/skills/.
const SkillName = "wapps-secrets"

// assetRoot is the embed path that holds the skill's files.
const assetRoot = "assets/" + SkillName

// Scope selects where the skill is installed.
type Scope int

const (
	// ScopeUser installs into ~/.claude/skills — available in every repo. The
	// skill's own front-matter description gates activation to repos that have
	// a .wapps.yaml, so a user-wide install is not noisy. This is the default.
	ScopeUser Scope = iota
	// ScopeProject installs into <dir>/.claude/skills — scoped to one repo
	// (e.g. to commit it so teammates/CI get it without per-user setup).
	ScopeProject
)

func (s Scope) String() string {
	if s == ScopeProject {
		return "project"
	}
	return "user"
}

// Options configures an install/status call.
type Options struct {
	Scope Scope
	// ProjectDir is the repo root for ScopeProject (default: current dir).
	ProjectDir string
	// Copy writes real files instead of symlinks. Real files are committable
	// (a symlink into ~/.config/wapps is machine-specific), so prefer Copy when
	// installing into a repo you intend to commit.
	Copy bool
}

// Result describes what an install did.
type Result struct {
	Scope       Scope
	Destination string   // the .claude/skills/<name> dir
	Source      string   // materialized symlink source (empty when Copy)
	Files       []string // dest file paths written/linked
	Mode        string   // "symlink" or "copy"
}

// embeddedFiles returns relative-path -> content for every embedded skill file.
func embeddedFiles() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := fs.WalkDir(assets, assetRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		b, err := assets.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(assetRoot, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	return out, err
}

// Fingerprint is a stable content hash over all embedded skill files. It is
// written next to the materialized source so a later run can detect drift
// (an installed skill older than the running binary's embedded copy).
func Fingerprint() (string, error) {
	files, err := embeddedFiles()
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00", n)
		h.Write(files[n])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

const fingerprintFile = ".fingerprint"

// sourceDir is the stable location symlinks point at. It lives under the same
// ~/.config/wapps tree the CLI already uses, survives brew upgrades, and is
// re-materialized on every install.
func sourceDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "wapps", "skills", SkillName), nil
}

// skillsBase resolves the .claude/skills directory for the given scope.
func skillsBase(opts Options) (string, error) {
	switch opts.Scope {
	case ScopeProject:
		dir := opts.ProjectDir
		if dir == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return "", err
			}
			dir = cwd
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		return filepath.Join(abs, ".claude", "skills"), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".claude", "skills"), nil
	}
}

// materialize writes the embedded files into sourceDir (overwriting) plus a
// fingerprint marker, and returns the dir. This is the symlink target.
func materialize() (string, error) {
	dir, err := sourceDir()
	if err != nil {
		return "", err
	}
	files, err := embeddedFiles()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for rel, content := range files {
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		if err := writeFileAtomic(dst, content, 0o644); err != nil {
			return "", err
		}
	}
	fp, err := Fingerprint()
	if err == nil {
		_ = writeFileAtomic(filepath.Join(dir, fingerprintFile), []byte(fp), 0o644)
	}
	return dir, nil
}

// writeFileAtomic writes via a temp file + rename so a concurrent reader never
// sees a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wapps-skill-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Install materializes the embedded skill and installs it for the given scope.
// Symlink mode (default) links each file to the refreshed source; Copy mode
// writes real, committable files. Idempotent: a correct existing install is
// left untouched; a stale link or wrong file is replaced.
func Install(opts Options) (Result, error) {
	base, err := skillsBase(opts)
	if err != nil {
		return Result{}, err
	}
	dest := filepath.Join(base, SkillName)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return Result{}, err
	}
	files, err := embeddedFiles()
	if err != nil {
		return Result{}, err
	}

	res := Result{Scope: opts.Scope, Destination: dest}

	if opts.Copy {
		res.Mode = "copy"
		for rel, content := range files {
			p := filepath.Join(dest, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return Result{}, err
			}
			if err := writeFileAtomic(p, content, 0o644); err != nil {
				return Result{}, err
			}
			res.Files = append(res.Files, p)
		}
		sort.Strings(res.Files)
		return res, nil
	}

	// Symlink mode: refresh the stable source, then FILE-symlink each file.
	srcDir, err := materialize()
	if err != nil {
		return Result{}, err
	}
	res.Mode = "symlink"
	res.Source = srcDir
	for rel := range files {
		link := filepath.Join(dest, filepath.FromSlash(rel))
		target := filepath.Join(srcDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			return Result{}, err
		}
		// Idempotent: keep a correct symlink, replace anything else.
		if cur, err := os.Readlink(link); err == nil && cur == target {
			res.Files = append(res.Files, link)
			continue
		}
		_ = os.Remove(link) // wrong symlink, or a real file from an older copy install
		if err := os.Symlink(target, link); err != nil {
			return Result{}, err
		}
		res.Files = append(res.Files, link)
	}
	sort.Strings(res.Files)
	return res, nil
}

// State is the installed status for one scope.
type State struct {
	Scope       Scope
	Destination string
	Installed   bool
	Mode        string // "symlink", "copy", or "" when not installed
	UpToDate    bool   // installed content matches the binary's embedded copy
	Target      string // symlink target (symlink mode)
}

// Status reports whether the skill is installed for the scope and whether its
// content matches the running binary's embedded copy.
func Status(opts Options) (State, error) {
	base, err := skillsBase(opts)
	if err != nil {
		return State{}, err
	}
	dest := filepath.Join(base, SkillName)
	st := State{Scope: opts.Scope, Destination: dest}

	files, err := embeddedFiles()
	if err != nil {
		return st, err
	}

	allPresent := true
	allMatch := true
	sawSymlink := false
	for rel, content := range files {
		p := filepath.Join(dest, filepath.FromSlash(rel))
		fi, err := os.Lstat(p)
		if err != nil {
			allPresent = false
			allMatch = false
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			sawSymlink = true
			if tgt, err := os.Readlink(p); err == nil {
				st.Target = tgt
			}
		}
		// Resolve through symlinks for the content compare.
		got, err := os.ReadFile(p)
		if err != nil || string(got) != string(content) {
			allMatch = false
		}
	}
	st.Installed = allPresent
	st.UpToDate = allPresent && allMatch
	if allPresent {
		if sawSymlink {
			st.Mode = "symlink"
		} else {
			st.Mode = "copy"
		}
	}
	return st, nil
}

// Uninstall removes the skill from the given scope (its .claude/skills/<name>
// dir). The materialized source under ~/.config/wapps is left in place (other
// scopes may still link to it). Returns the removed path.
func Uninstall(opts Options) (string, error) {
	base, err := skillsBase(opts)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(base, SkillName)
	if _, err := os.Lstat(dest); err != nil {
		return "", nil // nothing installed
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", err
	}
	return dest, nil
}

// NeedsRefresh reports whether the USER-scope skill is installed but its content
// no longer matches the binary's embedded copy (the post-`brew upgrade` case).
// Best-effort and side-effect free: returns false on any error or when the
// skill is not installed (so users who never installed it are not nagged).
func NeedsRefresh() bool {
	st, err := Status(Options{Scope: ScopeUser})
	if err != nil {
		return false
	}
	return st.Installed && !st.UpToDate
}

// AutoRefresh updates an existing symlink-mode install IN PLACE when the
// binary's embedded skill is newer than the materialized source — the
// post-`brew upgrade` case. Because every symlink install points its links at
// the single ~/.config/wapps source, rewriting that source updates the linked
// content with no re-linking.
//
// It is deliberately narrow and safe:
//   - only acts when a prior symlink install left a .fingerprint marker (so it
//     never auto-creates an install the user didn't ask for);
//   - never touches copy-mode installs (committed repo files the user manages);
//   - best-effort — returns false on any error or when already current.
//
// Returns true only when it actually rewrote the source.
func AutoRefresh() bool {
	dir, err := sourceDir()
	if err != nil {
		return false
	}
	marker, err := os.ReadFile(filepath.Join(dir, fingerprintFile))
	if err != nil {
		return false // never symlink-installed → nothing to refresh
	}
	want, err := Fingerprint()
	if err != nil {
		return false
	}
	if string(marker) == want {
		return false // already current
	}
	if _, err := materialize(); err != nil {
		return false
	}
	return true
}
