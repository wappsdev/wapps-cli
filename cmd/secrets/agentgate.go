package secrets

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"golang.org/x/term"
)

// agentPolicy is the agent-mode class of every secrets verb (SPEC §7.1). It is
// the CENTRAL registry: a verb missing from this map counts as fail-closed
// REFUSED ("unannotated new verbs default to REFUSED"), so a verb author must
// add theirs here explicitly. Subcommand families (policy show/set/lint,
// projects list/rm) are keyed by the first-level name UNDER SecretsCmd
// (gateKey), so "policy set" can never INHERIT the data-plane "set" permission.
var agentPolicy = map[string]string{
	// Data-plane writes and reads: agent allowed (policy.json authorizes on the server).
	"exec":       agentmode.PolicyAllow, // --break-glass is refused in RunE
	"apply":      agentmode.PolicyAllow,
	"set":        agentmode.PolicyAllow,
	"import-env": agentmode.PolicyAllow,
	"sync":       agentmode.PolicyAllow,
	"rotate":     agentmode.PolicyAllow,
	"init":       agentmode.PolicyAllow,
	"list":       agentmode.PolicyAllow,
	"env":        agentmode.PolicyAllow, // the print form is refused in RunE (§7.1)
	"status":     agentmode.PolicyAllow,
	// A surface that prints secret values: agent refused.
	"get": agentmode.PolicyRefuseAgent,
	// IRREVERSIBLE destructive surface: agent refused. The server already
	// requires a separate `delete` grant (§4.2 rev4); this is the client-side
	// second lock.
	"rm": agentmode.PolicyRefuseAgent,
	// The TTY-only pin verb.
	"trust-repo": agentmode.PolicyTTY,
	// Control plane (SPEC §7.1): policy editing and rotate-plan are admin ops
	// (write-AUD, 15-minute WebAuthn session): agent gets CONTROL_PLANE_REQUIRED.
	"policy":      agentmode.PolicyControl,
	"rotate-plan": agentmode.PolicyControl,
}

// bindingExempt lists the verbs exempt from the repo→project binding check:
// trust-repo (it CREATES the binding), status (must be safe in every state).
// policy/rotate-plan are GLOBAL admin ops, not tied to a repo→project binding.
var bindingExempt = map[string]bool{
	"trust-repo":  true,
	"status":      true,
	"policy":      true,
	"rotate-plan": true,
}

func init() {
	// Run SecretsCmd's own hook WITHOUT overriding the parent's
	// PersistentPreRunE (root: config resolve): every PersistentPreRunE in the
	// chain runs, root to leaf.
	cobra.EnableTraverseRunHooks = true
	SecretsCmd.PersistentPreRunE = secretsPreRunE
}

// gateKey returns the gating key: the first-level command name UNDER
// SecretsCmd. For a leaf subcommand (e.g. `policy set`) the family's name
// ("policy") is used, so a leaf name that collides with a data-plane verb
// cannot inherit the wrong permission.
func gateKey(cmd *cobra.Command) string {
	name := cmd.Name()
	for c := cmd; c != nil; c = c.Parent() {
		p := c.Parent()
		if p != nil && p.Name() == "secrets" {
			name = c.Name()
			break
		}
	}
	return name
}

// secretsPreRunE applies agent-mode gating and the repo→project binding pin
// before EVERY secrets verb (SPEC §7.1). Living on SecretsCmd, no verb can
// forget it; an unannotated verb is fail-closed REFUSED.
func secretsPreRunE(cmd *cobra.Command, _ []string) error {
	// A group command (bare `wapps secrets` / `wapps secrets policy`) or help: no gating.
	if !cmd.Runnable() || cmd.Name() == "secrets" {
		return nil
	}
	isAgent := agentmode.IsAgent()
	key := gateKey(cmd)
	policy := agentPolicy[key] // missing → "" → Guard is fail-closed REFUSED
	if err := agentmode.Guard(policy, isAgent); err != nil {
		return err
	}
	if bindingExempt[key] {
		return nil
	}
	return checkRepoBinding(isAgent)
}

// checkRepoBinding verifies that a config's repo→project binding is pinned in
// the TRUSTED home dir (SPEC §7.1 trust-repo).
//   - unpinned → BINDING_UNPINNED (an agent can never pin; a human runs trust-repo
//     or answers the inline prompt)
//   - a different project → hard fail (re-pinning takes a human)
//   - service principal (CI) → the pin check is SKIPPED (see below)
func checkRepoBinding(isAgent bool) error {
	// A bare `--project <name>` (not in the registry): there is NO repo to bind.
	// For a HUMAN this names the target explicitly on the command line, which is
	// not the confused-deputy case the pin guards. For an AGENT it is: the pin
	// exists precisely so that an agent in repo A cannot read project B, and
	// being able to type --project does not authorize it → fail-closed.
	if projectOverride != "" {
		if isAgent {
			// The recovery line is overridden: there is NO repo to pin, so the
			// registry's default "run trust-repo" would be meaningless here.
			return clierr.Newf(clierr.BindingUnpinned,
				"--project %q names a project with no local repo; an agent may not target a project this way", projectOverride).
				WithRecovery("a human must run this in a terminal, or work inside the project's repo")
		}
		return nil
	}
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil || cfg == nil {
		return nil // no config → no binding check
	}
	// Service principal (P1.8): when the CF Access service-token PAIR is set in
	// the env, the repo-pin check is skipped. trust-repo (TTY) is impossible in
	// a fresh CI container; without this exemption EVERY Woodpecker step that
	// consumes the store would die with BINDING_UNPINNED. The confused-deputy
	// risk is already bounded server-side by per-key policy (`service:` selector
	// rules, worker/src/policy.ts). With only HALF of the pair set there is NO
	// bypass; fail-closed behaviour stays as is.
	//
	// SECURITY CONSTRAINT (fresh-eyes P3): this exemption removes the per-repo
	// confused-deputy containment; the only check left is the server-side
	// per-key policy. It is safe ONLY while service tokens are PER-PROJECT
	// scoped (each repo uses its own tofu-minted `repo_seed` token, plan P3.6;
	// scope policy: infra-tofu/docs/SECURITY-token-scopes.md). A broad-scope
	// (multi-project) service token could cross the project boundary through
	// this exemption, so provisioning must ALWAYS stay narrow.
	if serviceTokenPairSet() {
		return nil
	}
	repoID := repoIdentity(cfg)
	fp := binding.Fingerprint(repoID)

	path, err := binding.DefaultPath()
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "resolve repo-pins path")
	}
	store, err := binding.Load(path)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "load repo pins")
	}
	cerr := store.Check(fp, cfg.Project)
	if cerr == nil {
		return nil
	}
	if errors.Is(cerr, binding.ErrMismatch) {
		// A MISMATCH is never resolved inline. It means the config claims a
		// project OTHER than the pinned one, which is the very reason the pin
		// exists. A new binding (below) is ordinary and harmless; CHANGING a
		// binding takes a deliberate decision: an explicit trust-repo.
		return clierr.Newf(clierr.BindingUnpinned,
			"repo is pinned to a different project than %q; re-pin required", cfg.Project).
			WithRecovery("if this is intended, run: wapps secrets trust-repo")
	}

	// From here on the binding is UNPINNED: it has never been set up.
	//
	// Agent/CI → fail-closed. This is where the pin really does its work: a
	// forged or compromised .wapps.yaml must not claim a project on its own.
	// An agent being able to write that file does not authorize it.
	if isAgent {
		return clierr.Newf(clierr.BindingUnpinned, "repo→project binding for %q is not pinned", cfg.Project)
	}
	// A human without a TTY (pipe/script): we cannot ask, so we do not pretend to.
	if !stdinIsTTY() {
		return clierr.Newf(clierr.BindingUnpinned, "repo→project binding for %q is not pinned", cfg.Project)
	}
	// A human at a terminal: coming to this directory and typing the command is
	// a statement of intent. We ask HERE instead of teaching a separate command;
	// the security is the same (a human still confirms) and the friction is one
	// key per repo. The project is shown BY NAME, because seeing which project
	// is claimed is exactly what is protected, and so is every source a sync
	// would read (owner decision B, see syncReadsBlock).
	if !bindPrompt(repoID, cfg) {
		return clierr.Newf(clierr.BindingUnpinned, "not pinned; binding declined for %q", cfg.Project)
	}
	store.Pin(fp, binding.Pin{Repo: repoID, Project: cfg.Project, Backend: cfg.Backend})
	if serr := store.Save(path); serr != nil {
		return clierr.Wrapf(clierr.Internal, serr, "save repo pin")
	}
	fmt.Fprintf(os.Stderr, "✓ bound this repo to project %q (change it later with: wapps secrets trust-repo)\n", cfg.Project)
	return nil
}

// bindPrompt asks a human to confirm an unpinned binding inline. Package seam:
// tests replace it so they never block on stdin.
var bindPrompt = func(repoID string, cfg *config.WappsYAML) bool {
	fmt.Fprint(os.Stderr, bindPromptText(repoID, cfg))
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(sc.Text()))
	return a == "y" || a == "yes"
}

// bindPromptText is the inline binding question: the repo, the project it
// claims, and every source a sync of this config would read. Every
// user-controlled string passes through visible.
func bindPromptText(repoID string, cfg *config.WappsYAML) string {
	return "This repo is not bound to a project yet.\n" +
		"  repo:    " + visible(repoID) + "\n" +
		"  project: " + visible(cfg.Project) + "\n" +
		syncReadsBlock(cfg) +
		"Bind them? [y/N]: "
}

// syncReadsBlock lists the sources `wapps secrets sync` would read for cfg,
// resolved against the config root and cleaned, one per line, with the ones
// outside the config root marked. Empty when no source is declared.
//
// Owner decision (B), 2026-10-05: a source may name any file (a relative
// "../" path or an absolute one is deliberate, "secrets-from-anywhere"), so a
// cloned repository's .wapps.yaml can point sync at ~/.ssh/id_rsa. Pinning a
// binding is what lets a later sync (or an agent) run without asking, so the
// human who pins is shown exactly what that sync will read.
//
// Containment is decided on the RESOLVED path (realPath of the source and of
// the root), so a symlink inside the root that points out is marked. When the
// path resolves somewhere other than where it reads, the resolved target is
// shown after "->". Every string in the block passes through visible, so a
// path cannot carry a terminal escape that redraws the prompt.
func syncReadsBlock(cfg *config.WappsYAML) string {
	srcs := cfg.ResolvedSources()
	if len(srcs) == 0 {
		return ""
	}
	root := cfg.ConfigRoot()
	realRoot := realPath(root)
	var b strings.Builder
	b.WriteString("  sync reads:\n")
	for _, s := range srcs {
		raw := s.Path
		if s.Type == "tofu" {
			raw = s.Workdir
		}
		p := filepath.Clean(raw)
		// The kernel resolves the RAW path (an absolute source reaches the
		// reader uncleaned, and "link/.." is the link target's parent).
		real := realPath(raw)
		b.WriteString("    " + visible(s.Type) + " " + visible(p))
		if real != expectedRealPath(p, root, realRoot) {
			b.WriteString(" -> " + visible(real))
		}
		if !withinRoot(real, realRoot) {
			b.WriteString(" (outside the config root)")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// expectedRealPath is where p would resolve if no symlink below the root
// were involved: under the resolved root when p is lexically inside it, p
// itself otherwise. A resolved path that differs from it is shown.
func expectedRealPath(p, root, realRoot string) string {
	if !withinRoot(p, root) {
		return p
	}
	return filepath.Join(realRoot, strings.TrimPrefix(p, root))
}

// withinRoot reports whether the cleaned path p is root or lies under it,
// component-wise ("/ab" is not under "/a"). It is lexical: callers that need
// symlinks resolved pass realPath results.
func withinRoot(p, root string) bool {
	if root == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

// maxLinkHops bounds the symlinks realPath follows past a missing component
// (Linux's MAXSYMLINKS), so a link loop ends.
const maxLinkHops = 40

// realPath resolves every symlink in the absolute path p, the way the kernel
// does when sync opens it. An existing path is filepath.EvalSymlinks'. A path
// that does not exist yet is resolved through its longest existing ancestor:
// the parent is resolved, and the last component is followed when it is a
// (dangling) symlink or appended when it is absent, so a link to a file that
// appears later still shows where it points. A relative path, or a link chain
// longer than maxLinkHops, falls back to the lexical filepath.Clean. The Rust
// twin (configctx::real_path) is the same walk.
func realPath(p string) string { return realPathHops(p, 0) }

func realPathHops(p string, hops int) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if hops > maxLinkHops || !strings.HasPrefix(p, "/") {
		return filepath.Clean(p)
	}
	i := strings.LastIndex(p, "/")
	dir, base := p[:i], p[i+1:]
	if dir == "" {
		dir = "/"
	}
	d := realPathHops(dir, hops)
	switch base {
	case "", ".":
		return d
	case "..":
		return filepath.Dir(d)
	}
	c := filepath.Join(d, base)
	if t, err := os.Readlink(c); err == nil {
		if !strings.HasPrefix(t, "/") {
			t = d + "/" + t
		}
		return realPathHops(t, hops+1)
	}
	return c
}

// visible renders s for a terminal: printable text is kept, and every
// control character (C0, DEL, C1), Unicode space other than ' ', and format
// character (Cf, which holds the bidi overrides) becomes a Go-style escape
// (\n, \x1b, \u202e, \U000e0041), as do bytes that are not UTF-8 (\xff).
// A path from a cloned repository's .wapps.yaml cannot then erase or forge a
// line of the prompt. A backslash is printable and is kept as is. The set is
// spelled out (not unicode.IsPrint) so the Rust twin (configctx::visible)
// escapes exactly the same code points.
func visible(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\a':
			b.WriteString(`\a`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\v':
			b.WriteString(`\v`)
		case r < ' ' || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x80:
			b.WriteRune(r)
		case unicode.IsControl(r) || (unicode.IsSpace(r) && r != ' ') || isFormat(r):
			if r < 0x10000 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// isFormat reports the Unicode Cf (format) characters, the same table as the
// Rust port's gostrconv::is_format.
func isFormat(r rune) bool {
	switch {
	case r == 0x00AD, r >= 0x0600 && r <= 0x0605, r == 0x061C, r == 0x06DD, r == 0x070F,
		r >= 0x0890 && r <= 0x0891, r == 0x08E2, r == 0x180E, r >= 0x200B && r <= 0x200F,
		r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x206F,
		r == 0xFEFF, r >= 0xFFF9 && r <= 0xFFFB, r == 0x110BD, r == 0x110CD,
		r >= 0x13430 && r <= 0x1343F, r >= 0x1BCA0 && r <= 0x1BCA3,
		r >= 0x1D173 && r <= 0x1D17A, r == 0xE0001, r >= 0xE0020 && r <= 0xE007F:
		return true
	}
	return false
}

// stdinIsTTY reports whether an inline question can be asked (package seam:
// false in tests).
var stdinIsTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// repoIdentity returns the stable identity of the bound unit. That unit is NOT
// the repo but "this .wapps.yaml": the origin URL plus the config's path
// relative to the repo root.
//
// Why the path is included: the identity used to be the origin URL alone, so
// EVERY project in a monorepo collapsed onto one fingerprint. infra-tofu hosts
// five projects (vaulter, lab, vibe-pro, platform, secrets-gate); once one was
// pinned the other four became UNREACHABLE with "repo is pinned to a different
// project". Adding the path makes the relation many-to-many: a project can be
// used from several repos, a repo can serve several projects.
//
// When the config sits at the repo ROOT the identity stays the bare URL, so
// existing pins of single-project repos stay valid (no re-pin needed) and the
// checkouts of one repo keep sharing the pin.
func repoIdentity(cfg *config.WappsYAML) string {
	root := cfg.ConfigRoot()
	if root == "" {
		root = "."
	}
	sub := gitRepoSubpath(root)
	// With an origin the identity binds to it: every checkout of the repo shares the pin.
	if url := gitRemoteURL(root); url != "" {
		if sub != "" {
			return url + "#" + sub
		}
		return url
	}
	// WITHOUT an origin (a local repo) the MAIN repo root is used, NOT the
	// worktree's own root. Otherwise every worktree would get its own identity:
	// navlun's 25 worktrees would mean 25 binding questions and 25 separate
	// BINDING_UNPINNED refusals on the agent side. git --git-common-dir points
	// at the same .git from a worktree and from the main repo, so they all meet
	// in one pin.
	if main := gitMainRepoRoot(root); main != "" {
		if sub != "" {
			return main + "#" + sub
		}
		return main
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	return abs
}

// gitMainRepoRoot returns the root of the MAIN working tree (even when called
// from a worktree), or "" outside a git repo.
func gitMainRepoRoot(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--path-format=absolute", "--git-common-dir").Output()
	if err != nil {
		return ""
	}
	gitDir := strings.TrimSpace(string(out))
	if gitDir == "" {
		return ""
	}
	return filepath.Dir(gitDir)
}

// gitRepoSubpath returns dir's path relative to its git root ("" = the root itself).
func gitRepoSubpath(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-prefix").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(string(out)), "/")
}

// serviceTokenPairSet reports whether BOTH halves of the CF Access service
// token pair (CF_ACCESS_CLIENT_ID + CF_ACCESS_CLIENT_SECRET) are set. The read
// matches the non-interactive auth path's TrimSpace (cmd/login.go path 1)
// exactly, so "auth passes but the pin exemption does not" cannot happen.
func serviceTokenPairSet() bool {
	return strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_ID")) != "" &&
		strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_SECRET")) != ""
}

// gitRemoteURL returns `git -C <dir> remote get-url origin`, or "" on error or empty output.
func gitRemoteURL(dir string) string {
	out, err := exec.Command("git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
