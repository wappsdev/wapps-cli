package secrets

// binding_test.go pins the CONTRACT of the repo→project binding. There are
// four separate rules and each can break independently of the others:
//
//   1. Unpinned + HUMAN + TTY → asked inline; "yes" pins and continues.
//   2. Unpinned + AGENT       → never asked, fail-closed. The one place the pin
//                               really works: a forged .wapps.yaml must not
//                               claim a project on its own.
//   3. MISMATCH               → NEVER resolved inline. A new binding is
//                               ordinary; changing an existing one takes a
//                               deliberate decision.
//   4. Monorepo               → two configs in one repo get SEPARATE fingerprints.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
)

// stubBindPrompt replaces the inline question with a fixed answer and counts calls.
func stubBindPrompt(t *testing.T, answer bool) *int {
	t.Helper()
	calls := 0
	prev := bindPrompt
	bindPrompt = func(string, *config.WappsYAML) bool { calls++; return answer }
	t.Cleanup(func() { bindPrompt = prev })
	return &calls
}

func stubTTY(t *testing.T, isTTY bool) {
	t.Helper()
	prev := stdinIsTTY
	stdinIsTTY = func() bool { return isTTY }
	t.Cleanup(func() { stdinIsTTY = prev })
}

func TestBinding_UnpinnedHumanTTY_PromptsAndPins(t *testing.T) {
	setupStoreProjectUnpinned(t, "")
	stubTTY(t, true)
	calls := stubBindPrompt(t, true)

	if err := checkRepoBinding(false); err != nil {
		t.Fatalf("accepted prompt must pin and proceed, got %v", err)
	}
	if *calls != 1 {
		t.Fatalf("expected exactly one prompt, got %d", *calls)
	}
	// The pin must PERSIST: a second call must not ask again.
	if err := checkRepoBinding(false); err != nil {
		t.Fatalf("second call must use the saved pin, got %v", err)
	}
	if *calls != 1 {
		t.Errorf("binding must be asked once per repo, got %d prompts", *calls)
	}
}

func TestBinding_UnpinnedHumanDeclines_StaysUnpinned(t *testing.T) {
	setupStoreProjectUnpinned(t, "")
	stubTTY(t, true)
	stubBindPrompt(t, false)

	err := checkRepoBinding(false)
	if !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("declining must leave it unpinned, got %v", err)
	}
}

// An agent is NEVER asked; if it were, it would answer "yes" and the guard would do nothing.
func TestBinding_Agent_NeverPrompts(t *testing.T) {
	setupStoreProjectUnpinned(t, "")
	stubTTY(t, true) // EVEN with a TTY
	calls := stubBindPrompt(t, true)

	err := checkRepoBinding(true)
	if !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("agent must fail closed, got %v", err)
	}
	if *calls != 0 {
		t.Errorf("agent must never be prompted, got %d prompts", *calls)
	}
}

// Without a TTY (pipe/script) we cannot ask, and pinning as if we had is not allowed either.
func TestBinding_HumanNoTTY_NeverPrompts(t *testing.T) {
	setupStoreProjectUnpinned(t, "")
	stubTTY(t, false)
	calls := stubBindPrompt(t, true)

	if err := checkRepoBinding(false); !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("no TTY must fail closed, got %v", err)
	}
	if *calls != 0 {
		t.Errorf("must not prompt without a TTY, got %d", *calls)
	}
}

// A config claiming a project OTHER than the pinned one is not resolved inline.
func TestBinding_Mismatch_NeverPrompts(t *testing.T) {
	tmp := setupStoreProjectUnpinned(t, "")
	// Pin the repo to ANOTHER project while the config says "testproj".
	path, err := binding.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	st, err := binding.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(tmp)
	st.Pin(binding.Fingerprint(abs), binding.Pin{Repo: abs, Project: "someone-else", Backend: "store"})
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}

	stubTTY(t, true)
	calls := stubBindPrompt(t, true)

	err = checkRepoBinding(false)
	if err == nil || !strings.Contains(err.Error(), "different project") {
		t.Fatalf("a mismatch must fail loudly, got %v", err)
	}
	if *calls != 0 {
		t.Errorf("a mismatch must never be resolved by an inline prompt, got %d", *calls)
	}
}

// Monorepo: two configs in the same git repo must get SEPARATE fingerprints,
// or pinning one makes the other unreachable (exactly what happened in infra-tofu).
func TestRepoIdentity_MonorepoProjectsDoNotCollide(t *testing.T) {
	repo := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(repo, "init", "-q")
	run(repo, "remote", "add", "origin", "https://github.com/acme/monorepo.git")

	ids := map[string]string{}
	for _, proj := range []string{"alpha", "beta"} {
		dir := filepath.Join(repo, "projects", proj)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		yaml := "version: 2\nproject: " + proj + "\n"
		if err := os.WriteFile(filepath.Join(dir, ".wapps.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, cerr := config.Load(filepath.Join(dir, ".wapps.yaml"))
		if cerr != nil {
			t.Fatal(cerr)
		}
		ids[proj] = repoIdentity(cfg)
	}
	if ids["alpha"] == ids["beta"] {
		t.Fatalf("two projects in one repo must not share a fingerprint; both = %q", ids["alpha"])
	}
	for _, p := range []string{"alpha", "beta"} {
		if !strings.Contains(ids[p], "projects/"+p) {
			t.Errorf("identity for %s should carry its path in the repo, got %q", p, ids[p])
		}
	}
}

// Worktrees must share the SAME pin as the main repo. navlun has 25 worktrees;
// separate identities would mean 25 binding questions and 25 separate
// BINDING_UNPINNED refusals on the agent side.
func TestRepoIdentity_WorktreeSharesMainRepoPin(t *testing.T) {
	main := t.TempDir()
	git := func(dir string, args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(main, "init", "-q")
	git(main, "config", "user.email", "t@t.t")
	git(main, "config", "user.name", "t")
	yaml := "version: 2\nproject: navlun-app\n"
	if err := os.WriteFile(filepath.Join(main, ".wapps.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	git(main, "add", ".")
	git(main, "commit", "-qm", "init")

	wt := filepath.Join(t.TempDir(), "wt")
	git(main, "worktree", "add", "-q", wt)

	mainID := repoIdentity(mustCfg(t, filepath.Join(main, ".wapps.yaml")))
	wtID := repoIdentity(mustCfg(t, filepath.Join(wt, ".wapps.yaml")))

	if mainID != wtID {
		t.Fatalf("a worktree must share the main repo's identity:\n  main = %q\n  wt   = %q", mainID, wtID)
	}
}

func mustCfg(t *testing.T, path string) *config.WappsYAML {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
