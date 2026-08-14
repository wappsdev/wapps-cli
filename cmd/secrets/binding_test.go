package secrets

// binding_test.go, repo→proje bağlamasının SÖZLEŞMESİNİ pinler. Dört ayrı kural
// var ve dördü de birbirinden bağımsız olarak kırılabilir:
//
//   1. Pinsiz + İNSAN + TTY  → satır içi sorulur, "evet" pinler ve devam eder.
//   2. Pinsiz + AJAN         → asla sorulmaz, fail-closed. Pinin gerçekten iş
//                              gördüğü tek yer: uydurulmuş bir .wapps.yaml kendi
//                              başına bir proje talep edemesin.
//   3. UYUŞMAZLIK            → satır içi ÇÖZÜLMEZ. Yeni bağlama sıradan; var olan
//                              bir bağlamayı değiştirmek kasıtlı bir karar ister.
//   4. Monorepo              → aynı repo'daki iki config AYRI parmak izi alır.

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

// stubBindPrompt, satır içi soruyu sabit bir cevapla değiştirir + çağrıldı mı sayar.
func stubBindPrompt(t *testing.T, answer bool) *int {
	t.Helper()
	calls := 0
	prev := bindPrompt
	bindPrompt = func(string, string) bool { calls++; return answer }
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
	// Pin KALICI olmalı: ikinci çağrı bir daha sormamalı.
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

// Ajan ASLA sorulmaz — sorulsaydı ajan "evet" derdi ve guard hiçbir şey yapmazdı.
func TestBinding_Agent_NeverPrompts(t *testing.T) {
	setupStoreProjectUnpinned(t, "")
	stubTTY(t, true) // TTY olsa BİLE
	calls := stubBindPrompt(t, true)

	err := checkRepoBinding(true)
	if !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("agent must fail closed, got %v", err)
	}
	if *calls != 0 {
		t.Errorf("agent must never be prompted, got %d prompts", *calls)
	}
}

// TTY yoksa (pipe/script) soramayız — sormuş gibi yapıp pinlemek de olmaz.
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

// Config PİNLİ OLANDAN BAŞKA bir projeyi talep ediyorsa satır içi çözülmez.
func TestBinding_Mismatch_NeverPrompts(t *testing.T) {
	tmp := setupStoreProjectUnpinned(t, "")
	// Repo'yu BAŞKA bir projeye pinle, config ise "testproj" diyor.
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

// Monorepo: aynı git repo'sundaki iki config AYRI parmak izi almalı, yoksa
// biri pinlenince diğeri erişilemez olur (infra-tofu'da tam olarak bu oldu).
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
