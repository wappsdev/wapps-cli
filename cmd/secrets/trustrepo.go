package secrets

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
)

var trustRepoCmd = &cobra.Command{
	Use:   "trust-repo",
	Short: "Pin this repo's .wapps.yaml → project binding (TTY only, §7.7)",
	Long: `A .wapps.yaml names a project, but a repo file is attacker-writable
content (confused-deputy seam). trust-repo pins the (repo → project) binding in
the TRUSTED home dir (~/.config/wapps/repo-pins.json), NOT in the repo. An agent
hitting an unpinned store-backed binding is refused (BINDING_UNPINNED); only a
human at a terminal can pin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTrustRepo(cmd.OutOrStdout(), cmd.InOrStdin(), agentmode.IsAgent())
	},
}

// runTrustRepo, trust-repo verb'ünün üretim sürücüsüdür: TTY zorunlu, config
// store-backed olmalı, kullanıcı onayı alınır, sonra bağlama pinlenir.
func runTrustRepo(out io.Writer, in io.Reader, isAgent bool) error {
	if isAgent {
		return clierr.New(clierr.BindingUnpinned, "trust-repo must run in a human terminal")
	}
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil {
		return err
	}
	if cfg == nil || !cfg.IsStoreBackend() {
		return clierr.New(clierr.Internal, "trust-repo applies only to a backend: store .wapps.yaml")
	}
	repoID := repoIdentity(cfg)
	path, err := binding.DefaultPath()
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "resolve repo-pins path")
	}
	confirm := func() bool {
		r := bufio.NewReader(in)
		line, _ := r.ReadString('\n')
		return strings.EqualFold(strings.TrimSpace(line), "y")
	}
	return trustRepoCore(cfg, repoID, path, confirm, out)
}

// trustRepoCore, TTY/onay seam'lerini enjekte edilmiş biçimiyle çekirdek pinleme
// mantığıdır (test-edilebilir). Çözülen proje/profil/backend gösterilir, onay
// alınır, bağlama GÜVENİLEN home-dir'de pinlenir.
func trustRepoCore(cfg *config.WappsYAML, repoID, bindingPath string, confirm func() bool, out io.Writer) error {
	fp := binding.Fingerprint(repoID)

	fmt.Fprintf(out, "Pin repo→project binding:\n")
	fmt.Fprintf(out, "  repo:    %s\n", repoID)
	fmt.Fprintf(out, "  project: %s\n", cfg.Project)
	fmt.Fprintf(out, "  backend: %s\n", cfg.Backend)
	if len(cfg.Profiles) > 0 {
		names := make([]string, 0, len(cfg.Profiles))
		for n := range cfg.Profiles {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(out, "  profiles: %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(out, "Pin this binding? [y/N]: ")

	if !confirm() {
		return clierr.New(clierr.BindingUnpinned, "trust-repo aborted; binding not pinned")
	}

	store, err := binding.Load(bindingPath)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "load repo pins")
	}
	store.Pin(fp, binding.Pin{Repo: repoID, Project: cfg.Project, Backend: cfg.Backend})
	if err := store.Save(bindingPath); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "save repo pins")
	}
	fmt.Fprintf(out, "pinned %s → %s\n", shortRepo(repoID), cfg.Project)
	return nil
}

// shortRepo, uzun bir repo kimliğini görüntü için kısaltır (değer değil).
func shortRepo(s string) string {
	if len(s) > 60 {
		return "…" + s[len(s)-59:]
	}
	return s
}

func init() {
	SecretsCmd.AddCommand(trustRepoCmd)
}
