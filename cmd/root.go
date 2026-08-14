package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	coolifycmd "github.com/wappsdev/wapps-cli/cmd/coolify"
	deploycmd "github.com/wappsdev/wapps-cli/cmd/deploy"
	"github.com/wappsdev/wapps-cli/cmd/secrets"
	skillcmd "github.com/wappsdev/wapps-cli/cmd/skill"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/projects"
	skillpkg "github.com/wappsdev/wapps-cli/internal/skill"
	"github.com/wappsdev/wapps-cli/internal/updatecheck"
	"golang.org/x/term"
)

// Version is set at link time by GoReleaser via:
//
//	-ldflags="-X github.com/wappsdev/wapps-cli/cmd.Version=<tag>"
//
// Local builds (go build/install without ldflags) carry "dev" so support
// can see the binary came from an untagged build.
var Version = "dev"

var (
	verbose     bool
	cfgFile     string
	projectName string
	// skillCmdInvoked is set by PersistentPreRunE when the running command is
	// `skill ...`, so the post-command auto-refresh doesn't double-print a
	// "refreshed" notice on top of `skill install`'s own output.
	skillCmdInvoked bool
)

var rootCmd = &cobra.Command{
	Use:     "wapps",
	Version: Version,
	Short:   "wapps umbrella CLI — secrets, Tofu, Coolify and deploys for the wappsdev estate",
	Long: `wapps is the umbrella CLI for the wappsdev estate.

It wraps:
  - the secrets gate (server-side decryption; values never touch git)
  - Tofu (wapps tofu — project secrets injected as TF_VAR_*)
  - Coolify v4 REST API (gap shim for the SierraJC Tofu provider)
  - deploys through the company deploy-proxy
  - doctor (end-to-end dependency + access check)`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Record a `skill ...` invocation up front (before any early return) so
		// the post-command skill auto-refresh stays quiet for it. Cobra-resolved,
		// so flag-before-subcommand forms (`wapps --no-sync skill install`) are
		// handled correctly — an os.Args[1] check would miss those.
		if cmd.Name() == "skill" || (cmd.Parent() != nil && cmd.Parent().Name() == "skill") {
			skillCmdInvoked = true
		}

		// Resolve --project → cfgFile first, then hand the resolved config path
		// to the secrets package so its loaders + path resolution use the
		// config dir (configRoot), not cwd. This runs even under --no-sync (it
		// gates config resolution).
		if err := resolveProjectFlag(); err != nil {
			return err
		}
		if cfgFile != "" {
			abs, err := filepath.Abs(cfgFile)
			if err != nil {
				return fmt.Errorf("resolve --config path: %w", err)
			}
			secrets.SetConfigPath(abs)
		}

		return nil
	},
}

// resolveProjectFlag turns --project <name> into cfgFile = <dir>/.wapps.yaml via
// the registry. No-op when --project is unset. cobra's
// MarkFlagsMutuallyExclusive already rejects --config + --project at parse time;
// the explicit check here covers programmatic/test invocation that bypasses
// cobra parsing.
func resolveProjectFlag() error {
	if projectName == "" {
		return nil
	}
	if cfgFile != "" {
		return fmt.Errorf("--config and --project are mutually exclusive")
	}
	dir, err := projects.Resolve(projectName)
	if err != nil {
		// Kayıt defterinde YOKSA bu bir hata DEĞİLDİR: store'un ihtiyacı olan tek
		// şey proje ADI. list/get/rm/projects yerel dosyaya hiç bakmadığından
		// `--project navlun-app` her dizinden çalışır. Yerel dosya GEREKTİREN
		// verb'ler (apply/sync/exec/env — targets/sources okurlar) kendi net
		// "no .wapps.yaml found" hatasını verir.
		secrets.SetProjectName(projectName)
		return nil
	}
	cfgFile = filepath.Join(dir, ".wapps.yaml")
	return nil
}

func Execute() {
	// SilenceErrors/SilenceUsage: cobra hatayı KENDİSİ basıyordu, sonra aşağıdaki
	// blok bir kez daha basıyordu — kullanıcı aynı satırı iki kez, kurtarma
	// satırını ise HİÇ görmüyordu. Basma işi tek yerde toplandı. Usage dökümü de
	// susturuldu: bir binding/oturum hatasına 20 satır bayrak listesi eklemek
	// gerçek mesajı gömüyor (`--help` elbette çalışmaya devam eder).
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	err := rootCmd.Execute()

	// Best-effort "newer release available" notice, printed AFTER the command's
	// own output so it's the last thing the user sees. Never affects exit code.
	maybeNotifyUpdate()
	// After a `brew upgrade wapps`, an existing symlink install of the
	// wapps-secrets skill is refreshed in place automatically (no manual
	// re-install). Honors WAPPS_NO_UPDATE_CHECK; one-line notice on a TTY.
	maybeAutoRefreshSkill()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// KURTARMA SATIRI: clierr kayıt defteri her kod için "ne yapmalı"yı
		// taşıyor ama Error() onu içermediğinden bugüne dek hiç basılmamıştı.
		// Hatanın yarısı buydu: kullanıcı neyin yanlış olduğunu görüyor, nasıl
		// düzelteceğini görmüyordu.
		if rec := clierr.RecoveryOf(err); rec != "" {
			fmt.Fprintf(os.Stderr, "  → %s\n", rec)
		}
		os.Exit(1)
	}
}

// maybeNotifyUpdate gates the update check so it only runs in interactive
// sessions and never in CI/scripts/pipes:
//   - WAPPS_NO_UPDATE_CHECK set → fully disabled (opt-out for any context)
//   - stderr is not a TTY → skip (piped output, CI logs, cron)
//
// The version/semver gating (skip "dev" and "main-<sha>" local builds) lives
// in updatecheck.MaybeNotify itself.
func maybeNotifyUpdate() {
	if os.Getenv("WAPPS_NO_UPDATE_CHECK") != "" {
		return
	}
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	updatecheck.MaybeNotify(os.Stderr, updatecheck.Options{CurrentVersion: Version})
}

// maybeAutoRefreshSkill brings an existing symlink install of the wapps-secrets
// skill up to date with this binary's embedded copy, in place. The refresh runs
// even non-interactively (so CI gets the current skill) but only when a prior
// symlink install exists; the confirmation line is printed on a TTY only. Stays
// quiet during `wapps skill ...` (those commands manage the skill explicitly)
// and honors WAPPS_NO_UPDATE_CHECK as a full opt-out.
func maybeAutoRefreshSkill() {
	if os.Getenv("WAPPS_NO_UPDATE_CHECK") != "" {
		return
	}
	if skillCmdInvoked {
		// `skill ...` manages the skill explicitly; don't double-report.
		return
	}
	if skillpkg.AutoRefresh() && term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintln(os.Stderr, "✓ wapps-secrets skill refreshed to match the new wapps version.")
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to a .wapps.yaml; secrets resolve against its dir (default: ./.wapps.yaml)")
	rootCmd.PersistentFlags().StringVarP(&projectName, "project", "p", "", "Registered project name (see ~/.config/wapps/projects.yaml); resolves to that project's .wapps.yaml")
	rootCmd.MarkFlagsMutuallyExclusive("config", "project")
	rootCmd.AddCommand(secrets.SecretsCmd)
	rootCmd.AddCommand(secrets.DrCmd)       // §8.4 disaster recovery (dr verify/restore — B2 replica + Shamir shares)
	rootCmd.AddCommand(secrets.RotateCmd)   // rotasyon worklist yönetimi (rotate skip — kayıtlı SKIP kaçış kapısı)
	rootCmd.AddCommand(secrets.ProjectsCmd) // proje kavramı sırlardan bağımsız → kökte
	rootCmd.AddCommand(secrets.TofuCmd)     // birinci-sınıf `wapps tofu` (secrets exec --prefix '' -- tofu sarımı)
	rootCmd.AddCommand(coolifycmd.CoolifyCmd)
	rootCmd.AddCommand(skillcmd.SkillCmd)
	rootCmd.AddCommand(deploycmd.DeployCmd)
}
