package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	coolifycmd "github.com/wappsdev/wapps-cli/cmd/coolify"
	deploycmd "github.com/wappsdev/wapps-cli/cmd/deploy"
	gitcmd "github.com/wappsdev/wapps-cli/cmd/git"
	"github.com/wappsdev/wapps-cli/cmd/secrets"
	skillcmd "github.com/wappsdev/wapps-cli/cmd/skill"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/git"
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
	noSync      bool
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
	Short:   "wapps umbrella CLI — Tofu monorepo helper for Coolify + age secrets + git auto-sync",
	Long: `wapps is the umbrella CLI for the wappsdev/infra-tofu monorepo.

It wraps:
  - age encryption (secret archive sync)
  - Coolify v4 REST API (gap shim for SierraJC Tofu provider)
  - git auto-sync preflight (pull latest secrets/all.enc.age before any read)
  - doctor (end-to-end dependency check)`,
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
		// gates config resolution, not git).
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

		if noSync {
			return nil
		}
		// Skip auto-sync for `doctor` (preflight) and `git status` (introspection)
		if cmd.Name() == "doctor" {
			return nil
		}
		if cmd.Parent() != nil && cmd.Parent().Name() == "git" {
			return nil
		}
		// Skip auto-sync for `skill` — it installs local files, never touches
		// the repo's encrypted secrets, so a git preflight would be pure noise.
		if skillCmdInvoked {
			return nil
		}

		// git preflight runs against configRoot (the .wapps.yaml dir) when
		// --config/--project is set, else cwd. The archive path stays
		// repo-relative (git.fileSha prefixes "./" itself).
		repoPath := "."
		archiveRel := "secrets/all.enc.age"
		if cfgFile != "" {
			repoPath = filepath.Dir(cfgFile)
			if cfg, err := config.Load(cfgFile); err == nil && cfg.Dest != "" {
				archiveRel = cfg.Dest
			}
		}
		// Robust outside a git repo (spec Fix 3): skip the preflight cleanly when
		// the target dir isn't a work tree, rather than relying on the soft-fail
		// warning. Covers --config pointing at a non-repo and bare cwd usage.
		if !git.IsRepo(repoPath) {
			return nil
		}

		drift, err := git.HasDrift(repoPath, archiveRel)
		if err != nil {
			// Non-fatal: warn and proceed (offline / fetch failure cases)
			fmt.Fprintf(cmd.ErrOrStderr(), "⚠ git fetch failed: %v (continuing; use --no-sync to silence)\n", err)
			return nil
		}
		if drift {
			fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Remote has newer %s — pulling...\n", archiveRel)
			if err := git.Pull(repoPath); err != nil {
				return fmt.Errorf("auto pull failed: %w. Resolve manually or use --no-sync", err)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "✓ Pulled latest")
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
		return err
	}
	cfgFile = filepath.Join(dir, ".wapps.yaml")
	return nil
}

func Execute() {
	err := rootCmd.Execute()

	// Best-effort "newer release available" notice, printed AFTER the command's
	// own output so it's the last thing the user sees. Never affects exit code.
	maybeNotifyUpdate()
	// After a `brew upgrade wapps`, an existing symlink install of the
	// wapps-secrets skill is refreshed in place automatically (no manual
	// re-install). Honors WAPPS_NO_UPDATE_CHECK; one-line notice on a TTY.
	maybeAutoRefreshSkill()

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	rootCmd.PersistentFlags().BoolVar(&noSync, "no-sync", false, "Skip git auto-sync preflight")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to a .wapps.yaml; secrets resolve against its dir (default: ./.wapps.yaml)")
	rootCmd.PersistentFlags().StringVarP(&projectName, "project", "p", "", "Registered project name (see ~/.config/wapps/projects.yaml); resolves to that project's .wapps.yaml")
	rootCmd.MarkFlagsMutuallyExclusive("config", "project")
	rootCmd.AddCommand(secrets.SecretsCmd)
	rootCmd.AddCommand(secrets.DrCmd)     // §9.5 disaster recovery (dr verify/restore/repin-genesis/verifier)
	rootCmd.AddCommand(secrets.EscrowCmd) // §9.1/§9.7 escrow ceremony (keygen + verify-canary)
	rootCmd.AddCommand(gitcmd.GitCmd)
	rootCmd.AddCommand(coolifycmd.CoolifyCmd)
	rootCmd.AddCommand(skillcmd.SkillCmd)
	rootCmd.AddCommand(deploycmd.DeployCmd)
}
