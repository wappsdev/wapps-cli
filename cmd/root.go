package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	coolifycmd "github.com/wappsdev/wapps-cli/cmd/coolify"
	gitcmd "github.com/wappsdev/wapps-cli/cmd/git"
	"github.com/wappsdev/wapps-cli/cmd/secrets"
	"github.com/wappsdev/wapps-cli/internal/git"
	"github.com/wappsdev/wapps-cli/internal/updatecheck"
	"golang.org/x/term"
)

// Version is set at link time by GoReleaser via:
//   -ldflags="-X github.com/wappsdev/wapps-cli/cmd.Version=<tag>"
// Local builds (go build/install without ldflags) carry "dev" so support
// can see the binary came from an untagged build.
var Version = "dev"

var (
	noSync  bool
	verbose bool
	cfgFile string
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
		drift, err := git.HasDrift(".", "secrets/all.enc.age")
		if err != nil {
			// Non-fatal: warn and proceed (offline / not-a-repo cases)
			fmt.Fprintf(cmd.ErrOrStderr(), "⚠ git fetch failed: %v (continuing; use --no-sync to silence)\n", err)
			return nil
		}
		if drift {
			fmt.Fprintln(cmd.ErrOrStderr(), "⚠ Remote has newer secrets/all.enc.age — pulling...")
			if err := git.Pull("."); err != nil {
				return fmt.Errorf("auto pull failed: %w. Resolve manually or use --no-sync", err)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "✓ Pulled latest")
		}
		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()

	// Best-effort "newer release available" notice, printed AFTER the command's
	// own output so it's the last thing the user sees. Never affects exit code.
	maybeNotifyUpdate()

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

func init() {
	rootCmd.PersistentFlags().BoolVar(&noSync, "no-sync", false, "Skip git auto-sync preflight")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default: ./.wapps.yaml)")
	rootCmd.AddCommand(secrets.SecretsCmd)
	rootCmd.AddCommand(gitcmd.GitCmd)
	rootCmd.AddCommand(coolifycmd.CoolifyCmd)
}
