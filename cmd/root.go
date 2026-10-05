package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	coolifycmd "github.com/wappsdev/wapps-cli/cmd/coolify"
	deploycmd "github.com/wappsdev/wapps-cli/cmd/deploy"
	"github.com/wappsdev/wapps-cli/cmd/secrets"
	skillcmd "github.com/wappsdev/wapps-cli/cmd/skill"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
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
		// NOT being in the registry is not an error: all the store needs is the
		// project NAME. list/get/rm/projects never look at a local file, so
		// `--project navlun-app` works from any directory. The verbs that DO
		// need the local file (apply/sync/exec/env read targets/sources) give
		// their own clear "no .wapps.yaml found" error.
		secrets.SetProjectName(projectName)
		return nil
	}
	cfgFile = filepath.Join(dir, ".wapps.yaml")
	return nil
}

func Execute() {
	// SilenceErrors/SilenceUsage: cobra used to print the error ITSELF and the
	// block below printed it again — the user saw the same line twice and the
	// recovery line NEVER. Printing now happens in one place. The usage dump is
	// silenced too: 20 lines of flags appended to a binding/session error bury
	// the real message (`--help` of course still works).
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
		reportError(os.Stderr, err, agentmode.IsAgent())
		os.Exit(1)
	}
}

// reportError is the CLI's ONLY error printer, and it picks the FORMAT by reader.
//
// The contract has one axis: the `agent` flag is the SAME detection
// (agentmode.IsAgent(), §7.4.1) that already gates the verbs. So a refusal and
// the FORMAT of that refusal cannot diverge — a verb refused in agent mode
// reports its error in the agent format.
//
//   - human terminal → UNCHANGED: "Error: <sentence>" + "  → <recovery>".
//     Replacing a sentence with a JSON line would be a regression for a human.
//   - agent/CI (agent marker or non-TTY stdin) → the SPEC §7.5 envelope: ONE
//     line of JSON on stderr. Having to parse a sentence is the reason the
//     contract exists.
//
// The two formats are never printed side by side: "one line" is part of the
// envelope's contract, and the human side does not want JSON noise. Every
// reader sees EXACTLY one rendering.
func reportError(w io.Writer, err error, agent bool) {
	if err == nil {
		return
	}
	if agent {
		// The envelope carries the code, message, recovery and retryable ITSELF.
		clierr.Emit(w, err)
		return
	}
	fmt.Fprintf(w, "Error: %v\n", err)
	// RECOVERY LINE: the clierr registry carries "what to do" for every code,
	// but Error() does not include it, so it had never been printed. That was
	// half of the bug: the user saw what was wrong, not how to fix it.
	if rec := clierr.RecoveryOf(err); rec != "" {
		fmt.Fprintf(w, "  → %s\n", rec)
	}
}

// maybeNotifyUpdate gates the update check so it only runs in interactive
// sessions and never in CI/scripts/pipes:
//   - WAPPS_NO_UPDATE_CHECK set → fully disabled (opt-out for any context)
//   - stderr is not a TTY → skip (piped output, CI logs, cron)
//   - agent/CI context → skip; stderr there carries the JSON error envelope
//     and a stray notice line would break whoever parses it
//
// The version/semver gating (skip "dev" and "main-<sha>" local builds) lives
// in updatecheck.MaybeNotify itself.
func maybeNotifyUpdate() {
	if !humanNoticesEnabled(os.Getenv("WAPPS_NO_UPDATE_CHECK") != "",
		term.IsTerminal(int(os.Stderr.Fd())), agentmode.IsAgent()) {
		return
	}
	updatecheck.MaybeNotify(os.Stderr, updatecheck.Options{
		CurrentVersion: Version,
		// WAPPS_UPDATE_CHECK_URL replaces the GitHub releases endpoint; unset or
		// empty, the default applies. It exists so the Rust port's differential
		// can point both binaries at a fake releases server: the default is
		// HTTPS to api.github.com, which no test can stand in for. Whatever the
		// server answers, only digits and dots reach the terminal (MaybeNotify).
		APIURL: os.Getenv("WAPPS_UPDATE_CHECK_URL"),
	})
}

// humanNoticesEnabled says whether the human-only SIDE notices ("a new version
// is available", "skill refreshed") are printed.
//
// In agent mode stderr is a CONTRACT CHANNEL: reportError writes a one-line
// JSON envelope there, and every extra line breaks whoever parses it. The old
// condition only looked at stderr being a TTY — but stdin can be a pipe WHILE
// stderr is a terminal (`cat cfg | wapps ...`), and in that context the reader
// is an agent. Whether the notice is for a human is the SAME question as which
// error format to print, so it uses the same axis.
func humanNoticesEnabled(noUpdateCheck, stderrIsTTY, agent bool) bool {
	return !noUpdateCheck && stderrIsTTY && !agent
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
	// The refresh RUNS in agent mode too (so CI gets the current skill); only
	// the notice line is for humans.
	if skillpkg.AutoRefresh() && humanNoticesEnabled(false,
		term.IsTerminal(int(os.Stderr.Fd())), agentmode.IsAgent()) {
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
	rootCmd.AddCommand(secrets.RotateCmd)   // rotation worklist management (rotate skip — the recorded SKIP escape hatch)
	rootCmd.AddCommand(secrets.ProjectsCmd) // projects are independent of secrets → on the root
	rootCmd.AddCommand(secrets.TofuCmd)     // first-class `wapps tofu` (wraps secrets exec --prefix '' -- tofu)
	rootCmd.AddCommand(coolifycmd.CoolifyCmd)
	rootCmd.AddCommand(skillcmd.SkillCmd)
	rootCmd.AddCommand(deploycmd.DeployCmd)
}
