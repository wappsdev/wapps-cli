// Package skill wires the `wapps skill` commands that install the AI-safe
// "wapps-secrets" Claude Code skill onto the machine.
package skill

import (
	"fmt"

	"github.com/spf13/cobra"
	skillpkg "github.com/wappsdev/wapps-cli/internal/skill"
)

var (
	flagLocal bool   // install into the current repo instead of user-wide
	flagDir   string // override the project dir for --local
	flagCopy  bool   // write real files instead of symlinks (committable)
)

// SkillCmd is the parent for `wapps skill ...`.
var SkillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage the wapps-secrets Claude Code skill (AI-safe secret handling)",
	Long: `Install the "wapps-secrets" skill that teaches AI coding agents
(Claude Code, Cursor, Aider) to handle this repo's secrets with apply-only
commands — never reading or printing raw values.

The skill files ship inside the wapps binary, so a Homebrew install needs no
repo checkout: ` + "`wapps skill install`" + ` materializes them and symlinks
them into place. Re-run it after ` + "`brew upgrade wapps`" + ` to refresh.`,
}

func init() {
	installCmd.Flags().BoolVar(&flagLocal, "local", false,
		"Install into the current repo's .claude/skills (project-based) instead of user-wide")
	installCmd.Flags().StringVar(&flagDir, "dir", "",
		"Project directory for --local (default: current directory)")
	installCmd.Flags().BoolVar(&flagCopy, "copy", false,
		"Write real files instead of symlinks (committable; recommended with --local)")

	uninstallCmd.Flags().BoolVar(&flagLocal, "local", false,
		"Uninstall from the current repo instead of user-wide")
	uninstallCmd.Flags().StringVar(&flagDir, "dir", "",
		"Project directory for --local (default: current directory)")

	SkillCmd.AddCommand(installCmd)
	SkillCmd.AddCommand(statusCmd)
	SkillCmd.AddCommand(uninstallCmd)
}

// scopeFromFlags maps --local/--dir to skill options. Default is user-wide.
func optsFromFlags() skillpkg.Options {
	opts := skillpkg.Options{Scope: skillpkg.ScopeUser, Copy: flagCopy}
	if flagLocal {
		opts.Scope = skillpkg.ScopeProject
		opts.ProjectDir = flagDir
	}
	return opts
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install the wapps-secrets skill (default: user-wide ~/.claude/skills)",
	Long: `Install the wapps-secrets skill.

  wapps skill install                  user-wide (~/.claude/skills) — recommended
  wapps skill install --local --copy   into ./.claude/skills as committable files
  wapps skill install --local --dir X  into X/.claude/skills

User-wide is the default: the skill is available in every repo, but its own
description only activates it where a .wapps.yaml exists.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := skillpkg.Install(optsFromFlags())
		if err != nil {
			return fmt.Errorf("install skill: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ wapps-secrets skill installed (%s, %s)\n", res.Scope, res.Mode)
		fmt.Fprintf(cmd.OutOrStdout(), "  → %s\n", res.Destination)
		if res.Mode == "symlink" {
			fmt.Fprintf(cmd.OutOrStdout(), "  source: %s (refreshed; re-run after `brew upgrade wapps`)\n", res.Source)
		}
		if res.Scope == skillpkg.ScopeProject && res.Mode == "symlink" {
			fmt.Fprintln(cmd.OutOrStdout(), "  note: symlinks point at a machine-local path — use --copy if you intend to commit them")
		}
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the wapps-secrets skill is installed and current",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		for _, sc := range []skillpkg.Scope{skillpkg.ScopeUser, skillpkg.ScopeProject} {
			opts := skillpkg.Options{Scope: sc, ProjectDir: flagDir}
			st, err := skillpkg.Status(opts)
			if err != nil {
				return err
			}
			switch {
			case !st.Installed:
				fmt.Fprintf(out, "✗ %-8s not installed (%s)\n", st.Scope.String(), st.Destination)
			case st.UpToDate:
				fmt.Fprintf(out, "✓ %-8s installed, up to date (%s, %s)\n", st.Scope.String(), st.Mode, st.Destination)
			default:
				fmt.Fprintf(out, "⚠ %-8s installed but OUT OF DATE — run `wapps skill install`%s (%s)\n",
					st.Scope.String(), localSuffix(sc), st.Destination)
			}
		}
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the wapps-secrets skill",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := optsFromFlags()
		removed, err := skillpkg.Uninstall(opts)
		if err != nil {
			return fmt.Errorf("uninstall skill: %w", err)
		}
		if removed == "" {
			fmt.Fprintln(cmd.OutOrStdout(), "nothing to remove (not installed)")
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ removed %s\n", removed)
		return nil
	},
}

func localSuffix(sc skillpkg.Scope) string {
	if sc == skillpkg.ScopeProject {
		return " --local"
	}
	return ""
}
