package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	initWithFileSource bool
	initForce          bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold .wapps.yaml + secrets/ for a fresh repo (idempotent)",
	Long: `Initialize wapps secrets in the current repo.

Creates:
  .wapps.yaml             template config with a single tofu source
                          (add --with-file-source to also declare .env.shared)
  secrets/                directory (mode 0755)
  secrets/.gitignore      excludes rotation.log (sensitive pp fingerprints)

What is NOT created:
  secrets/all.enc.age     run 'wapps secrets sync' (or set/import-env) to
                          create the archive

Existing files are left alone unless --force is passed. Pre-existing
.wapps.yaml is never overwritten — operators get a warning + skip.

After init, set WAPPS_SECRETS_PASSPHRASE, populate .env.shared (if file
source) or set up your tofu project (if tofu source), then run
'wapps secrets sync'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInit(".", initWithFileSource, initForce)
	},
}

// runInit scaffolds the wapps directory layout at repoRoot. withFile adds
// a file source declaration to the template. force overwrites existing
// .wapps.yaml (default false — protects against accidental config wipe).
func runInit(repoRoot string, withFile, force bool) error {
	yamlPath := filepath.Join(repoRoot, ".wapps.yaml")
	secretsDir := filepath.Join(repoRoot, "secrets")
	gitignorePath := filepath.Join(secretsDir, ".gitignore")

	created := []string{}
	skipped := []string{}

	// .wapps.yaml — refuse to clobber unless --force.
	if existing, err := os.Stat(yamlPath); err == nil && !existing.IsDir() {
		if !force {
			skipped = append(skipped, yamlPath+" (already exists, use --force to overwrite)")
		} else {
			if err := writeWappsYAML(yamlPath, withFile); err != nil {
				return err
			}
			created = append(created, yamlPath+" (overwrote)")
		}
	} else if os.IsNotExist(err) {
		if err := writeWappsYAML(yamlPath, withFile); err != nil {
			return err
		}
		created = append(created, yamlPath)
	} else if err != nil {
		return fmt.Errorf("secrets.init: stat %s: %w", yamlPath, err)
	}

	// secrets/ directory.
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		return fmt.Errorf("secrets.init: mkdir %s: %w", secretsDir, err)
	}
	created = append(created, secretsDir+"/")

	// secrets/.gitignore — append rotation.log if not already excluded.
	if err := ensureGitignore(gitignorePath); err != nil {
		return err
	}
	created = append(created, gitignorePath)

	// Output summary.
	fmt.Println("✓ wapps init complete")
	for _, p := range created {
		fmt.Println("  +", p)
	}
	for _, p := range skipped {
		fmt.Println("  -", p)
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  1. export WAPPS_SECRETS_PASSPHRASE=<your-passphrase>")
	if withFile {
		fmt.Println("  2. Add KEY=VALUE lines to .env.shared (or run: wapps secrets set <KEY>)")
		fmt.Println("  3. wapps secrets sync")
	} else {
		fmt.Println("  2. Confirm 'tofu output -json' works in this directory")
		fmt.Println("  3. wapps doctor --for tofu")
		fmt.Println("  4. wapps secrets sync")
	}
	return nil
}

func writeWappsYAML(path string, withFile bool) error {
	var b strings.Builder
	b.WriteString("# wapps-cli configuration\n")
	b.WriteString("# Docs: https://github.com/wappsdev/wapps-cli\n")
	b.WriteString("\n")
	b.WriteString("version: 1\n")
	b.WriteString("dest: secrets/all.enc.age\n")
	b.WriteString("sources:\n")
	b.WriteString("  - type: tofu\n")
	b.WriteString("    workdir: .\n")
	b.WriteString("    prefix: \"TF_VAR_\"\n")
	if withFile {
		b.WriteString("  - type: file\n")
		b.WriteString("    path: .env.shared\n")
		b.WriteString("    prefix: \"\"\n")
	}
	b.WriteString("\n")
	b.WriteString("# Optional consumption targets. 'wapps secrets apply' (and set/sync)\n")
	b.WriteString("# materialize these from the archive — atomic, mode 0600, idempotent.\n")
	b.WriteString("# Add them to your repo-root .gitignore.\n")
	b.WriteString("# targets:\n")
	b.WriteString("#   - path: .env.local\n")
	b.WriteString("#     prefix: \"\"\n")
	b.WriteString("\n")
	b.WriteString("# Set redact_in_logs / require_clean_git to harden behavior.\n")
	b.WriteString("redact_in_logs: true\n")
	b.WriteString("require_clean_git: true\n")

	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("secrets.init: write %s: %w", path, err)
	}
	return nil
}

// ensureGitignore creates or appends to secrets/.gitignore so rotation.log
// (which contains pp fingerprints) never gets committed. We APPEND rather
// than overwrite so any operator-added entries are preserved.
func ensureGitignore(path string) error {
	const rotationLogEntry = "rotation.log"

	existing, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// Fresh file.
		body := "# wapps-cli — sensitive runtime artifacts\nrotation.log\n"
		return os.WriteFile(path, []byte(body), 0644)
	}
	if err != nil {
		return fmt.Errorf("secrets.init: read gitignore: %w", err)
	}
	if strings.Contains(string(existing), rotationLogEntry) {
		// Already present, leave file alone.
		return nil
	}
	// Append entry preserving existing content.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("secrets.init: open gitignore for append: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString("\n# wapps-cli — sensitive runtime artifacts\nrotation.log\n"); err != nil {
		return fmt.Errorf("secrets.init: append gitignore: %w", err)
	}
	return nil
}

func init() {
	initCmd.Flags().BoolVar(&initWithFileSource, "with-file-source", false,
		"include a 'file' source declaration for .env.shared (non-Tofu repos)")
	initCmd.Flags().BoolVar(&initForce, "force", false,
		"overwrite existing .wapps.yaml (default refuses to clobber)")
	SecretsCmd.AddCommand(initCmd)
}
