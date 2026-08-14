package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	initForce       bool
	initProjectName string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold .wapps.yaml for a fresh repo",
	Long: `Initialize wapps secrets in the current repo.

Creates a single file — .wapps.yaml — naming the project this repo reads from
in the secrets gate. Nothing encrypted is written to the repo: values live
server-side and are fetched on demand.

An existing .wapps.yaml is never overwritten unless --force is passed.

After init: 'wapps login', then 'wapps secrets trust-repo' to pin this repo to
the project, then 'wapps secrets set <KEY>'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInitStore(".", initProjectName, initForce)
	},
}

// runInitStore, v2 backend:store config'ini iskeletler (SPEC §6.1): yerel
// arşiv/secrets dizini YOKTUR — değerler gate'te yaşar. Sonraki adımlar:
// login → trust-repo → set.
func runInitStore(repoRoot, project string, force bool) error {
	if project == "" {
		abs, err := filepath.Abs(repoRoot)
		if err != nil {
			return fmt.Errorf("secrets.init: resolve repo root: %w", err)
		}
		project = filepath.Base(abs)
	}
	yamlPath := filepath.Join(repoRoot, ".wapps.yaml")
	if existing, err := os.Stat(yamlPath); err == nil && !existing.IsDir() && !force {
		return fmt.Errorf("secrets.init: %s already exists (use --force to overwrite)", yamlPath)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("secrets.init: stat %s: %w", yamlPath, err)
	}
	if err := writeWappsYAMLStore(yamlPath, project); err != nil {
		return err
	}
	fmt.Println("✓ wapps init complete (backend: store)")
	fmt.Println("  +", yamlPath)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. wapps login                 # CF Access browser SSO")
	fmt.Println("  2. wapps secrets trust-repo    # pin this repo to project " + project)
	fmt.Println("  3. wapps secrets set <KEY>     # first set creates the manifest chain")
	fmt.Println("     (an admin adds policy rows: wapps secrets policy set)")
	return nil
}

// writeWappsYAMLStore, v2 backend:store template'ini yazar (server-decrypt
// SPEC §6.1: yeni proje = init → ilk set manifest zincirini kurar; policy
// satırları admin tarafından eklenir). Değerler Worker store'unda yaşar;
// yerel arşiv/passphrase YOKTUR.
func writeWappsYAMLStore(path, project string) error {
	var b strings.Builder
	b.WriteString("# wapps-cli configuration\n")
	b.WriteString("# Docs: https://github.com/wappsdev/wapps-cli\n")
	b.WriteString("\n")
	b.WriteString("version: 2\n")
	b.WriteString("# The project this repo reads from in the secrets gate.\n")
	b.WriteString("project: " + project + "\n")
	b.WriteString("\n")
	b.WriteString("# Optional consumption targets. 'wapps secrets apply' materializes these\n")
	b.WriteString("# from the store — atomic, mode 0600, idempotent. Gitignore them.\n")
	b.WriteString("# targets:\n")
	b.WriteString("#   - path: .env.local\n")
	b.WriteString("#     prefix: \"\"\n")
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("secrets.init: write %s: %w", path, err)
	}
	return nil
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false,
		"overwrite an existing .wapps.yaml (default refuses to clobber)")
	initCmd.Flags().StringVar(&initProjectName, "project-name", "",
		"project name in the gate (default: current directory name)")
	SecretsCmd.AddCommand(initCmd)
}
