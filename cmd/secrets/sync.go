package secrets

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Tofu output → secrets/all.enc.age (suggest commit)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return syncWithTofuOutput(tofu.Output, "secrets/all.enc.age")
	},
}

func syncWithTofuOutput(outputFn func() ([]byte, error), destPath string) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	out, err := outputFn()
	if err != nil {
		return fmt.Errorf("secrets.sync: tofu output: %w", err)
	}

	encrypted, err := ageutil.Encrypt(out, passphrase)
	if err != nil {
		return fmt.Errorf("secrets.sync: encrypt: %w", err)
	}

	if err := os.WriteFile(destPath, encrypted, 0600); err != nil {
		return fmt.Errorf("secrets.sync: write: %w", err)
	}

	fmt.Printf("✓ Wrote %s (%d bytes)\n", destPath, len(encrypted))
	// Split "+" + "%Y-%m-%d" emits the literal shell snippet "$(date +%Y-%m-%d)"
	// for the user's shell to evaluate. Combined into one literal would trigger
	// go vet's printf format-string check (treating %Y/%m/%d as Go format verbs).
	dateFmt := "+" + "%Y-%m-%d"
	fmt.Printf("Next: git add secrets/all.enc.age && git commit -m 'chore: secret sync $(date %s)'\n", dateFmt)
	return nil
}

func init() {
	SecretsCmd.AddCommand(syncCmd)
}
