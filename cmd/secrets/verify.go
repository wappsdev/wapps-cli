package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Drift check: Tofu output sha vs age archive sha",
	RunE: func(cmd *cobra.Command, args []string) error {
		passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
		if passphrase == "" {
			return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
		}

		liveOut, err := tofu.Output()
		if err != nil {
			return fmt.Errorf("verify: tofu output: %w", err)
		}
		liveSha := sha256.Sum256(liveOut)

		enc, err := os.ReadFile("secrets/all.enc.age")
		if err != nil {
			return fmt.Errorf("verify: read archive: %w", err)
		}
		dec, err := ageutil.Decrypt(enc, passphrase)
		if err != nil {
			return fmt.Errorf("verify: decrypt: %w", err)
		}
		archiveSha := sha256.Sum256(dec)

		if liveSha == archiveSha {
			fmt.Println("✓ Tofu state and age archive in sync")
			return nil
		}
		fmt.Printf("⚠ Drift detected:\n  live:    %s\n  archive: %s\n", hex.EncodeToString(liveSha[:8]), hex.EncodeToString(archiveSha[:8]))
		fmt.Println("Run: wapps secrets sync")
		return fmt.Errorf("drift")
	},
}

func init() {
	SecretsCmd.AddCommand(verifyCmd)
}
