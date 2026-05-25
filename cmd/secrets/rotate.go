package secrets

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var rotateMasterCmd = &cobra.Command{
	Use:   "rotate-master",
	Short: "Re-encrypt archive with NEW master passphrase (interactive)",
	RunE: func(cmd *cobra.Command, args []string) error {
		oldPass := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
		if oldPass == "" {
			return fmt.Errorf("set WAPPS_SECRETS_PASSPHRASE (current passphrase)")
		}
		newPass := os.Getenv("WAPPS_SECRETS_PASSPHRASE_NEW")
		if newPass == "" {
			return fmt.Errorf("set WAPPS_SECRETS_PASSPHRASE_NEW (new passphrase) — print + save to Apple Passwords before continuing")
		}

		enc, err := os.ReadFile("secrets/all.enc.age")
		if err != nil {
			return err
		}
		dec, err := ageutil.Decrypt(enc, oldPass)
		if err != nil {
			return fmt.Errorf("decrypt with OLD pass failed: %w", err)
		}
		newEnc, err := ageutil.Encrypt(dec, newPass)
		if err != nil {
			return err
		}
		if err := os.WriteFile("secrets/all.enc.age", newEnc, 0600); err != nil {
			return err
		}
		fmt.Println("✓ Archive re-encrypted with new passphrase")
		fmt.Println("Next: commit + push, then share new passphrase to team via Signal E2E")
		return nil
	},
}

func init() {
	SecretsCmd.AddCommand(rotateMasterCmd)
}
