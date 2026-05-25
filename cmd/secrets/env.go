package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Dump all secrets as .envrc-style export lines",
	RunE: func(cmd *cobra.Command, args []string) error {
		passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
		if passphrase == "" {
			return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
		}

		enc, err := os.ReadFile("secrets/all.enc.age")
		if err != nil {
			return err
		}
		dec, err := ageutil.Decrypt(enc, passphrase)
		if err != nil {
			return err
		}

		var outputs map[string]struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(dec, &outputs); err != nil {
			return err
		}

		for k, v := range outputs {
			escaped := strings.ReplaceAll(v.Value, "'", "'\\''")
			fmt.Printf("export TF_VAR_%s='%s'\n", k, escaped)
		}
		return nil
	},
}

func init() {
	SecretsCmd.AddCommand(envCmd)
}
