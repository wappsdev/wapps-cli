package secrets

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Decrypt + extract single secret value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		val, err := readKey(resolveArchivePath(), args[0])
		if err != nil {
			return err
		}
		fmt.Println(val)
		return nil
	},
}

func readKey(archivePath, key string) (string, error) {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return "", fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return "", fmt.Errorf("secrets.get: read archive: %w", err)
	}

	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return "", fmt.Errorf("secrets.get: decrypt: %w", err)
	}

	var outputs map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(dec, &outputs); err != nil {
		return "", fmt.Errorf("secrets.get: unmarshal: %w", err)
	}

	entry, ok := outputs[key]
	if !ok {
		return "", fmt.Errorf("secrets.get: key %q not found", key)
	}
	return entry.Value, nil
}

func init() {
	SecretsCmd.AddCommand(getCmd)
}
