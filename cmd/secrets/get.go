package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

	// Keep the value as raw JSON, NOT a struct that assumes value is a string.
	// Otherwise a single non-string value anywhere in the archive (e.g. an
	// array like vaulter_traefik_cert_paths) fails the whole unmarshal and
	// `get` crashes before it ever reaches the requested key.
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(dec, &outputs); err != nil {
		return "", fmt.Errorf("secrets.get: unmarshal: %w", err)
	}

	entry, ok := outputs[key]
	if !ok {
		return "", fmt.Errorf("secrets.get: key %q not found", key)
	}
	return rawValueToString(entry.Value), nil
}

// rawValueToString renders one archive value for `get`:
//   - absent "value" field or JSON null → "" (matches the pre-fix struct-into-
//     string zero-value semantics; never prints a raw envelope blob)
//   - JSON string → the string verbatim (unquoted, for piping)
//   - any other type (array/map/number/bool) → compact JSON
func rawValueToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		// Covers JSON string (→ value) and JSON null (→ ""), matching legacy.
		return s
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err == nil {
		return compact.String()
	}
	return strings.TrimSpace(string(raw))
}

func init() {
	SecretsCmd.AddCommand(getCmd)
}
