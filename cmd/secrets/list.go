package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secret names (no values)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runList(cmd.OutOrStdout())
	},
}

// runList, list'in backend-aware çekirdeğidir (SPEC §7.1 metadata düzlemi):
// backend:store ise anahtar ADLARI Worker metadata endpoint'inden gelir
// (GET /keys, §7.4 — passphrase/arşiv YOK, değer okunmaz); aksi halde legacy
// age-arşiv yolu AYNEN korunur. Çıktı iki backend'de birebir aynı biçimdedir.
func runList(w io.Writer) error {
	storeCfg, cerr := storeBackendConfig()
	if cerr != nil {
		return cerr
	}
	if storeCfg != nil {
		return runListStore(storeCfg, w)
	}
	return listKeys(resolveArchivePath(), w)
}

func listKeys(archivePath string, w io.Writer) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("secrets.list: read: %w", err)
	}
	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return fmt.Errorf("secrets.list: decrypt: %w", err)
	}

	var outputs map[string]json.RawMessage
	if err := json.Unmarshal(dec, &outputs); err != nil {
		return fmt.Errorf("secrets.list: unmarshal: %w", err)
	}

	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintln(w, k)
	}
	return nil
}

func init() {
	SecretsCmd.AddCommand(listCmd)
}
