package secrets

import (
	"io"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the project's secret names (never values)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runList(cmd.OutOrStdout())
	},
}

// runList, list'in backend-aware çekirdeğidir (SPEC §7.1 metadata düzlemi):
// backend:store ise anahtar ADLARI Worker metadata endpoint'inden gelir
// (GET /keys, §7.4 — passphrase/arşiv YOK, değer okunmaz); aksi halde legacy
// age-arşiv yolu AYNEN korunur. Çıktı iki backend'de birebir aynı biçimdedir.
func runList(w io.Writer) error {
	cfg, err := storeProject("list")
	if err != nil {
		return err
	}
	return runListStore(cfg, w)
}

func init() {
	SecretsCmd.AddCommand(listCmd)
}
