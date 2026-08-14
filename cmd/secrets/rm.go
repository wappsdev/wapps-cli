package secrets

// rm.go, `wapps secrets rm <KEY>` — bir anahtarı store'dan KALDIRIR
// (DELETE /v1/projects/{p}/keys/{KEY}; silme = manifest'te yokluk, §2.6).
//
// Neden ayrı bir verb: `set` yalnız yazar, `rotate` değeri değiştirir,
// `migrate tombstone` ARŞİV düzeyindedir. Bir sırrın ait olduğu kaynak yok
// olduğunda (silinen servis hesabı, kapatılan sağlayıcı) store'da öksüz bir
// kayıt kalıyordu ve onu temizlemenin hiçbir yolu yoktu — bootstrap eden
// script'ler "kimlik var ama hesap yok" tutarsızlığında haklı olarak duruyor,
// ama operatör bu durumu kapatamıyordu.
//
// Sözleşme (get/list ayrımının aynı çizgisi: AD görünür, DEĞER asla):
//   - ajan modunda REDDEDİLİR (agentgate.go: PolicyRefuseAgent) — silme geri alınamaz;
//   - sunucuda AYRI `delete` grant'i ister (write YETMEZ, worker/src/policy.ts §4.2 rev4);
//   - insan onayı ister ("yes"), --yes ile atlanır;
//   - olmayan anahtarta SESSİZ BAŞARI DEĞİL: gate 404 → adı konmuş NOT_FOUND;
//   - çıktı yalnızca anahtar ADIdır, hiçbir koşulda değer.

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// rmYes, --yes bayrağı (etkileşimli onayı atlar).
var rmYes bool

var rmCmd = &cobra.Command{
	Use:   "rm <KEY>",
	Short: "Remove a key from the store (irreversible; refused in agent mode)",
	Long: "Remove a key from the store.\n\n" +
		"Deletion is irreversible and needs its own `delete` grant in policy.json —\n" +
		"a `write` grant is NOT enough. Use this when the thing a secret pointed at is\n" +
		"gone (deleted service account, retired provider) and the entry is now orphaned.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRm(args[0], rmYes, cmd.InOrStdin(), cmd.OutOrStdout())
	},
}

// runRm, rm'in test edilebilir çekirdeğidir.
func runRm(key string, yes bool, in io.Reader, out io.Writer) error {
	if key == "" {
		return clierr.New(clierr.Internal, "secrets.rm: KEY argument is required")
	}

	cfg, err := storeProject("rm")
	if err != nil {
		return err
	}

	if !yes {
		ok, cerr := confirmTTY(in, out, fmt.Sprintf(
			"Remove %s from %s? This cannot be undone. Type 'yes' to confirm: ", key, cfg.Project))
		if cerr != nil {
			return fmt.Errorf("secrets.rm: read confirmation: %w", cerr)
		}
		if !ok {
			return clierr.New(clierr.Internal, "secrets.rm: aborted (confirmation not given)")
		}
	}

	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	if err := st.Delete(context.Background(), cfg.Project, key); err != nil {
		return err
	}

	fmt.Fprintf(out, "✓ Removed %s (store: %s)\n", key, cfg.Project)
	return nil
}

func init() {
	rmCmd.Flags().BoolVar(&rmYes, "yes", false, "skip the interactive confirm (still refused in agent mode)")
	SecretsCmd.AddCommand(rmCmd)
}
