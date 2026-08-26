package secrets

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/source"
	"github.com/wappsdev/wapps-cli/internal/store"
)

var importEnvCmd = &cobra.Command{
	Use:   "import-env <file>",
	Short: "Bulk import KEY=VALUE pairs from an env file into the store",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runImportEnv(args[0], os.Getenv)
	},
}

// runImportEnv reads a .env-style file from disk and merges every key into
// the archive, encrypting + writing atomically. Unlike `set`, this does not
// touch the file source declared in .wapps.yaml — import-env is meant for
// one-shot migrations (e.g., "I have an existing .env, get it into the
// archive"), not for the steady-state add-a-secret flow.
//
// Sequence:
//  1. Load .wapps.yaml (required — same dest contract as sync/set)
//  2. Parse the input file via the same parser file source uses (consistent
//     handling of comments, export prefix, quotes)
//  3. Decrypt current archive
//  4. Merge imported keys (later wins — typical "import overwrites" semantics)
//  5. Re-encrypt + atomic write
func runImportEnv(envFilePath string, lookup func(string) string) error {
	cfg, err := requireStoreConfig("import-env")
	if err != nil {
		return err
	}

	data, err := os.ReadFile(envFilePath)
	if err != nil {
		return fmt.Errorf("secrets.import-env: read %s: %w", envFilePath, err)
	}

	// Hand-off to source's parser keeps comment/quote/export handling
	// consistent with what a file source would produce on read.
	imported, err := source.ParseEnvFileBytes(envFilePath, data)
	if err != nil {
		return fmt.Errorf("secrets.import-env: %w", err)
	}
	if len(imported) == 0 {
		fmt.Fprintln(os.Stderr, "⚠ no keys found in input file (all lines were blank/comments)")
		return nil
	}

	sets, err := mergedToSets(imported)
	if err != nil {
		return err
	}

	ctx := context.Background()
	st, err := openStore(cfg)
	if err != nil {
		return err
	}

	// Hangi adların ÜZERİNE yazılacağını önceden söyleyebilmek için ad düzlemi
	// (Keys — değer okumaz, audit'e value.read düşmez) ile kesişim alınır.
	//
	// HATA SINIFA GÖRE AYRILIR, ve bu bir güvenlik kapısıdır:
	//
	// checkAndAdvanceEpochPin bir rollback saldırısını durduran TEK kontrol,
	// ve YALNIZCA Keys + Read içinden çağrılıyor — Import onu HİÇ çağırmıyor.
	// Yani bu Keys çağrısı, `import-env`in epoch pin'ini gördüğü TEK yer.
	// Hatası TÜMÜYLE yutulduğunda EPOCH_DOWNGRADE de yutuluyordu: geri
	// sarılmış bir store'a karşı `list` (Keys) ve `env` (Read) REDDEDERKEN,
	// toplu YAZAN fiil sessizce yazıp 0 ile çıkıyordu. Okuyan fiiller
	// "rollback" diye bağırırken yazan fiilin sessiz kalması ters yönde bir
	// asimetri — yazmak geri alınamaz olandır.
	//
	// Ayrım DAR tutuluyor: yutmanın ilk yazılma sebebi (Keys başka bir
	// sebeple patlarsa `import-env` kullanılamaz olmasın) korunuyor. Ayırt
	// etme clierr KODUYLA yapılıyor, dize eşleştirmesiyle DEĞİL — aynı ayrım
	// dr_epoch_reset.go'da da bu şekilde yazılı.
	existing := map[string]bool{}
	kr, kerr := st.Keys(ctx, cfg.Project)
	switch {
	case kerr == nil:
		for _, k := range kr.Keys {
			existing[k.KeyName] = true
		}
	case clierr.Is(kerr, clierr.EpochDowngrade):
		return kerr
	}
	var overridden []string
	for k := range sets {
		if existing[k] {
			overridden = append(overridden, k)
		}
	}
	sort.Strings(overridden)

	// TEK atomik epoch (POST /import) — yarım bir import diye bir şey yok.
	if err := st.Import(ctx, cfg.Project, sets, store.WriteOpts{}); err != nil {
		return err
	}

	// Auto-apply: bildirilen target'lar hemen yazılır ki tüketim tarafı
	// (.env.local vb.) ikinci bir komut beklemeden import'u yansıtsın.
	valuesJSON, err := valuesToArchiveJSON(sets)
	if err != nil {
		return fmt.Errorf("secrets.import-env: %w", err)
	}
	if err := applyTargetsAfterWrite(cfg, valuesJSON, os.Stderr); err != nil {
		return err
	}

	fmt.Printf("✓ Imported %d keys from %s into %s\n", len(sets), envFilePath, cfg.Project)
	if len(overridden) > 0 {
		fmt.Fprintf(os.Stderr, "⚠ overwrote existing keys: %v\n", overridden)
	}
	return nil
}

func init() {
	SecretsCmd.AddCommand(importEnvCmd)
}
