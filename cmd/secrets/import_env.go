package secrets

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/source"
)

var importEnvCmd = &cobra.Command{
	Use:   "import-env <file>",
	Short: "Bulk import KEY=VALUE pairs from an env file into the archive",
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
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("secrets.import-env: .wapps.yaml required (import-env writes to cfg.Dest)")
	}

	data, err := os.ReadFile(envFilePath)
	if err != nil {
		return fmt.Errorf("secrets.import-env: read %s: %w", envFilePath, err)
	}

	// Hand-off to source's parser keeps comment/quote/export handling
	// consistent with what file source would produce on read.
	imported, err := source.ParseEnvFileBytes(envFilePath, data)
	if err != nil {
		return fmt.Errorf("secrets.import-env: %w", err)
	}
	if len(imported) == 0 {
		fmt.Fprintln(os.Stderr, "⚠ no keys found in input file (all lines were blank/comments)")
		return nil
	}

	passphrase := lookup("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("secrets.import-env: WAPPS_SECRETS_PASSPHRASE not set")
	}

	archive, err := decryptArchive(cfg.ResolveDest(), passphrase)
	if err != nil {
		return err
	}

	var overridden []string
	for k, v := range imported {
		if _, exists := archive[k]; exists {
			overridden = append(overridden, k)
		}
		archive[k] = v
	}

	payload, err := encryptAndWriteArchiveLookup(cfg.ResolveDest(), archive, passphrase)
	if err != nil {
		return err
	}

	// Auto-apply: targets declared in .wapps.yaml are written immediately so
	// the consumption side (.env.local, etc.) reflects the import without a
	// follow-up command. Reuses the payload bytes the encrypt step produced
	// — same reasoning as set.go (avoid double-marshal key-order drift).
	if err := applyTargetsAfterArchiveWrite(cfg, payload, os.Stderr); err != nil {
		return err
	}

	fmt.Printf("✓ Imported %d keys from %s into %s\n", len(imported), envFilePath, cfg.Dest)
	if len(overridden) > 0 {
		fmt.Fprintf(os.Stderr, "⚠ overrode existing archive keys: %v\n", overridden)
	}
	fmt.Printf("Next: review the merge, then 'wapps secrets sync' to confirm sources still reconcile cleanly\n")
	return nil
}

// encryptAndWriteArchiveLookup wraps ageutil.EncryptWriteAtomic with the
// import-env error context. Returns the marshaled payload bytes so callers
// reuse them (see set.go's encryptAndWriteArchive for the same pattern).
func encryptAndWriteArchiveLookup(path string, archive map[string]json.RawMessage, passphrase string) ([]byte, error) {
	payload, err := json.Marshal(archive)
	if err != nil {
		return nil, fmt.Errorf("marshal archive: %w", err)
	}
	if err := ageutil.EncryptWriteAtomic(path, payload, passphrase); err != nil {
		return nil, fmt.Errorf("import-env: %w", err)
	}
	return payload, nil
}

func init() {
	SecretsCmd.AddCommand(importEnvCmd)
}
