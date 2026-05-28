package secrets

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/config"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Materialize all declared consumption targets from the archive",
	Long: `Decrypt the archive once and write every target declared in
.wapps.yaml's 'targets:' block atomically. Idempotent: if a target file
on disk already matches what would be written, the file is left alone
(mtime unchanged). Errors if no targets are declared — use
'wapps secrets env --write <file>' for one-off writes.

Designed to be safe to call from npm 'predev' / 'prebuild' scripts so
'.env.local' is always up-to-date with the archive.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runApply(cmd.OutOrStdout())
	},
}

func runApply(stdoutW io.Writer) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("apply: WAPPS_SECRETS_PASSPHRASE not set")
	}

	cfg, err := config.Load(wappsYAMLPath)
	if err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("apply: no targets declared in %s — add a 'targets:' block or use 'wapps secrets env --write <file>' for one-off writes", wappsYAMLPath)
	}

	enc, err := os.ReadFile(cfg.Dest)
	if err != nil {
		return fmt.Errorf("apply: read %s: %w", cfg.Dest, err)
	}
	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return fmt.Errorf("apply: decrypt: %w", err)
	}

	return applyTargets(cfg, dec, stdoutW)
}

// applyTargets writes every declared target idempotently. Exported via the
// internal package boundary so set/import-env/sync can call it after archive
// updates without duplicating logic.
//
// stdoutW receives one human-readable line per target (wrote / unchanged) so
// the operator can see what the command did. Never prints values.
func applyTargets(cfg *config.WappsYAML, decryptedArchive []byte, stdoutW io.Writer) error {
	for i, t := range cfg.Targets {
		prefix := t.EffectivePrefix(cfg.DefaultPrefix)

		var buf bytes.Buffer
		if err := writeTofuOutputsAsEnv(decryptedArchive, prefix, &buf); err != nil {
			return fmt.Errorf("apply: targets[%d] %s: format: %w", i, t.Path, err)
		}
		want := buf.Bytes()

		// Idempotency: if the file already contains exactly these bytes, leave
		// it alone. Avoids spurious mtime updates that confuse file watchers
		// (Next.js dev server, Vite HMR, fs.watch consumers).
		existing, err := os.ReadFile(t.Path)
		if err == nil && bytes.Equal(existing, want) {
			fmt.Fprintf(stdoutW, "unchanged %s\n", t.Path)
			continue
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("apply: targets[%d] %s: stat existing: %w", i, t.Path, err)
		}

		if err := ageutil.WriteFileAtomic(t.Path, want, 0600); err != nil {
			return fmt.Errorf("apply: targets[%d] %s: write: %w", i, t.Path, err)
		}
		fmt.Fprintf(stdoutW, "wrote %s\n", t.Path)
	}
	return nil
}

// applyTargetsAfterArchiveWrite is the post-write hook used by every
// archive-mutating command (sync, set, import-env, rotate-master). It writes
// all declared targets idempotently. When no targets are declared this is a
// no-op so the same call works in both targets-enabled and legacy repos.
//
// Returns a wrapped error that names the archive path so the operator knows
// the archive write succeeded and a manual `wapps secrets apply` would retry
// just the file materialization step.
func applyTargetsAfterArchiveWrite(cfg *config.WappsYAML, decryptedArchive []byte, stdoutW io.Writer) error {
	if cfg == nil || len(cfg.Targets) == 0 {
		return nil
	}
	if err := applyTargets(cfg, decryptedArchive, stdoutW); err != nil {
		return fmt.Errorf("archive saved to %s but apply failed: %w (run 'wapps secrets apply' to retry)", cfg.Dest, err)
	}
	return nil
}

func init() {
	SecretsCmd.AddCommand(applyCmd)
}
