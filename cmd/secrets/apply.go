package secrets

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/atomicfile"
	"github.com/wappsdev/wapps-cli/internal/config"
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Write every declared consumption target from the store",
	Long: `Fetch the project's secrets once and write every target declared in
.wapps.yaml's 'targets:' block atomically. Idempotent: if a target file on
disk already matches what would be written, the file is left alone (mtime
unchanged). Errors if no targets are declared — use
'wapps secrets env --write <file>' for one-off writes.

Safe to call from npm 'predev' / 'prebuild' scripts so '.env.local' always
matches the store.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runApply(cmd.OutOrStdout())
	},
}

func runApply(stdoutW io.Writer) error {
	cfg, err := requireStoreConfig("apply")
	if err != nil {
		return err
	}
	return runApplyStore(cfg, stdoutW)
}

// applyTargets writes every declared target idempotently. Exported via the
// internal package boundary so set/import-env/sync can call it after a store
// updates without duplicating logic.
//
// stdoutW receives one human-readable line per target (wrote / unchanged) so
// the operator can see what the command did. Never prints values.
func applyTargets(cfg *config.WappsYAML, valuesJSON []byte, stdoutW io.Writer) error {
	for i, t := range cfg.Targets {
		prefix := t.EffectivePrefix(cfg.DefaultPrefix)

		var buf bytes.Buffer
		if err := writeTofuOutputsAsEnv(valuesJSON, prefix, &buf); err != nil {
			return fmt.Errorf("apply: targets[%d] %s: format: %w", i, t.Path, err)
		}
		want := buf.Bytes()

		// Resolve the target path against configRoot so a --project/--config
		// apply writes <project>/.env.local, not <cwd>/.env.local — never
		// scatter plaintext secret files into whatever dir the operator was in.
		// The display lines keep the raw t.Path (repo-relative) for readability.
		target := t.ResolvePath(cfg.ConfigRoot())

		// Idempotency: if the file already contains exactly these bytes, leave
		// it alone. Avoids spurious mtime updates that confuse file watchers
		// (Next.js dev server, Vite HMR, fs.watch consumers).
		existing, err := os.ReadFile(target)
		if err == nil && bytes.Equal(existing, want) {
			fmt.Fprintf(stdoutW, "unchanged %s\n", t.Path)
			continue
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("apply: targets[%d] %s: stat existing: %w", i, t.Path, err)
		}

		if err := atomicfile.Write(target, want, 0600); err != nil {
			return fmt.Errorf("apply: targets[%d] %s: write: %w", i, t.Path, err)
		}
		fmt.Fprintf(stdoutW, "wrote %s\n", t.Path)
	}
	return nil
}

// applyTargetsAfterWrite is the post-write hook used by the store-mutating
// verbs (set, import-env, sync). It writes all declared targets idempotently;
// with no targets declared it is a no-op.
//
// The error names the store write as already committed, so the operator knows
// only the local file materialization needs retrying — not the secret write.
func applyTargetsAfterWrite(cfg *config.WappsYAML, valuesJSON []byte, stdoutW io.Writer) error {
	if cfg == nil || len(cfg.Targets) == 0 {
		return nil
	}
	if err := applyTargets(cfg, valuesJSON, stdoutW); err != nil {
		return fmt.Errorf("the store write succeeded but writing local targets failed: %w (run 'wapps secrets apply' to retry)", err)
	}
	return nil
}

func init() {
	SecretsCmd.AddCommand(applyCmd)
}
