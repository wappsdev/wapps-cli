package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/source"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

const wappsYAMLPath = ".wapps.yaml"

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sources → encrypted archive (suggest commit)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSync(cmd.Context(), os.Getenv)
	},
}

// runSync is the testable entry point for `wapps secrets sync`. It picks
// between two paths:
//
//   - Legacy (no .wapps.yaml): single tofu source, dest = secrets/all.enc.age.
//     Preserves the v0.5.x behavior so existing repos continue to work.
//   - Config-driven (.wapps.yaml present): one or more sources merged into the
//     archive at the configured dest. Multi-repo rollout depends on this path.
//
// lookup is os.Getenv in production; tests inject their own to drive specific
// env states without polluting the parent process.
func runSync(ctx context.Context, lookup func(string) string) error {
	cfg, err := loadOrNil(wappsYAMLPath)
	if err != nil {
		return err
	}

	if cfg == nil {
		// Legacy single-tofu path.
		if err := preflightTofuEnv(lookup); err != nil {
			return err
		}
		return syncWithTofuOutput(tofu.Output, "secrets/all.enc.age")
	}

	// Config-driven path. Only preflight tofu env if at least one source needs it.
	if hasTofuSource(cfg.Sources) {
		if err := preflightTofuEnv(lookup); err != nil {
			return err
		}
	}

	merged, err := readAndMerge(ctx, cfg.Sources)
	if err != nil {
		return err
	}

	passphrase := lookup("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	payload, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("secrets.sync: marshal merged: %w", err)
	}

	if err := ageutil.EncryptWriteAtomic(cfg.Dest, payload, passphrase); err != nil {
		return fmt.Errorf("secrets.sync: %w", err)
	}

	fmt.Printf("✓ Wrote %s (%d keys from %d sources)\n",
		cfg.Dest, len(merged), len(cfg.Sources))
	emitCommitHint(cfg.Dest)
	return nil
}

// loadOrNil returns nil when the config file doesn't exist, propagates parse
// errors so typos surface loudly. Distinguishing "file missing" from "file
// broken" is the difference between gracefully falling back to legacy mode
// and overwriting a good archive with the wrong sources.
func loadOrNil(path string) (*config.WappsYAML, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("secrets.sync: stat %s: %w", path, err)
	}
	return config.Load(path)
}

func hasTofuSource(cfgs []source.Config) bool {
	for _, c := range cfgs {
		if c.Type == "tofu" {
			return true
		}
	}
	return false
}

// readAndMerge instantiates each Source, reads it under the shared context,
// and merges results. Override warnings are printed but do not fail the sync
// (the operator may have intentionally overridden a Tofu-managed secret).
func readAndMerge(ctx context.Context, cfgs []source.Config) (map[string]json.RawMessage, error) {
	parts := make([]map[string]json.RawMessage, 0, len(cfgs))
	for i, c := range cfgs {
		src, err := source.New(c)
		if err != nil {
			return nil, fmt.Errorf("secrets.sync: sources[%d]: %w", i, err)
		}
		data, err := src.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("secrets.sync: sources[%d] (%s): %w", i, src.Name(), err)
		}
		parts = append(parts, data)
	}
	merged, overridden := source.Merge(parts)
	for _, k := range overridden {
		fmt.Fprintf(os.Stderr, "⚠ key overridden by later source: %s\n", k)
	}
	return merged, nil
}

func emitCommitHint(dest string) {
	// Split "+" + "%Y-%m-%d" emits the literal shell snippet "$(date +%Y-%m-%d)"
	// for the user's shell to evaluate. Combined into one literal would trigger
	// go vet's printf format-string check (treating %Y/%m/%d as Go format verbs).
	dateFmt := "+" + "%Y-%m-%d"
	fmt.Printf("Next: git add %s && git commit -m 'chore: secret sync $(date %s)'\n", dest, dateFmt)
}

// preflightTofuEnv checks that the environment is set up correctly for
// `tofu output` to succeed. tofu loads provider creds + state-backend creds at
// startup, so missing env vars produce confusing tofu errors that don't point
// at the actual fix. This pre-check fails fast with a copy-pasteable script
// snippet so the operator can recover in one step.
//
// lookup is os.Getenv in production; tests inject their own to drive specific
// missing-var scenarios deterministically.
func preflightTofuEnv(lookup func(string) string) error {
	// Hard requirements: without these, `tofu output` fails immediately.
	required := []struct {
		name string
		hint string
	}{
		{"AWS_ACCESS_KEY_ID", "R2 backend credentials (map from WAPPS_R2_ACCESS_KEY_ID)"},
		{"AWS_SECRET_ACCESS_KEY", "R2 backend credentials (map from WAPPS_R2_SECRET_ACCESS_KEY)"},
		{"AWS_ENDPOINT_URL_S3", "R2 backend endpoint (map from WAPPS_R2_ENDPOINT)"},
		{"AWS_REGION", "R2 backend region (must be 'auto' for Cloudflare R2)"},
		{"TF_VAR_state_passphrase", "Tofu encryption block (map from WAPPS_TOFU_STATE_PASSPHRASE)"},
	}

	var missing []string
	for _, r := range required {
		if lookup(r.name) == "" {
			missing = append(missing, r.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString("secrets.sync preflight: required environment not set.\n\n")
	b.WriteString("Missing:\n")
	for _, name := range missing {
		var hint string
		for _, r := range required {
			if r.name == name {
				hint = r.hint
				break
			}
		}
		fmt.Fprintf(&b, "  - %s (%s)\n", name, hint)
	}
	b.WriteString("\nRecovery (paste into your shell, sourcing your project secrets first):\n\n")
	b.WriteString("  set -a\n")
	b.WriteString("  source ~/.config/<project>/secrets.env\n")
	b.WriteString("  set +a\n")
	b.WriteString("  export AWS_ACCESS_KEY_ID=\"$WAPPS_R2_ACCESS_KEY_ID\"\n")
	b.WriteString("  export AWS_SECRET_ACCESS_KEY=\"$WAPPS_R2_SECRET_ACCESS_KEY\"\n")
	b.WriteString("  export AWS_ENDPOINT_URL_S3=\"$WAPPS_R2_ENDPOINT\"\n")
	b.WriteString("  export AWS_REGION=auto\n")
	b.WriteString("  export TF_VAR_state_passphrase=\"$WAPPS_TOFU_STATE_PASSPHRASE\"\n")
	b.WriteString("\nThen re-run: wapps secrets sync")
	return fmt.Errorf("%s", b.String())
}

func syncWithTofuOutput(outputFn func() ([]byte, error), destPath string) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
	}

	out, err := outputFn()
	if err != nil {
		return fmt.Errorf("secrets.sync: tofu output: %w", err)
	}

	if err := ageutil.EncryptWriteAtomic(destPath, out, passphrase); err != nil {
		return fmt.Errorf("secrets.sync: %w", err)
	}

	fmt.Printf("✓ Wrote %s\n", destPath)
	emitCommitHint(destPath)
	return nil
}

func init() {
	SecretsCmd.AddCommand(syncCmd)
}
