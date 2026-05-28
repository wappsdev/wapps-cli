package secrets

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Tofu output → secrets/all.enc.age (suggest commit)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := preflightTofuEnv(os.Getenv); err != nil {
			return err
		}
		return syncWithTofuOutput(tofu.Output, "secrets/all.enc.age")
	},
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

	encrypted, err := ageutil.Encrypt(out, passphrase)
	if err != nil {
		return fmt.Errorf("secrets.sync: encrypt: %w", err)
	}

	if err := os.WriteFile(destPath, encrypted, 0600); err != nil {
		return fmt.Errorf("secrets.sync: write: %w", err)
	}

	fmt.Printf("✓ Wrote %s (%d bytes)\n", destPath, len(encrypted))
	// Split "+" + "%Y-%m-%d" emits the literal shell snippet "$(date +%Y-%m-%d)"
	// for the user's shell to evaluate. Combined into one literal would trigger
	// go vet's printf format-string check (treating %Y/%m/%d as Go format verbs).
	dateFmt := "+" + "%Y-%m-%d"
	fmt.Printf("Next: git add secrets/all.enc.age && git commit -m 'chore: secret sync $(date %s)'\n", dateFmt)
	return nil
}

func init() {
	SecretsCmd.AddCommand(syncCmd)
}
