package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Dump all secrets as .envrc-style export lines",
	RunE: func(cmd *cobra.Command, args []string) error {
		passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
		if passphrase == "" {
			return fmt.Errorf("WAPPS_SECRETS_PASSPHRASE not set")
		}

		enc, err := os.ReadFile("secrets/all.enc.age")
		if err != nil {
			return err
		}
		dec, err := ageutil.Decrypt(enc, passphrase)
		if err != nil {
			return err
		}

		return writeTofuOutputsAsEnv(dec, os.Stdout)
	},
}

// writeTofuOutputsAsEnv parses `tofu output -json` and emits .envrc-style
// `export TF_VAR_<key>='<value>'` lines to w. Output keys are sorted for
// deterministic output (important for tests + git diff stability).
//
// Value type dispatch:
//   - string → emit unquoted shell value (with single-quote escaping)
//   - list/map/bool/number/null → emit raw JSON inside single quotes. Tofu
//     re-parses TF_VAR_<name> as JSON, so non-string types round-trip without
//     loss. This is what fixes Bug 1 (forcing string here used to crash on
//     vaulter_traefik_cert_paths and other list outputs).
func writeTofuOutputsAsEnv(jsonInput []byte, w io.Writer) error {
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(jsonInput, &outputs); err != nil {
		return fmt.Errorf("env: parse tofu output: %w", err)
	}

	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		raw := outputs[k].Value
		trimmed := bytes.TrimSpace(raw)

		// JSON null: emit literal 'null' so the user can see it explicitly.
		// Otherwise json.Unmarshal would silently zero the destination string
		// and we'd lose the signal.
		if string(trimmed) == "null" {
			fmt.Fprintf(w, "export TF_VAR_%s='null'\n", k)
			continue
		}

		// String: emit unquoted shell value with single-quote escape.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			escaped := strings.ReplaceAll(s, "'", "'\\''")
			fmt.Fprintf(w, "export TF_VAR_%s='%s'\n", k, escaped)
			continue
		}

		// Non-string (list/map/bool/number): emit compact JSON inside single
		// quotes so Tofu re-parses it without whitespace artifacts. This fixes
		// Bug 1 — non-string outputs no longer crash unmarshal.
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			// Fallback: raw isn't valid JSON but reached us anyway. Strip
			// whitespace and emit literally so the user can debug.
			compact.WriteString(strings.TrimSpace(string(raw)))
		}
		escaped := strings.ReplaceAll(compact.String(), "'", "'\\''")
		fmt.Fprintf(w, "export TF_VAR_%s='%s'\n", k, escaped)
	}
	return nil
}

func init() {
	SecretsCmd.AddCommand(envCmd)
}
