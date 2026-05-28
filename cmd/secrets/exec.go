package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var execPrefix string

var execCmd = &cobra.Command{
	Use:   "exec -- <command> [args...]",
	Short: "Run a command with archive secrets injected as env vars",
	Long: `Decrypt the archive and exec the given command with each secret
exported as an env var. The wapps process forwards the subprocess's stdout
and stderr without buffering, and exits with the subprocess's exit code.

AI-safe contract (P4 from /office-hours, refined in eng review D9): wapps
itself prints no secret values — only the subprocess does (and its output
is the subprocess's own responsibility). Use this from agent contexts
that need credentialed commands without putting values in the agent
transcript.

Example:
  wapps secrets exec -- pnpm dev
  wapps secrets exec --prefix '' -- ./scripts/deploy.sh`,
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: false,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExec(args, execPrefix, defaultExecRunner)
	},
}

// runExec is the testable entry point for `wapps secrets exec --`.
//
// args: positional args after the `--`. args[0] is the command name,
// remainder are passed to it verbatim. Caller (cobra) enforces at least
// one element.
//
// prefix: prepended to each key when building the env var name. Default
// "TF_VAR_" preserves Tofu workflows; pass --prefix "" for plain emit
// (vaulter-api etc.).
//
// runner: dependency-injected subprocess invocation. Production wires to
// defaultExecRunner which calls exec.CommandContext. Tests inject a fake
// that captures the env + args and returns a synthesized exit code.
func runExec(args []string, prefix string, runner execRunner) error {
	if len(args) == 0 {
		return fmt.Errorf("exec: at least one positional arg required (the command to run)")
	}

	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("exec: WAPPS_SECRETS_PASSPHRASE not set")
	}

	archivePath := resolveArchivePath()
	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("exec: read %s: %w", archivePath, err)
	}
	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return fmt.Errorf("exec: decrypt: %w", err)
	}

	injected, err := buildExecEnv(dec, prefix)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	// Merge with inherited env. Inherited entries come first so injected
	// secrets take precedence on collision (operator intent: "use the
	// archive's STRIPE_KEY, not the one already in my shell").
	mergedEnv := append(os.Environ(), injected...)

	exitCode, err := runner(args[0], args[1:], mergedEnv)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// execRunner is the subprocess-spawn seam. Implementations should forward
// stdin/stdout/stderr to the child and block until the child exits, then
// return its exit code.
type execRunner func(name string, args, env []string) (int, error)

// buildExecEnv converts the decrypted archive JSON into a []string of
// "KEY=VALUE" entries suitable for exec.Cmd.Env. It mirrors writeTofuOutputsAsEnv
// but emits raw key=value (no `export`, no shell quoting) since exec's env
// passing is byte-exact (no shell layer interpretation).
//
// Sort order is deterministic so tests can assert against the slice.
//
// Non-string types (list/map/bool/number) are serialized as compact JSON
// strings — caller decides how to parse. This matches `env --write` so the
// two apply paths feed callers the same format.
func buildExecEnv(archiveDecrypted []byte, prefix string) ([]string, error) {
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(archiveDecrypted, &outputs); err != nil {
		return nil, fmt.Errorf("parse archive: %w", err)
	}

	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	env := make([]string, 0, len(keys))
	for _, k := range keys {
		raw := outputs[k].Value
		val, err := valueToShellString(raw)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		env = append(env, prefix+k+"="+val)
	}
	return env, nil
}

// valueToShellString reduces a JSON value (string | list | map | bool |
// number | null) to a single string for cmd.Env. Strings unwrap; everything
// else emits its compact JSON. Empty/null becomes the literal "null".
func valueToShellString(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		return "null", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	// Non-string: emit compact JSON. Subprocess can json.parse if it wants.
	return trimmed, nil
}

func init() {
	execCmd.Flags().StringVar(&execPrefix, "prefix", "TF_VAR_",
		"prefix prepended to each env var name (default 'TF_VAR_' for Tofu; pass '' for plain)")
	SecretsCmd.AddCommand(execCmd)
}
