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
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var (
	envWritePath string
	envPrefix    string
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Dump all secrets as .envrc-style export lines",
	Long: `Dump all secrets as 'export KEY=VALUE' lines.

By default writes to stdout (printable). Use --write <file> to write to a
file silently (AI-safe path — no secret value reaches stdout, terminal,
or LLM transcript). Use --prefix to control the env var prefix (default
TF_VAR_ preserves Tofu workflow; pass --prefix '' for plain emit needed
by non-Tofu repos like vaulter-api).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// env'in print-form'u (--write yok) gizli DÜZ METİN basar → ajan modunda
		// YAPISAL red; env --write FILE serbest kalır (§7.4.2).
		if envWritePath == "" {
			if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
				return err
			}
		}
		return runEnv(envWritePath, envPrefix, os.Stdout)
	},
}

// runEnv is the testable entry point for `wapps secrets env`.
//
// writePath: when non-empty, env output is written to this file (0600,
// atomic temp+rename) and stdoutW receives nothing. When empty, output
// goes to stdoutW. The AI-safe pattern (P4 from /office-hours, refined
// in eng review D9) requires this — agents call `env --write` so that
// secret values never reach stdout/transcript/log.
//
// prefix: prepended to every key on emit. Defaults to "TF_VAR_" so Tofu
// workflows are unchanged. Empty string disables prefixing (vaulter-api
// and other non-Tofu repos).
func runEnv(writePath, prefix string, stdoutW io.Writer) error {
	// Backend yönlendirme (§7.12): backend:store ise export satırları store
	// snapshot'ından üretilir; aksi halde aşağıdaki legacy age-arşiv yolu AYNEN korunur.
	storeCfg, cerr := storeBackendConfig()
	if cerr != nil {
		return cerr
	}
	if storeCfg != nil {
		return runEnvStore(storeCfg, writePath, prefix, stdoutW)
	}

	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("env: WAPPS_SECRETS_PASSPHRASE not set")
	}

	// Archive path comes from .wapps.yaml when present, otherwise legacy
	// default. We don't need the full config here — just the dest path.
	archivePath := resolveArchivePath()

	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("env: read %s: %w", archivePath, err)
	}
	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return fmt.Errorf("env: decrypt: %w", err)
	}

	if writePath == "" {
		// Legacy stdout path. Operator-driven, terminal-attached.
		return writeTofuOutputsAsEnv(dec, prefix, stdoutW)
	}

	// AI-safe path: write to file, stdout stays empty.
	return writeEnvFileAtomic(writePath, dec, prefix)
}

// writeEnvFileAtomic emits env output to a temp file at writePath+".tmp",
// then renames into place. Atomic so a power loss or signal mid-write
// can't leave a partially-decrypted .env.local on disk.
func writeEnvFileAtomic(writePath string, archiveDecrypted []byte, prefix string) error {
	tmp := writePath + ".tmp"
	// Open with 0600 — env files contain plaintext secrets and must not be
	// world-readable.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("env: open temp %s: %w", tmp, err)
	}
	if err := writeTofuOutputsAsEnv(archiveDecrypted, prefix, f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("env: close temp: %w", err)
	}
	if err := os.Rename(tmp, writePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("env: rename %s -> %s: %w", tmp, writePath, err)
	}
	return nil
}

// resolveArchivePath returns the archive path declared in .wapps.yaml if
// the file exists, otherwise the legacy default. We deliberately do NOT
// fail on broken .wapps.yaml here — env is a read-only operation and the
// legacy default is a safe fallback for old repos. Sync/Set are the
// commands that halt on broken config because they WRITE.
func resolveArchivePath() string {
	cfg, _ := loadOrNil(wappsConfigPath())
	if cfg != nil && cfg.Dest != "" {
		// Resolve against the .wapps.yaml dir (configRoot) so reads work from
		// any cwd under --config/--project. When no override is set, configRoot
		// == cwd → identical to the old cwd-relative behavior.
		return cfg.ResolveDest()
	}
	// No/absent config: resolve the default against the override dir if one was
	// given, else cwd-relative (legacy).
	return resolveLegacyDest()
}

// archiveRelForGit returns the repo-relative archive path for `git show`, which
// treats its argument as a pathspec (not a filesystem path). Always the raw
// cfg.Dest (or the default) — never configRoot-resolved, since an absolute path
// would make `git show <ref>:./<path>` fail. Used by diff's git-ref side.
func archiveRelForGit() string {
	cfg, _ := loadOrNil(wappsConfigPath())
	if cfg != nil && cfg.Dest != "" {
		return cfg.Dest
	}
	return defaultArchiveRel
}

// envName applies the source prefix to a key idempotently: a key that already
// starts with the prefix is emitted verbatim, never double-prefixed. This keeps
// a mixed archive correct — Tofu outputs are stored bare (e.g. coolify_uuid →
// TF_VAR_coolify_uuid) while file-source secrets carried in already prefixed
// (e.g. TF_VAR_gemini_api_key) round-trip unchanged instead of becoming
// TF_VAR_TF_VAR_gemini_api_key. An empty prefix emits every key as-is.
func envName(prefix, key string) string {
	if prefix == "" || strings.HasPrefix(key, prefix) {
		return key
	}
	return prefix + key
}

// writeTofuOutputsAsEnv parses tofu-output-shaped JSON and emits
// `export <prefix><key>='<value>'` lines to w. Output keys are sorted for
// deterministic output (important for tests + git diff stability).
//
// Value type dispatch:
//   - string → emit unquoted shell value (with single-quote escaping)
//   - list/map/bool/number/null → emit raw JSON inside single quotes. Tofu
//     re-parses TF_VAR_<name> as JSON, so non-string types round-trip without
//     loss. This is what fixes Bug 1 (forcing string here used to crash on
//     vaulter_traefik_cert_paths and other list outputs).
func writeTofuOutputsAsEnv(jsonInput []byte, prefix string, w io.Writer) error {
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(jsonInput, &outputs); err != nil {
		return fmt.Errorf("env: parse archive: %w", err)
	}

	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		raw := outputs[k].Value
		trimmed := bytes.TrimSpace(raw)
		name := envName(prefix, k)

		// JSON null: emit literal 'null' so the user can see it explicitly.
		// Otherwise json.Unmarshal would silently zero the destination string
		// and we'd lose the signal.
		if string(trimmed) == "null" {
			fmt.Fprintf(w, "export %s='null'\n", name)
			continue
		}

		// String: emit unquoted shell value with single-quote escape.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			escaped := strings.ReplaceAll(s, "'", "'\\''")
			fmt.Fprintf(w, "export %s='%s'\n", name, escaped)
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
		fmt.Fprintf(w, "export %s='%s'\n", name, escaped)
	}
	return nil
}

func init() {
	envCmd.Flags().StringVar(&envWritePath, "write", "",
		"write env output to this file (0600, atomic) instead of stdout; AI-safe path that never prints values")
	envCmd.Flags().StringVar(&envPrefix, "prefix", "TF_VAR_",
		"prefix prepended to each KEY (default 'TF_VAR_' for Tofu workflows; pass '' for plain emit)")
	SecretsCmd.AddCommand(envCmd)
}
