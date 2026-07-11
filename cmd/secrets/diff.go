package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

var diffCmd = &cobra.Command{
	Use:   "diff [ref]",
	Short: "Compare archive keys against a git ref (default: HEAD~1)",
	Long: `Show which keys were added, changed, or removed between the
archive at the given git ref and the current working tree.

AI-safe: only key names are printed. Values, value hashes, and value
lengths never reach stdout. Change detection uses sha256 of the canonical
value JSON; hashes stay in-process.

Examples:
  wapps secrets diff               # vs HEAD~1
  wapps secrets diff main          # vs main branch tip
  wapps secrets diff v0.10.0       # vs tag
  wapps secrets diff HEAD~5        # vs five commits ago`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref := "HEAD~1"
		if len(args) == 1 {
			ref = args[0]
		}
		return runDiff(ref, gitShowRunner, cmd.OutOrStdout())
	},
}

// gitShowFn fetches the bytes of `path` at git ref. Production = gitShowRunner.
// Tests inject a stub so we don't need a real git history.
type gitShowFn func(ref, path string) ([]byte, error)

func runDiff(ref string, gitShow gitShowFn, stdoutW io.Writer) error {
	// Backend yönlendirme (SPEC §7.1): backend:store'da anahtar tarihçesi
	// SUNUCUDADIR — git-ref karşılaştırması tanımsızdır ve buradaki legacy yol
	// ya passphrase hatasıyla ya da BAYAT bir legacy arşivi listeleyerek
	// yanıltırdı. Arşive/passphrase'e DOKUNMADAN fail loud; store tarihçe
	// diff'i bir sunucu history API'si gerektirir (bugün yok).
	storeCfg, cerr := storeBackendConfig()
	if cerr != nil {
		return cerr
	}
	if storeCfg != nil {
		return clierr.New(clierr.NotAvailable,
			"diff compares legacy git-archive snapshots; with backend:store the key history lives server-side — use 'wapps secrets list' (current key names, GET /keys metadata) or the audit log; a store history diff needs a server history API")
	}

	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("diff: WAPPS_SECRETS_PASSPHRASE not set")
	}

	// Two paths: the filesystem path (resolved against configRoot, works from
	// any cwd) for reading the current archive, and the raw repo-relative path
	// for `git show <ref>:./<path>` — git interprets its arg as a pathspec, not
	// a filesystem path, so an absolute path would break it. Under
	// --config/--project the git-ref side runs in cwd (not the project repo) and
	// is therefore best-effort/cwd-bound; the current-archive read is fully
	// config-aware.
	archivePath := resolveArchivePath()
	gitPath := archiveRelForGit()

	currentEnc, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("diff: read current %s: %w", archivePath, err)
	}
	currentDec, err := ageutil.Decrypt(currentEnc, passphrase)
	if err != nil {
		return fmt.Errorf("diff: decrypt current: %w", err)
	}
	currentMap, err := parseArchiveValueHashes(currentDec)
	if err != nil {
		return fmt.Errorf("diff: parse current: %w", err)
	}

	refEnc, err := gitShow(ref, gitPath)
	if err != nil {
		return fmt.Errorf("diff: fetch archive at %s: %w", ref, err)
	}
	refDec, err := ageutil.Decrypt(refEnc, passphrase)
	if err != nil {
		// Decrypt failure usually means a rotation between ref and current.
		return fmt.Errorf("diff: decrypt archive at %s: %w (passphrase may have rotated since then — diff across rotation not supported)", ref, err)
	}
	refMap, err := parseArchiveValueHashes(refDec)
	if err != nil {
		return fmt.Errorf("diff: parse archive at %s: %w", ref, err)
	}

	return printDiff(refMap, currentMap, ref, stdoutW)
}

// parseArchiveValueHashes returns key → sha256(canonical value JSON). The
// actual values stay inside this function — only opaque hashes leave. This is
// the AI-safety boundary for diff: no caller can reconstruct values from the
// returned map.
func parseArchiveValueHashes(decryptedArchive []byte) (map[string]string, error) {
	var envelope map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(decryptedArchive, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	out := make(map[string]string, len(envelope))
	for k, v := range envelope {
		// Normalize whitespace so semantically-equal JSON hashes equal.
		var compact bytes.Buffer
		if err := json.Compact(&compact, v.Value); err != nil {
			// Value isn't valid JSON — hash raw bytes as a fallback.
			compact.Reset()
			compact.Write(v.Value)
		}
		h := sha256.Sum256(compact.Bytes())
		out[k] = hex.EncodeToString(h[:])
	}
	return out, nil
}

func printDiff(refMap, currentMap map[string]string, ref string, w io.Writer) error {
	var added, removed, changed, unchanged []string
	for k := range currentMap {
		if _, was := refMap[k]; !was {
			added = append(added, k)
		} else if refMap[k] != currentMap[k] {
			changed = append(changed, k)
		} else {
			unchanged = append(unchanged, k)
		}
	}
	for k := range refMap {
		if _, has := currentMap[k]; !has {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)

	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Fprintf(w, "no changes vs %s (%d unchanged keys)\n", ref, len(unchanged))
		return nil
	}

	for _, k := range added {
		fmt.Fprintf(w, "+ %s\tadded\n", k)
	}
	for _, k := range changed {
		fmt.Fprintf(w, "~ %s\tchanged\n", k)
	}
	for _, k := range removed {
		fmt.Fprintf(w, "- %s\tremoved\n", k)
	}
	if len(unchanged) > 0 {
		fmt.Fprintf(w, "  (%d unchanged keys omitted)\n", len(unchanged))
	}
	return nil
}

func init() {
	SecretsCmd.AddCommand(diffCmd)
}

// archive-bytes-at-ref helpers live in diff_git.go to keep this file free of
// process-spawning code (security-hook policy).
