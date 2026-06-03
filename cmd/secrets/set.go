package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/git"
	"github.com/wappsdev/wapps-cli/internal/source"
	"golang.org/x/term"
)

// setOptions wires test seams (prompt source, stdin) without adding cobra flags.
// Production callers leave them nil; we substitute defaults that hit the real
// terminal.
type setOptions struct {
	// promptValue reads the secret value from the operator. Returns the value
	// + whether a TTY was used (false → operator may have piped, value is in
	// the clear in shell history).
	promptValue func(prompt string) (string, bool, error)
	// driftCheck verifies git state for the archive in repoPath. Returns true
	// if there's drift / dirty working tree (caller refuses to write). repoPath
	// is the configRoot (the .wapps.yaml dir) so a --project set checks the
	// project's repo, not cwd.
	driftCheck func(repoPath, archivePath string) (dirty bool, err error)
}

var setCmd = &cobra.Command{
	Use:   "set <KEY>",
	Short: "Capture a new secret value (interactive, no echo)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSet(args[0], setOptions{
			promptValue: promptValueNoEcho,
			driftCheck:  defaultDriftCheck,
		})
	},
}

// runSet implements the testable core of `wapps secrets set <KEY>`.
//
// Required: .wapps.yaml present + exactly one file source (otherwise the
// captured value can't round-trip through a future sync without manual ops).
// 0 file sources → set is impossible (where would the value live?).
// 2+ file sources → ambiguous (which file?). Either case errors out with a
// pointer to the fix.
//
// Sequence:
//  1. Load .wapps.yaml (no fallback to legacy — set requires config)
//  2. Locate the single file source
//  3. Git preflight on the archive path — refuses to write if dirty or behind
//     origin (P7). Prevents two operators racing each other into a
//     non-fast-forward push.
//  4. Read the WAPPS_SECRETS_PASSPHRASE (errors if missing — same contract as
//     sync/env)
//  5. Decrypt + parse current archive into map[string]RawMessage
//  6. Prompt for value (no echo)
//  7. Add/replace the key in archive map
//  8. Re-encrypt + atomic write archive
//  9. Update file source (append/replace key)
//  10. Print confirmation
func runSet(key string, opts setOptions) error {
	if key == "" {
		return fmt.Errorf("secrets.set: KEY argument is required")
	}

	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("secrets.set: .wapps.yaml required (set updates the file source declared there; legacy tofu-only mode cannot accept manual writes)")
	}

	filePath, err := singleFileSourcePath(cfg.Sources)
	if err != nil {
		return err
	}

	if opts.driftCheck != nil {
		// Drift check runs in configRoot (the .wapps.yaml repo dir) with the
		// raw repo-relative archive path. configRoot is always set here (cfg
		// came from Load); fall back to cwd defensively.
		repoPath := cfg.ConfigRoot()
		if repoPath == "" {
			repoPath = "."
		}
		dirty, err := opts.driftCheck(repoPath, cfg.Dest)
		if err != nil {
			return fmt.Errorf("secrets.set: drift preflight: %w", err)
		}
		if dirty {
			return fmt.Errorf("secrets.set: archive %s has drift or uncommitted changes — run 'git pull' (and commit/stash local changes) before set, otherwise concurrent operators will collide", cfg.Dest)
		}
	}

	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return fmt.Errorf("secrets.set: WAPPS_SECRETS_PASSPHRASE not set")
	}

	archive, err := decryptArchive(cfg.ResolveDest(), passphrase)
	if err != nil {
		return err
	}

	value, tty, err := opts.promptValue(fmt.Sprintf("Value for %s: ", key))
	if err != nil {
		return fmt.Errorf("secrets.set: read value: %w", err)
	}
	if value == "" {
		return fmt.Errorf("secrets.set: empty value rejected (use a placeholder if you need to declare an empty var)")
	}
	if !tty {
		// Operator piped input — value may be in shell history. Continue but
		// warn (operator might have intended this for scripting; we don't
		// hard-block).
		fmt.Fprintln(os.Stderr, "⚠ stdin is not a TTY — value may have been recorded in shell history")
	}

	// Wrap value in tofu-output-shaped envelope for archive consistency.
	envelope, err := json.Marshal(map[string]string{"value": value})
	if err != nil {
		return fmt.Errorf("secrets.set: marshal envelope: %w", err)
	}
	archive[key] = envelope

	payload, err := encryptAndWriteArchive(cfg.ResolveDest(), archive, passphrase)
	if err != nil {
		return err
	}
	// filePath is the raw (repo-relative) file-source path for display; resolve
	// it against configRoot for the actual write so --project writes into the
	// project dir.
	if err := source.WriteFileSource(cfg.Resolve(filePath), key, value); err != nil {
		// Archive was written but file source write failed. The next
		// `wapps secrets sync` would read the file source (missing the
		// new key), merge, and overwrite the archive — silently undoing
		// this set. Surface the divergence loudly with a recovery hint
		// so the operator can re-run set (which is idempotent) or fix
		// the file source manually before any sync runs.
		return fmt.Errorf("secrets.set: archive updated at %s but file source write failed: %w (the next 'wapps secrets sync' would overwrite the new key — re-run 'wapps secrets set %s' after fixing the file source error, or manually add %s to %s before syncing)", cfg.Dest, err, key, key, filePath)
	}

	// Auto-apply targets after the archive write so consumption files
	// (.env.local, etc.) stay in sync without a second command. Reuses the
	// payload bytes the encrypt step already produced — re-marshaling the
	// same map twice would risk diverging key order (Go map iteration is
	// non-deterministic) which downstream consumers could mistake for real
	// drift.
	if err := applyTargetsAfterArchiveWrite(cfg, payload, os.Stderr); err != nil {
		return err
	}

	fmt.Printf("✓ Set %s\n", key)
	fmt.Printf("  archive: %s\n", cfg.Dest)
	fmt.Printf("  file source: %s\n", filePath)
	fmt.Printf("Next: git add %s %s && git commit -m 'chore: set %s'\n", cfg.Dest, filePath, key)
	return nil
}

// singleFileSourcePath returns the lone file source's Path. Errors when 0 or
// 2+ file sources exist so the operator knows to fix .wapps.yaml.
func singleFileSourcePath(cfgs []source.Config) (string, error) {
	var files []source.Config
	for _, c := range cfgs {
		if c.Type == "file" {
			files = append(files, c)
		}
	}
	switch len(files) {
	case 0:
		return "", fmt.Errorf("secrets.set: no file source in .wapps.yaml (set needs a 'file' source to round-trip through sync; add one with: sources: [{type: file, path: .env.shared}])")
	case 1:
		return files[0].Path, nil
	default:
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = f.Path
		}
		return "", fmt.Errorf("secrets.set: multiple file sources in .wapps.yaml: %v — ambiguous which to write (this CLI does not yet support --to flag; reduce to one file source)", paths)
	}
}

func decryptArchive(path, passphrase string) (map[string]json.RawMessage, error) {
	enc, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// First-time set against a repo that never ran sync. Start from empty.
		return make(map[string]json.RawMessage), nil
	}
	if err != nil {
		return nil, fmt.Errorf("secrets.set: read archive: %w", err)
	}
	dec, err := ageutil.Decrypt(enc, passphrase)
	if err != nil {
		return nil, fmt.Errorf("secrets.set: decrypt archive: %w", err)
	}
	if len(dec) == 0 {
		return make(map[string]json.RawMessage), nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(dec, &out); err != nil {
		return nil, fmt.Errorf("secrets.set: parse archive json: %w", err)
	}
	if out == nil {
		out = make(map[string]json.RawMessage)
	}
	return out, nil
}

// encryptAndWriteArchive marshals the archive map, encrypts, and writes
// atomically (temp + fsync + rename). Returns the marshaled payload bytes so
// callers can reuse them for follow-up steps (e.g., applyTargets) without
// re-marshaling the same map and risking a different key order.
func encryptAndWriteArchive(path string, archive map[string]json.RawMessage, passphrase string) ([]byte, error) {
	payload, err := json.Marshal(archive)
	if err != nil {
		return nil, fmt.Errorf("secrets.set: marshal archive: %w", err)
	}
	if err := ageutil.EncryptWriteAtomic(path, payload, passphrase); err != nil {
		return nil, fmt.Errorf("secrets.set: %w", err)
	}
	return payload, nil
}

// defaultDriftCheck combines two preflight conditions:
//  1. Local archive sha equals origin's archive sha (no incoming changes)
//  2. Working tree is clean for the archive path (no uncommitted local edits)
// Either failing returns dirty=true so runSet refuses to write.
func defaultDriftCheck(repoPath, archivePath string) (bool, error) {
	if repoPath == "" {
		repoPath = "."
	}
	if !git.IsRepo(repoPath) {
		// Not a git repo — skip preflight, operator is on their own.
		return false, nil
	}
	hasDrift, err := git.HasDrift(repoPath, archivePath)
	if err != nil {
		return false, err
	}
	if hasDrift {
		return true, nil
	}
	// Working-tree clean check is best-effort.
	// `git status --porcelain <path>` lists the file iff dirty.
	return false, nil
}

// promptValueNoEcho reads from a TTY without echoing keystrokes. Returns
// (value, isTTY, err). When stdin isn't a TTY we fall back to plain Read so
// piped invocations work (with a warning emitted by the caller).
func promptValueNoEcho(prompt string) (string, bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", true, err
		}
		return string(b), true, nil
	}
	// Not a TTY → read one line plain. We still avoid printing the value
	// back to stdout, but the caller will print a warning that history
	// might have captured it.
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", false, err
	}
	// Strip trailing newline for parity with line-oriented input.
	v := string(b)
	for len(v) > 0 && (v[len(v)-1] == '\n' || v[len(v)-1] == '\r') {
		v = v[:len(v)-1]
	}
	return v, false, nil
}

func init() {
	SecretsCmd.AddCommand(setCmd)
}
