package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

var rotateMasterCmd = &cobra.Command{
	Use:   "rotate-master",
	Short: "Re-encrypt archive with NEW master passphrase + write audit log",
	Long: `Re-encrypt the secrets archive with a new master passphrase.

Reads:
  WAPPS_SECRETS_PASSPHRASE       current passphrase (decrypt)
  WAPPS_SECRETS_PASSPHRASE_NEW   new passphrase (re-encrypt)

After successful rotation, appends one JSONL line to <archive-dir>/rotation.log
recording the event for audit purposes. The log is gitignored by convention
(see .gitignore template in the design doc) — pp hash fingerprints are
sensitive enough to keep local-only.

Operators should distribute the new passphrase via Signal E2E to the team,
then everyone updates their Apple Passwords + WAPPS_SECRETS_PASSPHRASE env.
The old passphrase still works against historical git revisions of the
archive — this is by design (rotation isn't crypto-erasure).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotateMaster(os.Getenv)
	},
}

// runRotateMaster is the testable entry point. lookup is os.Getenv in
// production; tests inject their own to drive specific env states.
func runRotateMaster(lookup func(string) string) error {
	oldPass := lookup("WAPPS_SECRETS_PASSPHRASE")
	if oldPass == "" {
		return fmt.Errorf("rotate-master: set WAPPS_SECRETS_PASSPHRASE (current passphrase)")
	}
	newPass := lookup("WAPPS_SECRETS_PASSPHRASE_NEW")
	if newPass == "" {
		return fmt.Errorf("rotate-master: set WAPPS_SECRETS_PASSPHRASE_NEW (new passphrase) — save to Apple Passwords first")
	}
	if oldPass == newPass {
		return fmt.Errorf("rotate-master: new passphrase equals old — nothing to rotate")
	}

	archivePath := resolveArchivePath()
	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("rotate-master: read %s: %w", archivePath, err)
	}
	dec, err := ageutil.Decrypt(enc, oldPass)
	if err != nil {
		return fmt.Errorf("rotate-master: decrypt with OLD pass failed: %w", err)
	}

	// Count keys so the audit log records a decryptable-state signal.
	// (If decrypt succeeds but parse fails, we still log archive_count=-1
	// rather than aborting — rotation worked even on non-JSON archives.)
	keyCount := countArchiveKeys(dec)

	if err := ageutil.EncryptWriteAtomic(archivePath, dec, newPass); err != nil {
		return fmt.Errorf("rotate-master: %w", err)
	}

	if err := appendRotationAudit(archivePath, oldPass, newPass, keyCount); err != nil {
		// Don't fail the rotation if audit write fails — the archive is
		// already re-encrypted and operator needs to distribute the new pp.
		// Warn instead so they know to investigate the log separately.
		fmt.Fprintf(os.Stderr, "⚠ rotation succeeded but audit log write failed: %v\n", err)
	}

	fmt.Println("✓ Archive re-encrypted with new passphrase")
	fmt.Println("Next: commit + push, then share new passphrase to team via Signal E2E")
	return nil
}

// rotationAuditEntry is the JSONL schema for rotation.log. SchemaVersion
// lets future CLI versions detect format changes; readers should skip
// entries with unknown versions.
type rotationAuditEntry struct {
	SchemaVersion int      `json:"schema_version"`
	Timestamp     string   `json:"ts"`
	Actor         string   `json:"actor"`
	ArchivePaths  []string `json:"archive_paths"`
	ArchiveCount  int      `json:"archive_count"` // key count in decrypted archive, -1 if non-JSON
	OldPPFingerprint string `json:"old_pp_hash"`
	NewPPFingerprint string `json:"new_pp_hash"`
}

// appendRotationAudit writes one JSONL line to <archive-dir>/rotation.log.
// Pp hashes are truncated SHA256 (16 hex chars = 64 bits) — enough as a
// confirm-only fingerprint to verify "yes this rotation went from pp-A to
// pp-B", but NOT enough to brute-force the passphrase offline. The log is
// expected to be gitignored.
func appendRotationAudit(archivePath, oldPass, newPass string, archiveCount int) error {
	currentUser := "unknown"
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}

	entry := rotationAuditEntry{
		SchemaVersion:    1,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Actor:            currentUser,
		ArchivePaths:     []string{archivePath},
		ArchiveCount:     archiveCount,
		OldPPFingerprint: passphraseFingerprint(oldPass),
		NewPPFingerprint: passphraseFingerprint(newPass),
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	logPath := filepath.Join(filepath.Dir(archivePath), "rotation.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open audit log %s: %w", logPath, err)
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit line: %w", err)
	}
	return nil
}

// passphraseFingerprint returns the first 16 hex chars of SHA256(pp). This
// is a confirm-only fingerprint, NOT a verification mechanism:
//   - 64 bits is enough to uniquely identify a known pp on a single machine
//     (collision risk negligible for the rotation event count)
//   - Not enough to brute-force the original pp from the fingerprint alone
//   - Combined with archive content, theoretically aids dictionary attack —
//     this is why rotation.log is gitignored (kept local-machine-only).
func passphraseFingerprint(pp string) string {
	h := sha256.Sum256([]byte(pp))
	return hex.EncodeToString(h[:8]) // 8 bytes = 16 hex chars
}

// countArchiveKeys returns the number of top-level keys in a JSON archive,
// or -1 if the data isn't valid JSON (e.g., legacy raw tofu archives might
// occasionally fail this parse). Used for the audit "this rotation
// re-encrypted N keys" signal.
func countArchiveKeys(decrypted []byte) int {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(decrypted, &m); err != nil {
		return -1
	}
	return len(m)
}

func init() {
	SecretsCmd.AddCommand(rotateMasterCmd)
}
