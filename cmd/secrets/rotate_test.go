package secrets

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

func setupRotateTest(t *testing.T, archive map[string]string) (oldPass, newPass string) {
	t.Helper()
	tmp := t.TempDir()
	t.Chdir(tmp)
	// Both passphrases must be >= minNewPassphraseLen (16) so the rotation
	// flow's new-pp length guard is satisfied. Test fixtures use long
	// padding so they look obviously synthetic.
	oldPass = "old-pp-test-fixture-123"
	newPass = "new-pp-test-fixture-456"

	if err := os.MkdirAll("secrets", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	envelope := make(map[string]json.RawMessage)
	for k, v := range archive {
		b, _ := json.Marshal(map[string]string{"value": v})
		envelope[k] = b
	}
	raw, _ := json.Marshal(envelope)
	if err := ageutil.EncryptWriteAtomic("secrets/all.enc.age", raw, oldPass); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return
}

// TestRunRotateMaster_AuditPathRelativeWithWappsYAML locks the audit-log path
// format for the rolled-out case (a .wapps.yaml present, so resolveArchivePath
// returns an absolute path): the audit entry's archive_paths must stay the raw
// repo-relative "secrets/all.enc.age", not the absolute resolved path. The
// rotation itself must still succeed (reads/writes the resolved archive).
func TestRunRotateMaster_AuditPathRelativeWithWappsYAML(t *testing.T) {
	oldPass, newPass := setupRotateTest(t, map[string]string{"K": "v"})
	// Seed a .wapps.yaml in cwd → resolveArchivePath resolves to an absolute
	// path; the audit field should remain relative.
	if err := os.WriteFile(".wapps.yaml", []byte("version: 1\nsources:\n  - type: tofu\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	lookup := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return oldPass
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return newPass
		}
		return ""
	}
	if err := runRotateMaster(lookup); err != nil {
		t.Fatalf("runRotateMaster: %v", err)
	}

	logData, err := os.ReadFile("secrets/rotation.log")
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entry rotationAuditEntry
	if err := json.Unmarshal([]byte(strings.SplitN(string(logData), "\n", 2)[0]), &entry); err != nil {
		t.Fatalf("parse JSONL: %v", err)
	}
	if len(entry.ArchivePaths) != 1 || entry.ArchivePaths[0] != "secrets/all.enc.age" {
		t.Errorf("archive_paths = %v, want [secrets/all.enc.age] (raw relative even with .wapps.yaml present)", entry.ArchivePaths)
	}
	// Rotation actually happened: archive now decrypts with the new pp.
	enc, _ := os.ReadFile("secrets/all.enc.age")
	if _, err := ageutil.Decrypt(enc, newPass); err != nil {
		t.Errorf("archive not re-encrypted with new pp: %v", err)
	}
}

func TestRunRotateMaster_HappyPath(t *testing.T) {
	oldPass, newPass := setupRotateTest(t, map[string]string{
		"DB_PASSWORD": "secret",
		"STRIPE_KEY":  "sk_test",
	})

	lookup := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return oldPass
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return newPass
		}
		return ""
	}

	if err := runRotateMaster(lookup); err != nil {
		t.Fatalf("runRotateMaster: %v", err)
	}

	// Archive re-encrypted: new pp decrypts, old does not.
	enc, _ := os.ReadFile("secrets/all.enc.age")
	if _, err := ageutil.Decrypt(enc, newPass); err != nil {
		t.Errorf("new passphrase should decrypt: %v", err)
	}
	if _, err := ageutil.Decrypt(enc, oldPass); err == nil {
		t.Errorf("old passphrase should NOT decrypt after rotation")
	}

	// Audit log written.
	logPath := filepath.Join("secrets", "rotation.log")
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("audit log missing: %v", err)
	}
}

func TestRunRotateMaster_AuditLogJSONLSchema(t *testing.T) {
	oldPass, newPass := setupRotateTest(t, map[string]string{
		"K1": "v1", "K2": "v2", "K3": "v3",
	})
	lookup := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return oldPass
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return newPass
		}
		return ""
	}
	if err := runRotateMaster(lookup); err != nil {
		t.Fatalf("runRotateMaster: %v", err)
	}

	logData, err := os.ReadFile("secrets/rotation.log")
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(logData)))
	if !scanner.Scan() {
		t.Fatal("audit log empty")
	}
	var entry rotationAuditEntry
	if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
		t.Fatalf("parse JSONL line: %v\nline: %s", err, scanner.Text())
	}

	if entry.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", entry.SchemaVersion)
	}
	if entry.Timestamp == "" {
		t.Errorf("ts empty")
	}
	if entry.Actor == "" {
		t.Errorf("actor empty")
	}
	if len(entry.ArchivePaths) != 1 || entry.ArchivePaths[0] != "secrets/all.enc.age" {
		t.Errorf("archive_paths = %v, want [secrets/all.enc.age]", entry.ArchivePaths)
	}
	if entry.ArchiveCount != 3 {
		t.Errorf("archive_count = %d, want 3", entry.ArchiveCount)
	}
	if entry.OldPPFingerprint == "" || entry.NewPPFingerprint == "" {
		t.Errorf("pp fingerprints empty: old=%s new=%s", entry.OldPPFingerprint, entry.NewPPFingerprint)
	}
	if entry.OldPPFingerprint == entry.NewPPFingerprint {
		t.Errorf("old and new fingerprints identical — should differ")
	}
	// Fingerprint format: 16 hex chars.
	if len(entry.OldPPFingerprint) != 16 {
		t.Errorf("old fingerprint length = %d, want 16 (truncated SHA256)", len(entry.OldPPFingerprint))
	}
}

func TestRunRotateMaster_AppendsToExistingLog(t *testing.T) {
	// Run twice — audit log should have 2 entries on disk.
	oldPass, newPass := setupRotateTest(t, map[string]string{"K": "v"})

	lookup1 := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return oldPass
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return newPass
		}
		return ""
	}
	if err := runRotateMaster(lookup1); err != nil {
		t.Fatalf("first rotate: %v", err)
	}

	// Second rotation: newPass becomes old, generate a fresh new one.
	even2Pass := "newer-pp-test-fixture-789"
	lookup2 := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return newPass
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return even2Pass
		}
		return ""
	}
	if err := runRotateMaster(lookup2); err != nil {
		t.Fatalf("second rotate: %v", err)
	}

	logData, _ := os.ReadFile("secrets/rotation.log")
	lines := strings.Count(string(logData), "\n")
	if lines != 2 {
		t.Errorf("expected 2 audit lines, got %d:\n%s", lines, logData)
	}
}

func TestRunRotateMaster_ErrorWhenSamePassphrase(t *testing.T) {
	setupRotateTest(t, map[string]string{"K": "v"})

	lookup := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE", "WAPPS_SECRETS_PASSPHRASE_NEW":
			return "same-pp-padded-for-length"
		}
		return ""
	}
	err := runRotateMaster(lookup)
	if err == nil {
		t.Fatal("expected error when old and new pp equal")
	}
	if !strings.Contains(err.Error(), "new passphrase equals old") {
		t.Errorf("error should explain: %v", err)
	}
}

func TestRunRotateMaster_ErrorWhenOldPassMissing(t *testing.T) {
	setupRotateTest(t, map[string]string{"K": "v"})
	err := runRotateMaster(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error: old passphrase required")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE") {
		t.Errorf("error should name env var: %v", err)
	}
}

func TestRunRotateMaster_ErrorWhenNewPassMissing(t *testing.T) {
	setupRotateTest(t, map[string]string{"K": "v"})
	lookup := func(k string) string {
		if k == "WAPPS_SECRETS_PASSPHRASE" {
			return "old"
		}
		return ""
	}
	err := runRotateMaster(lookup)
	if err == nil {
		t.Fatal("expected error: new passphrase required")
	}
	if !strings.Contains(err.Error(), "WAPPS_SECRETS_PASSPHRASE_NEW") {
		t.Errorf("error should name env var: %v", err)
	}
}

func TestRunRotateMaster_WrongOldPassErrors(t *testing.T) {
	_, newPass := setupRotateTest(t, map[string]string{"K": "v"})

	lookup := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return "wrong-old-pp"
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return newPass
		}
		return ""
	}
	err := runRotateMaster(lookup)
	if err == nil {
		t.Fatal("expected decrypt failure with wrong old pp")
	}
	if !strings.Contains(err.Error(), "OLD") {
		t.Errorf("error should mention OLD passphrase: %v", err)
	}
}

func TestPassphraseFingerprint_DistinctForDifferentInputs(t *testing.T) {
	fp1 := passphraseFingerprint("pp1")
	fp2 := passphraseFingerprint("pp2")
	if fp1 == fp2 {
		t.Errorf("distinct passphrases should produce distinct fingerprints")
	}
	if len(fp1) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(fp1))
	}
}

func TestPassphraseFingerprint_DeterministicForSameInput(t *testing.T) {
	if passphraseFingerprint("same-pp") != passphraseFingerprint("same-pp") {
		t.Error("same input must produce same fingerprint")
	}
}

func TestCountArchiveKeys_ValidJSON(t *testing.T) {
	if got := countArchiveKeys([]byte(`{"a":{"value":"x"},"b":{"value":"y"}}`)); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestCountArchiveKeys_InvalidJSONReturnsMinusOne(t *testing.T) {
	if got := countArchiveKeys([]byte(`not json`)); got != -1 {
		t.Errorf("got %d, want -1 for non-JSON", got)
	}
}

// TestRunRotateMaster_RejectsShortNewPassphrase is the regression for the
// silent weak-passphrase rotation: an operator who set WAPPS_SECRETS_PASSPHRASE_NEW=x
// (typo, partial paste) previously rotated successfully and the team
// distributed the brute-forceable passphrase. Now the rotation refuses.
func TestRunRotateMaster_RejectsShortNewPassphrase(t *testing.T) {
	oldPass, _ := setupRotateTest(t, map[string]string{"K": "v"})
	lookup := func(k string) string {
		switch k {
		case "WAPPS_SECRETS_PASSPHRASE":
			return oldPass
		case "WAPPS_SECRETS_PASSPHRASE_NEW":
			return "x" // 1 char, well below min
		}
		return ""
	}
	err := runRotateMaster(lookup)
	if err == nil {
		t.Fatal("expected error for too-short new passphrase")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should explain length, got: %v", err)
	}
}
