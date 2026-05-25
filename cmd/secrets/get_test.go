package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

func setupEncryptedArchive(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	plaintext := []byte(`{"jwt_key":{"value":"abc-123","sensitive":true},"db_password":{"value":"pgpass","sensitive":true}}`)
	enc, err := ageutil.Encrypt(plaintext, "test-pass")
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(tmp, "all.enc.age")
	os.WriteFile(archivePath, enc, 0600)
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test-pass")
	return archivePath
}

func TestGetReturnsSingleValue(t *testing.T) {
	archive := setupEncryptedArchive(t)
	val, err := readKey(archive, "jwt_key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "abc-123" {
		t.Errorf("Want abc-123, got %q", val)
	}
}

func TestGetMissingKeyError(t *testing.T) {
	archive := setupEncryptedArchive(t)
	_, err := readKey(archive, "nonexistent")
	if err == nil {
		t.Errorf("Expected error for missing key")
	}
}

func TestListReturnsAllNames(t *testing.T) {
	archive := setupEncryptedArchive(t)
	buf := &bytes.Buffer{}
	if err := listKeys(archive, buf); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	for _, want := range []string{"jwt_key", "db_password"} {
		if !strings.Contains(output, want) {
			t.Errorf("List missing %q in:\n%s", want, output)
		}
	}
}
