package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

func TestSyncWritesEncryptedArchive(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("WAPPS_SECRETS_PASSPHRASE", "test-pass-123")

	stubOutput := `{"jwt_key":{"value":"abc","sensitive":true,"type":"string"}}`
	stubFn := func() ([]byte, error) { return []byte(stubOutput), nil }

	if err := syncWithTofuOutput(stubFn, filepath.Join(tmp, "all.enc.age")); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	enc, err := os.ReadFile(filepath.Join(tmp, "all.enc.age"))
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	dec, err := ageutil.Decrypt(enc, "test-pass-123")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(dec) != stubOutput {
		t.Errorf("Want %s, got %s", stubOutput, dec)
	}
}
