package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// TestRunSet_FromFile, --from-file'ın değeri dosyadan okuduğunu (argv'de değer
// yok, TTY gerekmez) ve arşive yazdığını doğrular (§7.9.3).
func TestRunSet_FromFile(t *testing.T) {
	yaml := "version: 1\ndest: secrets/all.enc.age\nsources:\n  - type: tofu\n    workdir: .\n  - type: file\n    path: .env.shared\n"
	dir := setUpSetTestRepo(t, struct {
		yamlContent string
		envContent  string
		archiveSeed map[string]string
		passphrase  string
	}{yamlContent: yaml, envContent: "", passphrase: "pp"})

	valFile := filepath.Join(dir, "val.txt")
	if err := os.WriteFile(valFile, []byte("s3cr3t-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSet("MY_KEY", setOptions{fromFile: valFile, driftCheck: cleanDrift})
	if err != nil {
		t.Fatalf("runSet --from-file: %v", err)
	}

	// Arşivi çöz + MY_KEY == "s3cr3t-from-file" (sondaki newline soyulmuş).
	enc, err := os.ReadFile(filepath.Join(dir, "secrets/all.enc.age"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ageutil.Decrypt(enc, "pp")
	if err != nil {
		t.Fatal(err)
	}
	var archive map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(dec, &archive); err != nil {
		t.Fatal(err)
	}
	if archive["MY_KEY"].Value != "s3cr3t-from-file" {
		t.Errorf("MY_KEY = %q, want s3cr3t-from-file", archive["MY_KEY"].Value)
	}
}
