package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileSource_NewFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	if err := WriteFileSource(path, "STRIPE_KEY", "sk_test_123"); err != nil {
		t.Fatalf("WriteFileSource: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	content := string(data)
	if !strings.HasPrefix(content, FileSourceHeader) {
		t.Errorf("missing header:\n%s", content)
	}
	if !strings.Contains(content, "STRIPE_KEY='sk_test_123'") {
		t.Errorf("missing key line:\n%s", content)
	}
}

func TestWriteFileSource_AppendsAndSorts(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	if err := WriteFileSource(path, "ZETA", "z"); err != nil {
		t.Fatalf("WriteFileSource ZETA: %v", err)
	}
	if err := WriteFileSource(path, "ALPHA", "a"); err != nil {
		t.Fatalf("WriteFileSource ALPHA: %v", err)
	}
	if err := WriteFileSource(path, "MIKE", "m"); err != nil {
		t.Fatalf("WriteFileSource MIKE: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)

	alphaIdx := strings.Index(content, "ALPHA=")
	mikeIdx := strings.Index(content, "MIKE=")
	zetaIdx := strings.Index(content, "ZETA=")
	if !(alphaIdx > 0 && alphaIdx < mikeIdx && mikeIdx < zetaIdx) {
		t.Errorf("not sorted alphabetically:\n%s", content)
	}
}

func TestWriteFileSource_OverridesExistingKey(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	if err := WriteFileSource(path, "FOO", "old"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileSource(path, "FOO", "new-rotated"); err != nil {
		t.Fatalf("second write: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "FOO='new-rotated'") {
		t.Errorf("new value missing:\n%s", content)
	}
	if strings.Contains(content, "FOO='old'") {
		t.Errorf("old value still present:\n%s", content)
	}
}

func TestWriteFileSource_EscapesSingleQuotes(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	if err := WriteFileSource(path, "TRICKY", "it's tricky"); err != nil {
		t.Fatalf("WriteFileSource: %v", err)
	}

	data, _ := os.ReadFile(path)
	want := `TRICKY='it'\''s tricky'`
	if !strings.Contains(string(data), want) {
		t.Errorf("single-quote escape wrong.\nwant substring: %q\ngot: %s", want, data)
	}
}

func TestWriteFileSource_PreservesExistingKeysOnAppend(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	// Seed file with existing keys (header + 2 entries).
	seed := FileSourceHeader + "KEEP_ME='original'\nALSO_KEEP='intact'\n"
	if err := os.WriteFile(path, []byte(seed), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := WriteFileSource(path, "NEW_KEY", "new"); err != nil {
		t.Fatalf("WriteFileSource: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	for _, k := range []string{"KEEP_ME='original'", "ALSO_KEEP='intact'", "NEW_KEY='new'"} {
		if !strings.Contains(content, k) {
			t.Errorf("missing %s after merge:\n%s", k, content)
		}
	}
}

func TestWriteFileSource_FileMode0600(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	if err := WriteFileSource(path, "SECRET", "value"); err != nil {
		t.Fatalf("WriteFileSource: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("file mode = %o, want 0600 (owner read/write only — secrets file)", mode)
	}
}

func TestWriteFileSource_AtomicNoTempLeftover(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.shared")

	if err := WriteFileSource(path, "X", "y"); err != nil {
		t.Fatalf("WriteFileSource: %v", err)
	}

	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file %s should not persist after successful write", tmpPath)
	}
}
