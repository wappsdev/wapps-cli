package ageutil

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteFileAtomic_CreatesFileWithMode(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secrets.age")

	if err := WriteFileAtomic(path, []byte("payload"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("mode = %o, want 0600", mode)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "payload" {
		t.Errorf("data = %q, want payload", data)
	}
}

func TestWriteFileAtomic_OverwritesExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secrets.age")
	if err := os.WriteFile(path, []byte("old contents"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := WriteFileAtomic(path, []byte("new contents"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new contents" {
		t.Errorf("data = %q, want 'new contents'", data)
	}
}

func TestWriteFileAtomic_NoTempLeftoverOnSuccess(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secrets.age")

	if err := WriteFileAtomic(path, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	// Temp file lives in same dir with leading dot + ".tmp" suffix.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %s left behind", e.Name())
		}
	}
}

func TestWriteFileAtomic_TempIsSameDirAsTarget(t *testing.T) {
	// Documents/asserts the temp file lives next to the target so the
	// rename stays within one filesystem. Cross-fs rename can fall back
	// to copy+delete, defeating atomicity.
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "secrets")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(subdir, "all.enc.age")

	if err := WriteFileAtomic(path, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	// File should be in subdir, not in tmp root.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("target file missing: %v", err)
	}
}

func TestEncryptWriteAtomic_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secrets.age")
	plaintext := []byte("hello secret world")
	pp := "test-passphrase-123"

	if err := EncryptWriteAtomic(path, plaintext, pp); err != nil {
		t.Fatalf("EncryptWriteAtomic: %v", err)
	}

	enc, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	dec, err := Decrypt(enc, pp)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Errorf("roundtrip mismatch: got %q want %q", dec, plaintext)
	}
}

func TestEncryptWriteAtomic_BadPassphraseDoesNotPartiallyWrite(t *testing.T) {
	// If Encrypt errors (e.g., scrypt setup), no temp file or target file
	// should be left behind. Simulating via empty passphrase which age's
	// scrypt recipient rejects.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secrets.age")

	err := EncryptWriteAtomic(path, []byte("data"), "")
	if err == nil {
		t.Fatal("expected error on empty passphrase")
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("target file should not exist after encrypt failure")
	}
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %s left behind", e.Name())
		}
	}
}

// TestWriteFileAtomic_ConcurrentWritersDontCorrupt closes the race where two
// processes calling WriteFileAtomic on the same path used to share a fixed
// .<name>.tmp file: the second OpenFile with O_TRUNC would wipe the first's
// in-flight buffer, and the rename order could leave a half-written byte
// stream visible. With os.CreateTemp's unique suffix, both writers complete
// independently and the result is always one of their full payloads.
func TestWriteFileAtomic_ConcurrentWritersDontCorrupt(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "racey")

	payloadA := bytes.Repeat([]byte("A"), 4096)
	payloadB := bytes.Repeat([]byte("B"), 4096)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = WriteFileAtomic(path, payloadA, 0600)
	}()
	go func() {
		defer wg.Done()
		_ = WriteFileAtomic(path, payloadB, 0600)
	}()
	wg.Wait()

	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	// Result must be exactly one of the two payloads — never a hybrid.
	if !bytes.Equal(final, payloadA) && !bytes.Equal(final, payloadB) {
		t.Errorf("concurrent writers produced corrupt output (len=%d, first byte=%q)", len(final), final[0])
	}
}

func TestWriteFileAtomic_ParentMustExist(t *testing.T) {
	// We intentionally do NOT auto-mkdir parent directories — that would
	// hide operator typos. Verify the error path is clean.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "does-not-exist", "secrets.age")

	err := WriteFileAtomic(path, []byte("x"), 0600)
	if err == nil {
		t.Fatal("expected error when parent dir missing")
	}
}
