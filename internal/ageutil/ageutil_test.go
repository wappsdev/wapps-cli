package ageutil

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	plaintext := []byte(`{"jwt_signing_key":{"value":"secret-abc-123"}}`)
	passphrase := "test-master-passphrase-2026"

	encrypted, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(string(encrypted[:20]), "age-encryption.org") {
		t.Fatalf("Expected age header, got: %s", encrypted[:50])
	}

	decrypted, err := Decrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Roundtrip mismatch.\nWant: %s\nGot:  %s", plaintext, decrypted)
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	plaintext := []byte("secret")
	encrypted, _ := Encrypt(plaintext, "correct-pass")

	_, err := Decrypt(encrypted, "wrong-pass")
	if err == nil {
		t.Errorf("Expected decrypt error with wrong passphrase, got nil")
	}
}
