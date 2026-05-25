package ageutil

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
)

func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("ageutil.Encrypt: new recipient: %w", err)
	}

	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("ageutil.Encrypt: writer: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("ageutil.Encrypt: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("ageutil.Encrypt: close: %w", err)
	}
	return buf.Bytes(), nil
}

func Decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("ageutil.Decrypt: new identity: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("ageutil.Decrypt: reader: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("ageutil.Decrypt: read: %w", err)
	}
	return plaintext, nil
}
