package cryptoid

import (
	"crypto/rand"
	"fmt"
	"io"
)

// randRead, b'yi CSPRNG ile doldurur (kısa okuma = hata; fail-closed).
func randRead(b []byte) error {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Errorf("cryptoid: csprng: %w", err)
	}
	return nil
}
