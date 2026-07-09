package cryptoid

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFingerprint_Format, parmak izi formatını doğrular (SPEC §3.7):
// "sha256:" + küçük-harf hex SHA-256(pubBytes).
func TestFingerprint_Format(t *testing.T) {
	pub := []byte("some-raw-pubkey-bytes")
	sum := sha256.Sum256(pub)
	want := "sha256:" + hex.EncodeToString(sum[:])
	got := Fingerprint(pub)
	assert.Equal(t, want, got)
	assert.True(t, strings.HasPrefix(got, FingerprintPrefix))
	assert.Len(t, got, len(FingerprintPrefix)+64) // sha256 hex = 64
}

// TestFingerprintRecipient, alıcı string'inin parmak izinin string üzerinden
// hesaplandığını doğrular (native ve plugin alıcıları aynı biçimde kapsar).
func TestFingerprintRecipient(t *testing.T) {
	rec := "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
	assert.Equal(t, Fingerprint([]byte(rec)), FingerprintRecipient(rec))

	// Plugin alıcısı (donanım) — parmak izi binary GEREKMEDEN hesaplanır.
	plug := "age1se1qgpq..." // örnek SE plugin recipient string'i
	assert.Equal(t, Fingerprint([]byte(plug)), PluginRecipientFingerprint(plug))
}
