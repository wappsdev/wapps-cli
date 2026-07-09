package cryptoid

import (
	"bytes"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBech32_RoundTrip, encode→decode round-trip'i doğrular.
func TestBech32_RoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, 32)
	enc, err := bech32Encode("age", data)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(enc, "age1"))
	hrp, dec, err := bech32Decode(enc)
	require.NoError(t, err)
	assert.Equal(t, "age", hrp)
	assert.Equal(t, data, dec)
}

// TestBech32_UppercaseHRP, büyük-harf HRP'nin (AGE-SECRET-KEY-) büyük-harf
// çıktı ürettiğini ve age tarafından çözülebildiğini doğrular.
func TestBech32_MatchesAge(t *testing.T) {
	// age ile üretilmiş gerçek bir kimliğin bizim decoder'ımızla çözülmesi.
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	recStr := id.Recipient().String()
	hrp, point, err := bech32Decode(recStr)
	require.NoError(t, err)
	assert.Equal(t, "age", hrp)
	assert.Len(t, point, 32)

	// Bizim ürettiğimiz secret-key string'i age tarafından parse edilebilmeli.
	scalar := bytes.Repeat([]byte{0x09}, 32)
	sk, err := bech32Encode("AGE-SECRET-KEY-", scalar)
	require.NoError(t, err)
	assert.Equal(t, strings.ToUpper(sk), sk, "uppercase HRP -> uppercase output")
	_, err = age.ParseX25519Identity(sk)
	assert.NoError(t, err)
}

// TestBech32_BadChecksum, bozuk checksum'un reddedildiğini doğrular.
func TestBech32_BadChecksum(t *testing.T) {
	enc, err := bech32Encode("age", bytes.Repeat([]byte{0x01}, 32))
	require.NoError(t, err)
	bad := []byte(enc)
	bad[len(bad)-1] ^= 1 // son karakteri boz (aynı charset içinde kalmayabilir)
	if bad[len(bad)-1] == enc[len(enc)-1] {
		t.Skip("no-op flip")
	}
	_, _, derr := bech32Decode(string(bad))
	assert.Error(t, derr)
}

// TestParseX25519Recipient_Point, alıcı string'inden çözülen noktanın kimlikle
// tutarlı olduğunu doğrular.
func TestParseX25519Recipient_Point(t *testing.T) {
	id, err := NewX25519IdentityFromScalar(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	rec := id.Recipient()
	parsed, err := ParseX25519Recipient(rec.String())
	require.NoError(t, err)
	assert.Equal(t, rec.Point(), parsed.Point())
	assert.Len(t, parsed.Point(), 32)
}
