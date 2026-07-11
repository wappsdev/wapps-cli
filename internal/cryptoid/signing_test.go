package cryptoid

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FROZEN VEKTÖR (SPEC §3.1): sabit Ed25519 seed + mesaj → bilinen key_id + imza.
const (
	frozenEd25519Seed  = "0707070707070707070707070707070707070707070707070707070707070707"
	frozenEd25519Msg   = "hello wapps-secrets"
	frozenEd25519KeyID = "sha256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889"
	frozenEd25519Sig   = "0c8f6858df10d39cba54a14f7f9899e200bc82dca807aa3fb65dfcb181ccfa513d0cb58f56fabc64fc6012670a820b5e44777695d976d1b22816570fa6621c0c"
)

func TestEd25519_FrozenVector(t *testing.T) {
	seed, _ := hex.DecodeString(frozenEd25519Seed)
	k, err := NewEd25519FromSeed(seed)
	require.NoError(t, err)
	assert.Equal(t, frozenEd25519KeyID, k.KeyID())

	sig, err := k.Sign([]byte(frozenEd25519Msg))
	require.NoError(t, err)
	assert.Equal(t, AlgEd25519, sig.Alg)
	assert.Equal(t, SigSchema, sig.Schema)
	assert.Equal(t, k.KeyID(), sig.KeyID)
	assert.Equal(t, frozenEd25519Sig, hex.EncodeToString(sig.Sig), "ed25519 sig format changed — FROZEN vector broken")
}

func TestEd25519_RoundtripAndTamper(t *testing.T) {
	k, err := GenerateEd25519()
	require.NoError(t, err)
	vk, err := NewVerifierKey(AlgEd25519, k.PublicKeyBytes())
	require.NoError(t, err)

	msg := []byte("the exact stored bytes")
	sig, err := k.Sign(msg)
	require.NoError(t, err)
	require.NoError(t, VerifySignatureEnvelope(msg, sig, vk))

	// Mesajın tek baytı bozulursa doğrulama başarısız olmalı.
	tamperedMsg := bytes.Clone(msg)
	tamperedMsg[0] ^= 0x01
	assert.ErrorIs(t, vk.Verify(tamperedMsg, sig.Sig), ErrSigInvalid)

	// İmzanın tek baytı bozulursa başarısız olmalı.
	badSig := bytes.Clone(sig.Sig)
	badSig[10] ^= 0x01
	assert.ErrorIs(t, vk.Verify(msg, badSig), ErrSigInvalid)
}

func TestECDSAP256_RoundtripAndTamper(t *testing.T) {
	k, err := GenerateECDSAP256()
	require.NoError(t, err)
	vk, err := NewVerifierKey(AlgECDSAP256SHA256, k.PublicKeyBytes())
	require.NoError(t, err)
	assert.Equal(t, k.KeyID(), vk.KeyID())

	msg := []byte("data-manifest exact bytes")
	sig, err := k.Sign(msg)
	require.NoError(t, err)
	assert.Len(t, sig.Sig, 64, "P1363 r‖s must be 64 bytes")
	require.NoError(t, VerifySignatureEnvelope(msg, sig, vk))

	tampered := bytes.Clone(msg)
	tampered[len(tampered)-1] ^= 0x01
	assert.ErrorIs(t, vk.Verify(tampered, sig.Sig), ErrSigInvalid)
}

// TestECDSAP256_RejectDER, DER-kodlu ECDSA imzasının REDDEDİLDİĞİNİ doğrular
// (yalnızca ham r‖s P1363 kabul edilir, SPEC §3.2).
func TestECDSAP256_RejectDER(t *testing.T) {
	k, err := GenerateECDSAP256()
	require.NoError(t, err)
	vk, err := NewVerifierKey(AlgECDSAP256SHA256, k.PublicKeyBytes())
	require.NoError(t, err)

	msg := []byte("hello")
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, d[:])
	require.NoError(t, err)

	// Aynı imzayı DER olarak kodla — reddedilmeli (uzunluk != 64).
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	require.NoError(t, err)
	assert.ErrorIs(t, vk.Verify(msg, der), ErrSigInvalid, "DER signature must be rejected")

	// Ham r‖s (P1363) doğru şekilde kabul edilmeli.
	p1363 := make([]byte, 64)
	r.FillBytes(p1363[:32])
	s.FillBytes(p1363[32:])
	assert.NoError(t, vk.Verify(msg, p1363))
}

// TestVerifierKey_AlgUnsupported, kapalı-küme dışı alg'ın reddedildiğini doğrular.
func TestVerifierKey_AlgUnsupported(t *testing.T) {
	_, err := NewVerifierKey("rsa-pkcs1", make([]byte, 32))
	assert.ErrorIs(t, err, ErrAlgUnsupported)

	_, err = NewVerifierKey(AlgEd25519, make([]byte, 31)) // yanlış boyut
	assert.ErrorIs(t, err, ErrAlgUnsupported)

	_, err = NewVerifierKey(AlgECDSAP256SHA256, make([]byte, 65)) // geçersiz SEC1 nokta
	assert.ErrorIs(t, err, ErrAlgUnsupported)
}

// TestVerifySignatureEnvelope_Mismatches, schema/alg/key_id uyumsuzluklarının
// ErrSigInvalid döndürdüğünü doğrular.
func TestVerifySignatureEnvelope_Mismatches(t *testing.T) {
	k, err := GenerateEd25519()
	require.NoError(t, err)
	vk, err := NewVerifierKey(AlgEd25519, k.PublicKeyBytes())
	require.NoError(t, err)
	msg := []byte("m")
	good, err := k.Sign(msg)
	require.NoError(t, err)

	t.Run("bad schema", func(t *testing.T) {
		s := good
		s.Schema = "evil/v1"
		assert.ErrorIs(t, VerifySignatureEnvelope(msg, s, vk), ErrSigInvalid)
	})
	t.Run("alg mismatch", func(t *testing.T) {
		s := good
		s.Alg = AlgECDSAP256SHA256
		assert.ErrorIs(t, VerifySignatureEnvelope(msg, s, vk), ErrSigInvalid)
	})
	t.Run("key_id mismatch", func(t *testing.T) {
		s := good
		s.KeyID = "sha256:deadbeef"
		assert.ErrorIs(t, VerifySignatureEnvelope(msg, s, vk), ErrSigInvalid)
	})
}

// TestKeyID_Format, key_id parmak izi formatını doğrular (SPEC §3.6.1/§3.7).
func TestKeyID_Format(t *testing.T) {
	k, err := GenerateEd25519()
	require.NoError(t, err)
	// Ed25519 key_id = sha256(32-byte pubkey).
	sum := sha256.Sum256(k.PublicKeyBytes())
	assert.Equal(t, FingerprintPrefix+hex.EncodeToString(sum[:]), k.KeyID())

	ek, err := GenerateECDSAP256()
	require.NoError(t, err)
	// P-256 pubkey = 65-byte uncompressed SEC1.
	assert.Len(t, ek.PublicKeyBytes(), 65)
	assert.Equal(t, byte(0x04), ek.PublicKeyBytes()[0])
	// crypto/ecdh, noktanın eğri üzerinde olduğunu doğrular (deprecated değil).
	_, err = ecdh.P256().NewPublicKey(ek.PublicKeyBytes())
	require.NoError(t, err)
	// key_id = sha256(65-byte SEC1 pubkey).
	esum := sha256.Sum256(ek.PublicKeyBytes())
	assert.Equal(t, FingerprintPrefix+hex.EncodeToString(esum[:]), ek.KeyID())
}
