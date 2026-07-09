package cryptoid

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPad_Buckets, padding'in doğru kovayı seçtiğini ve round-trip yaptığını
// doğrular (SPEC §3.5.2).
func TestPad_Buckets(t *testing.T) {
	cases := []struct {
		name       string
		plaintext  int
		wantBucket int
	}{
		{"empty", 0, 256},
		{"tiny", 10, 256},
		{"exactly 252 -> 256", 252, 256},
		{"253 -> 1K (253+4=257>256)", 253, 1024},
		{"1020 -> 1K", 1020, 1024},
		{"1021 -> 4K", 1021, 4096},
		{"4092 -> 4K", 4092, 4096},
		{"4093 -> 8K", 4093, 8192},
		{"10000 -> 12K", 10000, 12288},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt := bytes.Repeat([]byte{0xAA}, c.plaintext)
			padded, err := pad(pt)
			require.NoError(t, err)
			assert.Equal(t, c.wantBucket, len(padded), "bucket size")

			out, err := unpad(padded)
			require.NoError(t, err)
			assert.Equal(t, pt, out)
		})
	}
}

// TestPad_TooLarge, kapasiteyi aşan değerin ErrValueTooLarge ile reddedildiğini
// doğrular (SPEC §3.5.2).
func TestPad_TooLarge(t *testing.T) {
	_, err := pad(bytes.Repeat([]byte{0x01}, maxBucket)) // maxBucket+4 > maxBucket
	assert.ErrorIs(t, err, ErrValueTooLarge)
}

// TestUnpad_Tamper, bozuk padding'in ErrBlobMalformed döndürdüğünü doğrular.
func TestUnpad_Tamper(t *testing.T) {
	padded, err := pad([]byte("hello"))
	require.NoError(t, err)

	t.Run("nonzero fill", func(t *testing.T) {
		bad := bytes.Clone(padded)
		bad[100] = 0x01 // dolgu bölgesinde sıfır-olmayan bayt
		_, err := unpad(bad)
		assert.ErrorIs(t, err, ErrBlobMalformed)
	})
	t.Run("length beyond bucket", func(t *testing.T) {
		bad := bytes.Clone(padded)
		bad[0], bad[1], bad[2], bad[3] = 0xFF, 0xFF, 0xFF, 0xFF // devasa uzunluk
		_, err := unpad(bad)
		assert.ErrorIs(t, err, ErrBlobMalformed)
	})
	t.Run("invalid bucket size", func(t *testing.T) {
		_, err := unpad(make([]byte, 300)) // 300 geçerli kova değil
		assert.ErrorIs(t, err, ErrBlobMalformed)
	})
}

// FROZEN VEKTÖR (SPEC §3.1): sabit plaintext + DEK + nonce + slot → bilinen
// blob baytları ve içerik adresi. Değişirse blob formatı kırılmış demektir.
const (
	frozenBlobHex  = "5753423111111111111111111111111111111111111111111111111197d73761ed190171ce9c5c7fe2c11f325f341dc2fcac5c9c8142e23dc856086bd7435bffcea5dcdcc0275ce213aa333fd85c279fd0b1f8e03a9fa2e143cb13b8f250676d7b74740c67e143ed26793a63b8b96327ee9c21bf1fe13c2db236845eccbd227fe8b8d6a548fdf3cb79f0c183f1ff9a378e6a9d55e31aa4677677d96eb6e1a932cef7dfef2c416da84a47e0f2e085fb37e1eaaf2a8fcd115bfb7047bdb22e8751f0a2a443495485b7a724b44a30d4a88ccba0663bb44dbda1532d0c50843b9fc4b13083d539b6b8d91028e76c7c66c9cd9f5421737d73c797261637e55c60719e7737ed99afd91d375e578bf0f3d9b5dc19fa447a81bd3b29d559a6b7c2522ef586324d92223ee28ff61c841b"
	frozenBlobHash = "b8f2c16a9bc8b4875e55f29d52f66497f80a1ba3238d7872be171a3573b38b23"
	frozenBlobPT   = "postgres://user:pass@host/db"
)

// TestSealBlob_FrozenVector, sabit-nonce blob'un donmuş golden ile eşleştiğini
// ve round-trip açıldığını doğrular.
func TestSealBlob_FrozenVector(t *testing.T) {
	dek := fixedDEK()
	nonce := bytes.Repeat([]byte{0x11}, 24)
	blob, err := sealBlobWithNonce([]byte(frozenBlobPT), dek, testSlot, nonce)
	require.NoError(t, err)
	assert.Equal(t, frozenBlobHex, hex.EncodeToString(blob), "blob format changed — FROZEN vector broken")
	assert.Equal(t, frozenBlobHash, BlobHash(blob))
	assert.True(t, strings.HasPrefix(string(blob), BlobMagic))

	out, err := OpenBlob(blob, dek, testSlot)
	require.NoError(t, err)
	assert.Equal(t, frozenBlobPT, string(out))
}

// TestBlob_Roundtrip, rastgele nonce ile blob seal/open round-trip'i doğrular.
func TestBlob_Roundtrip(t *testing.T) {
	dek, err := NewDEK()
	require.NoError(t, err)
	pt := []byte("super-secret-value-42")
	blob, err := SealBlob(pt, dek, testSlot)
	require.NoError(t, err)
	out, err := OpenBlob(blob, dek, testSlot)
	require.NoError(t, err)
	assert.Equal(t, pt, out)
}

// TestBlob_AADBinding, blob'un farklı bir (project,keyName,keyVersion) altında
// AÇILAMADIĞINI doğrular — AAD bağlaması (SPEC §3.5.3, blob-swap savunması).
func TestBlob_AADBinding(t *testing.T) {
	dek := fixedDEK()
	blob, err := SealBlob([]byte("v"), dek, testSlot)
	require.NoError(t, err)

	wrong := []Slot{
		{Project: "other", KeyName: testSlot.KeyName, KeyVersion: testSlot.KeyVersion},
		{Project: testSlot.Project, KeyName: "OTHER", KeyVersion: testSlot.KeyVersion},
		{Project: testSlot.Project, KeyName: testSlot.KeyName, KeyVersion: 999},
	}
	for _, w := range wrong {
		_, err := OpenBlob(blob, dek, w)
		assert.ErrorIs(t, err, ErrBlobMalformed, "slot %+v must fail AEAD", w)
	}
}

// TestBlob_Tamper, tek bayt bozulmasının (magic/nonce/ciphertext) açmayı
// bozduğunu doğrular.
func TestBlob_Tamper(t *testing.T) {
	dek := fixedDEK()
	blob, err := SealBlob([]byte("value"), dek, testSlot)
	require.NoError(t, err)

	t.Run("bad magic", func(t *testing.T) {
		bad := bytes.Clone(blob)
		bad[0] = 'X'
		_, err := OpenBlob(bad, dek, testSlot)
		assert.ErrorIs(t, err, ErrBlobMalformed)
	})
	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := bytes.Clone(blob)
		bad[len(bad)-1] ^= 0x01
		_, err := OpenBlob(bad, dek, testSlot)
		assert.ErrorIs(t, err, ErrBlobMalformed)
	})
	t.Run("wrong DEK", func(t *testing.T) {
		var other DEK
		other[0] = 0xFF
		_, err := OpenBlob(blob, other, testSlot)
		assert.ErrorIs(t, err, ErrBlobMalformed)
	})
}

// TestVerifyBlobHash, içerik-adresi doğrulamasını test eder (SPEC §3.5.4).
func TestVerifyBlobHash(t *testing.T) {
	dek := fixedDEK()
	blob, err := SealBlob([]byte("x"), dek, testSlot)
	require.NoError(t, err)

	assert.NoError(t, VerifyBlobHash(blob, BlobHash(blob)))
	assert.NoError(t, VerifyBlobHash(blob, strings.ToUpper(BlobHash(blob)))) // case-insensitive
	assert.ErrorIs(t, VerifyBlobHash(blob, strings.Repeat("0", 64)), ErrBlobHashMismatch)

	bad := bytes.Clone(blob)
	bad[30] ^= 0x01
	assert.ErrorIs(t, VerifyBlobHash(bad, BlobHash(blob)), ErrBlobHashMismatch)
}

// TestAAD_Encoding, AAD kodlamasının tam byte dizisini doğrular (SPEC §3.5.3).
func TestAAD_Encoding(t *testing.T) {
	s := Slot{Project: "vaulter", KeyName: "DB_URL", KeyVersion: 42}
	want := append([]byte("vaulter"), 0x00)
	want = append(want, []byte("DB_URL")...)
	want = append(want, 0x00)
	want = append(want, []byte("42")...)
	assert.Equal(t, want, s.AAD())
}

// TestSlot_NULRejected, project/keyName içinde NUL'un reddedildiğini doğrular.
func TestSlot_NULRejected(t *testing.T) {
	dek := fixedDEK()
	_, err := SealBlob([]byte("v"), dek, Slot{Project: "a\x00b", KeyName: "K", KeyVersion: 1})
	assert.Error(t, err)
	_, err = SealBlob([]byte("v"), dek, Slot{Project: "a", KeyName: "K\x00", KeyVersion: 1})
	assert.Error(t, err)
}
