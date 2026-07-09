package cryptoid

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FROZEN VEKTÖR (SPEC §3.9): sabit gizli (0x42×32) + sabit rng → bilinen paylar.
var frozenShamirShares = []string{
	"e98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98f01",
	"0fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc302",
	"a40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40e03",
}

func TestShamir_FrozenVector(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	fixed := bytes.NewReader(bytes.Repeat([]byte{0xAB, 0xCD}, 64))
	shares, err := ShamirSplit(secret, 3, 2, fixed)
	require.NoError(t, err)
	require.Len(t, shares, 3)
	for i, sh := range shares {
		assert.Equal(t, frozenShamirShares[i], hex.EncodeToString(sh), "shamir share %d format changed — FROZEN vector broken", i)
	}
	// Herhangi 2 pay gizli sırrı geri vermeli.
	got, err := ShamirCombine([][]byte{shares[0], shares[2]})
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

// TestShamir_2of3_AllPairs, 2-of-3'te tüm pay çiftlerinin (ve üçlü) sırrı geri
// verdiğini; tek payın vermediğini doğrular.
func TestShamir_2of3_AllPairs(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	shares, err := ShamirSplit(secret, 3, 2, rand.Reader)
	require.NoError(t, err)

	pairs := [][]int{{0, 1}, {0, 2}, {1, 2}, {0, 1, 2}}
	for _, p := range pairs {
		subset := make([][]byte, 0, len(p))
		for _, idx := range p {
			subset = append(subset, shares[idx])
		}
		got, err := ShamirCombine(subset)
		require.NoError(t, err)
		assert.Equal(t, secret, got, "subset %v must recombine", p)
	}

	// Tek pay yetmez (threshold=2): en az 2 pay gerekli.
	_, err = ShamirCombine([][]byte{shares[0]})
	assert.Error(t, err)
}

// TestShamir_DuplicateAndBadShares, bozuk girdilerin reddedildiğini doğrular.
func TestShamir_DuplicateAndBadShares(t *testing.T) {
	secret := []byte("some-32-byte-escrow-scalar-here!")
	shares, err := ShamirSplit(secret, 3, 2, rand.Reader)
	require.NoError(t, err)

	t.Run("duplicate x", func(t *testing.T) {
		_, err := ShamirCombine([][]byte{shares[0], shares[0]})
		assert.Error(t, err)
	})
	t.Run("unequal length", func(t *testing.T) {
		short := shares[1][:len(shares[1])-2]
		_, err := ShamirCombine([][]byte{shares[0], short})
		assert.Error(t, err)
	})
	t.Run("zero x-coordinate", func(t *testing.T) {
		bad := bytes.Clone(shares[1])
		bad[len(bad)-1] = 0
		_, err := ShamirCombine([][]byte{shares[0], bad})
		assert.Error(t, err)
	})
}

// TestShamir_TamperedShareWrongSecret, bir payın gövdesi bozulursa yanlış
// (ama yine de deterministik) bir sonuç çıktığını ve doğru sırra EŞİT
// OLMADIĞINI doğrular — Shamir bütünlük SAĞLAMAZ (kripto katmanı bunu blob
// AEAD ile sağlar); bu test beklentiyi belgeler.
func TestShamir_TamperedShareWrongSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 32)
	shares, err := ShamirSplit(secret, 3, 2, rand.Reader)
	require.NoError(t, err)
	bad := bytes.Clone(shares[0])
	bad[0] ^= 0xFF
	got, err := ShamirCombine([][]byte{bad, shares[1]})
	require.NoError(t, err)
	assert.NotEqual(t, secret, got)
}

// TestShamir_InvalidParams, geçersiz parametrelerin reddedildiğini doğrular.
func TestShamir_InvalidParams(t *testing.T) {
	sec := []byte("x")
	_, err := ShamirSplit(nil, 3, 2, rand.Reader)
	assert.Error(t, err)
	_, err = ShamirSplit(sec, 2, 3, rand.Reader) // parts < threshold
	assert.Error(t, err)
	_, err = ShamirSplit(sec, 3, 1, rand.Reader) // threshold < 2
	assert.Error(t, err)
	_, err = ShamirSplit(sec, 3, 2, nil) // nil rng
	assert.Error(t, err)
}

// TestGF256_FieldAxioms, GF(2^8) alan aksiyomlarını (a*inv(a)=1) doğrular.
func TestGF256_FieldAxioms(t *testing.T) {
	for a := 1; a < 256; a++ {
		inv := gfInv(uint8(a))
		assert.Equal(t, uint8(1), gfMul(uint8(a), inv), "a*inv(a) must be 1 for a=%d", a)
	}
	// Çarpım değişmeli.
	assert.Equal(t, gfMul(0x53, 0xCA), gfMul(0xCA, 0x53))
}
