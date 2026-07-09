package cryptoid

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frozenVectors, testdata/frozen_vectors.json şemasıdır. Bu dosya, Go çekirdeği
// ile TypeScript Worker doğrulayıcısının AYNI donmuş vektörlere karşı çapraz
// test edilebilmesi için taşınabilir (cross-impl) bir artefakttır (SPEC §3.1).
type frozenVectors struct {
	Wrap struct {
		DEKHex             string `json:"dek_hex"`
		RecipientScalarHex string `json:"recipient_scalar_hex"`
		Recipient          string `json:"recipient"`
		RecipientFP        string `json:"recipient_fingerprint"`
		Slot               struct {
			Project    string `json:"project"`
			KeyName    string `json:"keyName"`
			KeyVersion uint64 `json:"keyVersion"`
		} `json:"slot"`
		WrapHex string `json:"wrap_hex"`
	} `json:"wrap"`
	Blob struct {
		DEKHex   string `json:"dek_hex"`
		NonceHex string `json:"nonce_hex"`
		Slot     struct {
			Project    string `json:"project"`
			KeyName    string `json:"keyName"`
			KeyVersion uint64 `json:"keyVersion"`
		} `json:"slot"`
		Plaintext string `json:"plaintext"`
		BlobHex   string `json:"blob_hex"`
		BlobHash  string `json:"blob_hash"`
	} `json:"blob"`
	Ed25519 struct {
		SeedHex string `json:"seed_hex"`
		Message string `json:"message"`
		KeyID   string `json:"key_id"`
		SigHex  string `json:"sig_hex"`
	} `json:"ed25519"`
	Shamir struct {
		SecretHex string   `json:"secret_hex"`
		Parts     int      `json:"parts"`
		Threshold int      `json:"threshold"`
		SharesHex []string `json:"shares_hex"`
	} `json:"shamir"`
}

func loadFrozen(t *testing.T) frozenVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/frozen_vectors.json")
	require.NoError(t, err)
	var fv frozenVectors
	require.NoError(t, json.Unmarshal(raw, &fv))
	return fv
}

// TestFrozenVectors_CrossImpl, Go çekirdeğinin testdata/frozen_vectors.json'daki
// her vektörü byte-bayt yeniden ürettiğini doğrular. Bu dosya değişirse (ve kod
// eşleşmezse) test kırılır — format ASLA sessizce değişemez (SPEC §3.1).
func TestFrozenVectors_CrossImpl(t *testing.T) {
	fv := loadFrozen(t)

	t.Run("wrap", func(t *testing.T) {
		var dek DEK
		mustHex(t, fv.Wrap.DEKHex, dek[:])
		id, err := NewX25519IdentityFromScalar(mustHexBytes(t, fv.Wrap.RecipientScalarHex))
		require.NoError(t, err)
		rec := id.Recipient()
		assert.Equal(t, fv.Wrap.Recipient, rec.String())
		assert.Equal(t, fv.Wrap.RecipientFP, rec.Fingerprint())
		slot := Slot{Project: fv.Wrap.Slot.Project, KeyName: fv.Wrap.Slot.KeyName, KeyVersion: fv.Wrap.Slot.KeyVersion}
		wrap, err := SealDEK(dek, rec, slot)
		require.NoError(t, err)
		assert.Equal(t, fv.Wrap.WrapHex, hex.EncodeToString(wrap))
	})

	t.Run("blob", func(t *testing.T) {
		var dek DEK
		mustHex(t, fv.Blob.DEKHex, dek[:])
		nonce := mustHexBytes(t, fv.Blob.NonceHex)
		slot := Slot{Project: fv.Blob.Slot.Project, KeyName: fv.Blob.Slot.KeyName, KeyVersion: fv.Blob.Slot.KeyVersion}
		blob, err := sealBlobWithNonce([]byte(fv.Blob.Plaintext), dek, slot, nonce)
		require.NoError(t, err)
		assert.Equal(t, fv.Blob.BlobHex, hex.EncodeToString(blob))
		assert.Equal(t, fv.Blob.BlobHash, BlobHash(blob))
	})

	t.Run("ed25519", func(t *testing.T) {
		k, err := NewEd25519FromSeed(mustHexBytes(t, fv.Ed25519.SeedHex))
		require.NoError(t, err)
		assert.Equal(t, fv.Ed25519.KeyID, k.KeyID())
		sig, err := k.Sign([]byte(fv.Ed25519.Message))
		require.NoError(t, err)
		assert.Equal(t, fv.Ed25519.SigHex, hex.EncodeToString(sig.Sig))
	})

	t.Run("shamir", func(t *testing.T) {
		secret := mustHexBytes(t, fv.Shamir.SecretHex)
		rng := bytes.NewReader(bytes.Repeat([]byte{0xAB, 0xCD}, 64))
		shares, err := ShamirSplit(secret, fv.Shamir.Parts, fv.Shamir.Threshold, rng)
		require.NoError(t, err)
		require.Len(t, shares, len(fv.Shamir.SharesHex))
		for i, sh := range shares {
			assert.Equal(t, fv.Shamir.SharesHex[i], hex.EncodeToString(sh))
		}
		// Ve geri toplanabildiğini doğrula.
		got, err := ShamirCombine([][]byte{shares[0], shares[1]})
		require.NoError(t, err)
		assert.Equal(t, secret, got)
	})
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustHex(t *testing.T, s string, dst []byte) {
	t.Helper()
	b := mustHexBytes(t, s)
	require.Len(t, b, len(dst))
	copy(dst, b)
}
