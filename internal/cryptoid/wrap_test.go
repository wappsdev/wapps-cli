package cryptoid

import (
	"bytes"
	"encoding/hex"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedDEK, testler için deterministik bir DEK (0,1,2,...,31).
func fixedDEK() DEK {
	var dek DEK
	for i := range dek {
		dek[i] = byte(i)
	}
	return dek
}

// fixedRecipientIdentity, sabit skalardan (0x42×32) deterministik bir X25519
// kimliği ve alıcısı döner.
func fixedRecipientIdentity(t *testing.T) (*X25519Identity, *X25519Recipient) {
	t.Helper()
	id, err := NewX25519IdentityFromScalar(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	return id, id.Recipient()
}

var testSlot = Slot{Project: "vaulter", KeyName: "DATABASE_URL", KeyVersion: 3}

// FROZEN VEKTÖR (SPEC §3.1): bilinen DEK + bilinen alıcı + slot → bilinen wrap
// baytları. Bu değer DEĞİŞİRSE wrap formatı sessizce kırılmış demektir.
const frozenWrapHex = "6167652d656e6372797074696f6e2e6f72672f76310a2d3e205832353531392049752f4761645366792f736b4a433362712b58674c45446266446579687465714f374e7147786b4b4646730a774c42725a534d6138486d6e515343502b33594973594777554850504d313741614166384b58787456524d0a2d2d2d20502b664b647945343479555431613230634336376c3653786752717237624b762f6c683057732b5749686b0ad1d16d2fa5583984cd837a0c0040e0bd97f7de3cdb92cebd08091952dab2e9b694beb3fe29ec0d20bfbf67e47f7bca7f81a65e12448927120adb9b4e632c6764"

const (
	frozenRecipient   = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
	frozenRecipientFP = "sha256:6a804773982840fa7eae3847079a53b0b140d678130dc68f1c7f72b5e5080d4f"
)

// TestSealDEK_FrozenVector, deterministik wrap'in donmuş golden ile bayt-bayt
// eşleştiğini doğrular (format sabitliği).
func TestSealDEK_FrozenVector(t *testing.T) {
	id, rec := fixedRecipientIdentity(t)
	require.Equal(t, frozenRecipient, rec.String())
	require.Equal(t, frozenRecipientFP, rec.Fingerprint())

	wrap, err := SealDEK(fixedDEK(), rec, testSlot)
	require.NoError(t, err)
	assert.Equal(t, frozenWrapHex, hex.EncodeToString(wrap), "wrap format changed — FROZEN vector broken")

	// age header ile başlamalı.
	assert.True(t, bytes.HasPrefix(wrap, []byte("age-encryption.org/v1\n")))

	// Round-trip: STANDART age.Decrypt ile çözülebilmeli (age-uyumluluk kanıtı).
	got, err := UnsealDEK(wrap, id)
	require.NoError(t, err)
	assert.Equal(t, fixedDEK(), got)
}

// TestSealDEK_Deterministic, aynı (DEK, recipient, slot)'un HER ZAMAN aynı
// baytları ürettiğini doğrular (SPEC §3.5.5 F8).
func TestSealDEK_Deterministic(t *testing.T) {
	_, rec := fixedRecipientIdentity(t)
	dek := fixedDEK()
	w1, err := SealDEK(dek, rec, testSlot)
	require.NoError(t, err)
	w2, err := SealDEK(dek, rec, testSlot)
	require.NoError(t, err)
	assert.Equal(t, w1, w2, "wrap must be deterministic")
}

// TestSealDEK_SlotBinding, farklı slot'ların farklı wrap ürettiğini doğrular
// (info = "wapps-wrap-v1"‖slot).
func TestSealDEK_SlotBinding(t *testing.T) {
	_, rec := fixedRecipientIdentity(t)
	dek := fixedDEK()
	base, err := SealDEK(dek, rec, testSlot)
	require.NoError(t, err)

	cases := []Slot{
		{Project: "vaulter2", KeyName: "DATABASE_URL", KeyVersion: 3},
		{Project: "vaulter", KeyName: "OTHER_KEY", KeyVersion: 3},
		{Project: "vaulter", KeyName: "DATABASE_URL", KeyVersion: 4},
	}
	for _, c := range cases {
		other, err := SealDEK(dek, rec, c)
		require.NoError(t, err)
		assert.NotEqual(t, base, other, "slot %+v must change wrap", c)
		// Ama her ikisi de aynı DEK'e çözülmeli.
		id, _ := fixedRecipientIdentity(t)
		d, err := UnsealDEK(other, id)
		require.NoError(t, err)
		assert.Equal(t, dek, d)
	}
}

// TestWrapVerify_PassAndTamper, WrapVerify öz-kontrolünün geçerli wrap'i kabul
// ettiğini ve tek bayt bozulmasını ErrWrapSelfcheckFailed ile reddettiğini
// doğrular (SPEC §3.5.5 zorunlu öz-kontrol).
func TestWrapVerify_PassAndTamper(t *testing.T) {
	_, rec := fixedRecipientIdentity(t)
	dek := fixedDEK()
	wrap, err := SealDEK(dek, rec, testSlot)
	require.NoError(t, err)

	require.NoError(t, WrapVerify(dek, rec, testSlot, wrap))

	// Her bayt konumunu tek tek boz — hepsi reddedilmeli.
	for i := 0; i < len(wrap); i++ {
		tampered := bytes.Clone(wrap)
		tampered[i] ^= 0x01
		err := WrapVerify(dek, rec, testSlot, tampered)
		assert.ErrorIs(t, err, ErrWrapSelfcheckFailed, "flipped byte %d must fail selfcheck", i)
	}
}

// TestWrapSelfCheck, kendi kimlik için tam öz-kontrolün (byte-compare +
// round-trip decrypt) geçtiğini doğrular.
func TestWrapSelfCheck(t *testing.T) {
	id, rec := fixedRecipientIdentity(t)
	dek := fixedDEK()
	wrap, err := SealDEK(dek, rec, testSlot)
	require.NoError(t, err)
	require.NoError(t, WrapSelfCheck(dek, rec, testSlot, wrap, id))
}

// TestUnsealDEK_WrongIdentity, yanlış kimliğin DEK'i çözemediğini doğrular.
func TestUnsealDEK_WrongIdentity(t *testing.T) {
	_, rec := fixedRecipientIdentity(t)
	wrap, err := SealDEK(fixedDEK(), rec, testSlot)
	require.NoError(t, err)

	other, err := GenerateX25519Identity()
	require.NoError(t, err)
	_, err = UnsealDEK(wrap, other)
	assert.Error(t, err)
}

// TestSealDEK_RandomRoundtrip, rastgele DEK + rastgele kimliklerle wrap/unwrap
// döngüsünü ve age.Decrypt uyumluluğunu doğrular.
func TestSealDEK_RandomRoundtrip(t *testing.T) {
	for i := 0; i < 20; i++ {
		id, err := GenerateX25519Identity()
		require.NoError(t, err)
		rec := id.Recipient()
		dek, err := NewDEK()
		require.NoError(t, err)
		slot := Slot{Project: "proj", KeyName: "KEY_A", KeyVersion: uint64(i + 1)}

		wrap, err := SealDEK(dek, rec, slot)
		require.NoError(t, err)
		require.NoError(t, WrapVerify(dek, rec, slot, wrap))

		// Standart age ile çöz.
		r, err := age.Decrypt(bytes.NewReader(wrap), id.AgeIdentity())
		require.NoError(t, err)
		out := make([]byte, 0, 32)
		buf := make([]byte, 64)
		for {
			n, rerr := r.Read(buf)
			out = append(out, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		assert.Equal(t, dek[:], out)
	}
}
