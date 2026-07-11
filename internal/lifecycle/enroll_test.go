package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/registry"
)

// TestEnroll_HumanFingerprintsBothAndBackupOnce, insan enroll'ünün HER İKİ anahtar
// ailesini fingerprint'lediğini (§8.1.1) ve backup gizlisinin YALNIZCA BİR KEZ
// alınabildiğini (§8.3) kanıtlar.
func TestEnroll_HumanFingerprintsBothAndBackupOnce(t *testing.T) {
	e := New(Config{Now: fixedNow})
	res, err := e.Enroll(EnrollRequest{
		IdentityID:   "human:alice@example.com",
		Type:         registry.TypeHuman,
		DeviceName:   "alice-mbp",
		IsAdmin:      true,
		AddedAtEpoch: 1,
	})
	require.NoError(t, err)

	// Kimlik: device+backup enc + admin+daily signing.
	assert.Equal(t, registry.TypeHuman, res.Identity.Type)
	assert.Len(t, res.Identity.EncKeys, 2)
	assert.Len(t, res.Identity.SigningKeys, 2)

	// Enrollment kaydı HER İKİ aileyi fingerprint'ler (§4.9 step 2).
	assert.Len(t, res.Enrollment.EncFingerprints, 2, "enc: device + backup")
	assert.Len(t, res.Enrollment.SigningFingerprints, 2, "signing: admin + daily")
	assert.ElementsMatch(t, res.EncFingerprints, res.Enrollment.EncFingerprints)
	assert.ElementsMatch(t, res.SigningFingerprints, res.Enrollment.SigningFingerprints)

	// Admin + daily anahtarları üretildi.
	require.NotNil(t, res.Admin)
	require.NotNil(t, res.Daily)

	// Backup gizlisi BİR KEZ (§8.3): ilk çağrı dolu, ikincisi boş.
	require.NotNil(t, res.Backup)
	secret := res.Backup.SecretOnce()
	assert.Contains(t, secret, "AGE-SECRET-KEY-1")
	assert.Empty(t, res.Backup.SecretOnce(), "backup secret must be retrievable only once")

	// Backup public'i wrap-set için erişilebilir kalır.
	assert.NotNil(t, res.Backup.Recipient())
}

// TestEnroll_MachineHasRotateBy, makine enroll'ünün ZORUNLU rotate_by (90g) +
// automation anahtarı taşıdığını ve backup üretmediğini kanıtlar (§8.4).
func TestEnroll_MachineHasRotateBy(t *testing.T) {
	e := New(Config{Now: fixedNow})
	res, err := e.Enroll(EnrollRequest{
		IdentityID:   "machine:tofu-sync-vaulter",
		Type:         registry.TypeMachine,
		AddedAtEpoch: 1,
	})
	require.NoError(t, err)

	require.NotNil(t, res.Identity.RotateBy, "machine must set rotate_by")
	assert.Equal(t, fixTime.Add(machineRotateWindow), *res.Identity.RotateBy)
	assert.Nil(t, res.Backup, "machines have no backup identity")
	require.Len(t, res.Identity.SigningKeys, 1)
	assert.Equal(t, registry.SignClassAutomation, res.Identity.SigningKeys[0].Class)
	// Enrollment yine de HER İKİ aileyi (enc + automation) fingerprint'ler.
	assert.Len(t, res.Enrollment.EncFingerprints, 1)
	assert.Len(t, res.Enrollment.SigningFingerprints, 1)
}

// TestEnroll_SoftwareKeygenClass, varsayılan yazılım keygen'in anahtarları
// "software" medyasıyla işaretlediğini doğrular (§8.1.1 software fallback).
func TestEnroll_SoftwareKeygenClass(t *testing.T) {
	e := New(Config{Now: fixedNow})
	res, err := e.Enroll(EnrollRequest{IdentityID: "human:bob@example.com", Type: registry.TypeHuman})
	require.NoError(t, err)
	for _, ek := range res.Identity.EncKeys {
		if ek.Class == registry.EncClassDevice {
			assert.Equal(t, "software", ek.Media)
		}
	}
}
