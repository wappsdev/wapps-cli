package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// TestEnrollment_FingerprintsBoth, enrollment kaydının HER İKİ anahtar ailesinin
// (enc + signing) §3.7 parmak izini taşıdığını ve bunların cryptoid'in ürettiği
// parmak izleriyle eşleştiğini doğrular (SPEC §4.9 step 2).
func TestEnrollment_FingerprintsBoth(t *testing.T) {
	human, adminKey := humanIdentity(t, "adnan@wapps.dev")

	rec, err := NewEnrollmentRecord(human, testTime)
	require.NoError(t, err)
	assert.Equal(t, SchemaEnrollment, rec.Schema)
	assert.Equal(t, human.ID, rec.IdentityID)

	// İki enc parmak izi (device + backup), iki signing parmak izi (admin + daily).
	require.Len(t, rec.EncFingerprints, 2)
	require.Len(t, rec.SigningFingerprints, 2)

	// Signing parmak izi cryptoid.Fingerprint ile bağımsız olarak eşleşmeli.
	adminFP := cryptoid.Fingerprint(adminKey.PublicKeyBytes())
	assert.Contains(t, rec.SigningFingerprints, adminFP)

	// Enc parmak izi recipient string üzerinden hesaplanmalı.
	deviceFP := cryptoid.FingerprintRecipient(human.EncKeys[0].Pubkey)
	assert.Contains(t, rec.EncFingerprints, deviceFP)
}

// TestEnrollment_MatchesFingerprints, ikinci-kanal parmak izi eşleşmesini
// (tam, sıra-bağımsız) test eder.
func TestEnrollment_MatchesFingerprints(t *testing.T) {
	human, _ := humanIdentity(t, "adnan@wapps.dev")
	rec, err := NewEnrollmentRecord(human, testTime)
	require.NoError(t, err)

	// Aynı küme, ters sıra → eşleşir.
	enc := []string{rec.EncFingerprints[1], rec.EncFingerprints[0]}
	sig := []string{rec.SigningFingerprints[1], rec.SigningFingerprints[0]}
	assert.True(t, rec.MatchesFingerprints(enc, sig))

	// Bir parmak izi değiştirilirse → eşleşmez (tam digest kontrolü).
	badEnc := append([]string(nil), rec.EncFingerprints...)
	badEnc[0] = "sha256:tampered"
	assert.False(t, rec.MatchesFingerprints(badEnc, rec.SigningFingerprints))

	// Eksik parmak izi → eşleşmez.
	assert.False(t, rec.MatchesFingerprints(rec.EncFingerprints[:1], rec.SigningFingerprints))
}

// TestEnrollment_Escrow, escrow kimliğinin yalnızca enc parmak izi taşıdığını
// (imzalama anahtarı yok) test eder.
func TestEnrollment_Escrow(t *testing.T) {
	e := escrowIdentity(t)
	rec, err := NewEnrollmentRecord(e, testTime)
	require.NoError(t, err)
	assert.Len(t, rec.EncFingerprints, 1)
	assert.Empty(t, rec.SigningFingerprints)
}

// TestEnrollment_KeyIDMismatch, bir anahtarın key_id'si pubkey'iyle tutarsızsa
// enrollment kaydı üretimi reddedilir.
func TestEnrollment_KeyIDMismatch(t *testing.T) {
	human, _ := humanIdentity(t, "adnan@wapps.dev")
	human.SigningKeys[0].KeyID = "sha256:tampered"
	_, err := NewEnrollmentRecord(human, testTime)
	assert.ErrorIs(t, err, ErrKeyIDMismatch)
}

// TestEnrollment_MachineNeedsSigning, imzalama anahtarı olmayan bir makine
// (non-escrow) enrollment'ı reddedilir.
func TestEnrollment_MachineNeedsSigning(t *testing.T) {
	m := machineIdentity(t, "reader-only")
	m.SigningKeys = nil // yazmayan makine bile enrollment'ta imzalama fp gerektirir? Hayır:
	// non-escrow ve imzalama anahtarı YOKSA reddedilir (kayıt en az bir signing fp ister).
	_, err := NewEnrollmentRecord(m, testTime)
	assert.ErrorIs(t, err, ErrRegistryInvalid)
}
