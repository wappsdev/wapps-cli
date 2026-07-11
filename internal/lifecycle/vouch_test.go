package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// vouchFixture, bir vouch senaryosunun dünyasıdır.
type vouchFixture struct {
	engine *Engine
	admin  tHuman
	head   *trust.VerifiedEpoch
	cand   *EnrollResult
}

func vouchWorld(t *testing.T) *vouchFixture {
	t.Helper()
	e := New(Config{Now: fixedNow, Classifier: prodClassifier})

	admin := newTHuman(t, "adnan@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)

	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{admin.identity(), esc.id},
		adminIDs:   []string{admin.id},
		grants:     []registry.Grant{readWriteGrant(admin.id, "vaulter")},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{admin.id, admin.id, admin.id}, // solo: A holds all 3
		m:          2,
		solo:       true,
	})

	cand, err := e.Enroll(EnrollRequest{IdentityID: "human:eve@wapps.dev", Type: registry.TypeHuman, AddedAtEpoch: 2})
	require.NoError(t, err)

	return &vouchFixture{engine: e, admin: admin, head: head, cand: cand}
}

// TestVouch_AcceptWithFingerprintCeremony, ikinci-kanal parmak izleri eşleşen +
// ceremony onaylı bir vouch'un doğrulanmış bir registry epoch ürettiğini kanıtlar
// (§8.1.3). Kimlik yeni head'de görünür.
func TestVouch_AcceptWithFingerprintCeremony(t *testing.T) {
	f := vouchWorld(t)
	obj, next, err := f.engine.Vouch(VouchRequest{
		Parent:               f.head,
		Enrollment:           f.cand.Enrollment,
		Identity:             f.cand.Identity,
		SecondChannelEnc:     f.cand.EncFingerprints, // ikinci kanaldan TAM eşleşme
		SecondChannelSigning: f.cand.SigningFingerprints,
		CeremonyConfirmed:    true,
		VouchedBy:            []string{f.admin.id},
		Signers:              []cryptoid.SigningKey{f.admin.admin}, // 1 admin (registry tier)
	})
	require.NoError(t, err)
	require.NotNil(t, next)
	assert.Equal(t, uint64(2), next.Manifest.AdminEpoch)
	assert.Equal(t, trust.ChangeRegistry, next.Manifest.ChangeClass)

	// Kimlik kayda girdi + vouched_by dolu.
	id, ok := next.Manifest.Registry().IdentityByID("human:eve@wapps.dev")
	require.True(t, ok, "vouched identity must be in the registry")
	assert.Equal(t, []string{f.admin.id}, id.VouchedBy)

	// vouch'lu kimliğin SIFIR erişimi var (henüz grant yok, §8.1.3).
	assert.False(t, next.Manifest.Registry().VerbAllowed("human:eve@wapps.dev", "vaulter", "read"))

	// Epoch, obj olarak da doğrulanabilir olmalı (roster zinciri).
	require.NotEmpty(t, obj.Sigs)
}

// TestVouch_RejectMismatchedFingerprints, ikinci-kanal parmak izleri kayıtla
// eşleşmezse vouch'un reddedildiğini kanıtlar (§8.1.2 — Worker/R2 substitution
// savunması).
func TestVouch_RejectMismatchedFingerprints(t *testing.T) {
	f := vouchWorld(t)
	_, _, err := f.engine.Vouch(VouchRequest{
		Parent:               f.head,
		Enrollment:           f.cand.Enrollment,
		Identity:             f.cand.Identity,
		SecondChannelEnc:     []string{"sha256:deadbeef"}, // yanlış
		SecondChannelSigning: f.cand.SigningFingerprints,
		CeremonyConfirmed:    true,
		VouchedBy:            []string{f.admin.id},
		Signers:              []cryptoid.SigningKey{f.admin.admin},
	})
	require.ErrorIs(t, err, ErrFingerprintMismatch)
}

// TestVouch_RejectWithoutCeremony, ceremony onay bayrağı set edilmeden yapılan bir
// vouch'un geçersiz olduğunu kanıtlar (§8.1.2).
func TestVouch_RejectWithoutCeremony(t *testing.T) {
	f := vouchWorld(t)
	_, _, err := f.engine.Vouch(VouchRequest{
		Parent:               f.head,
		Enrollment:           f.cand.Enrollment,
		Identity:             f.cand.Identity,
		SecondChannelEnc:     f.cand.EncFingerprints,
		SecondChannelSigning: f.cand.SigningFingerprints,
		CeremonyConfirmed:    false, // onaysız
		VouchedBy:            []string{f.admin.id},
		Signers:              []cryptoid.SigningKey{f.admin.admin},
	})
	require.ErrorIs(t, err, ErrCeremonyNotConfirmed)
}

// TestVouch_RejectDailyKeySigner, bir vouch daily (admin olmayan) anahtarla
// imzalanırsa trust katmanı tarafından reddedilir (registry epoch admin gerektirir).
func TestVouch_RejectDailyKeySigner(t *testing.T) {
	f := vouchWorld(t)
	_, _, err := f.engine.Vouch(VouchRequest{
		Parent:               f.head,
		Enrollment:           f.cand.Enrollment,
		Identity:             f.cand.Identity,
		SecondChannelEnc:     f.cand.EncFingerprints,
		SecondChannelSigning: f.cand.SigningFingerprints,
		CeremonyConfirmed:    true,
		VouchedBy:            []string{f.admin.id},
		Signers:              []cryptoid.SigningKey{f.admin.daily}, // daily → geçersiz
	})
	require.ErrorIs(t, err, trust.ErrTrustQuorumUnmet)
}
