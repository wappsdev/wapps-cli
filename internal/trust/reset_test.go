package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// buildResetPrior, reset senaryoları için son doğrulanmış PRE-RESET manifest'i
// (roster) + payload hash'i + kök anahtarları döner.
func buildResetPrior(t *testing.T, priorEpoch uint64) (prior *TrustManifest, priorSHA string, roots []*cryptoid.Ed25519SigningKey) {
	t.Helper()
	a := newAdminHuman(t, "adnan@wapps.dev")
	r0, r1, r2 := edFromSeed(t, 0x80), edFromSeed(t, 0x81), edFromSeed(t, 0x82)
	roots = []*cryptoid.Ed25519SigningKey{r0, r1, r2}
	prior = rosterManifest(priorEpoch, "prev", ChangeRoster, 2, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	obj, _, err := SignTrustManifest(prior, r0, r1)
	require.NoError(t, err)
	priorSHA = TrustObjectHash(obj.Bytes)
	return prior, priorSHA, roots
}

// resetManifest, prior'ı zincirleyen bir epoch-reset manifest'i kurar.
func resetManifest(t *testing.T, prior *TrustManifest, priorSHA string, resetEpoch uint64, prevLink string, roots []*cryptoid.Ed25519SigningKey) *TrustManifest {
	t.Helper()
	m := rosterManifest(resetEpoch, prevLink, ChangeEpochReset, 2, holdingsOf(prior.Admins[0], roots[0], roots[1], roots[2]), []adminHuman{})
	// Reset roster'ında admin kimliğini koru (roster geçerliliği için gerekmez;
	// buildSignerView admin gerektirmez).
	m.Identities = prior.Identities
	m.Admins = prior.Admins
	m.EpochReset = &EpochReset{
		Schema:      SchemaTrustReset,
		ResetID:     "0192-reset",
		Reason:      "escrow_restore",
		PriorChain:  PriorChain{LastAdminEpoch: prior.AdminEpoch, LastTrustSHA256: priorSHA},
		SnapshotRef: "snap-1",
	}
	return m
}

// TestEpochReset_HeadAvailable_Accept, prior head mevcutken geçerli bir reset'in
// ≥M kök imzasıyla kabulünü test eder (SPEC §4.8).
func TestEpochReset_HeadAvailable_Accept(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	m := resetManifest(t, prior, priorSHA, 42, priorSHA, roots)
	obj, _, err := SignTrustManifest(m, roots[0], roots[1])
	require.NoError(t, err)

	ep, err := VerifyEpochReset(obj, prior, priorSHA, Pin{AdminEpoch: 41}, 41, true)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), ep.Manifest.AdminEpoch)
	assert.Equal(t, "escrow_restore", ep.Manifest.EpochReset.Reason)
}

// TestEpochReset_InsufficientSigs, reset ≥M kök taşımazsa reddedilir.
func TestEpochReset_InsufficientSigs(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	m := resetManifest(t, prior, priorSHA, 42, priorSHA, roots)
	obj, _, err := SignTrustManifest(m, roots[0]) // 1-of-3
	require.NoError(t, err)

	_, err = VerifyEpochReset(obj, prior, priorSHA, Pin{AdminEpoch: 41}, 41, true)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestEpochReset_DowngradeGuard, istemcinin pin'i reset'in prior sınırından
// YENİYSE reddedilir — reset bir rollback'i aklayamaz (SPEC §4.8).
func TestEpochReset_DowngradeGuard(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	m := resetManifest(t, prior, priorSHA, 42, priorSHA, roots)
	obj, _, err := SignTrustManifest(m, roots[0], roots[1])
	require.NoError(t, err)

	// Pin epoch 45 > prior 41 → downgrade.
	_, err = VerifyEpochReset(obj, prior, priorSHA, Pin{AdminEpoch: 45}, 41, true)
	assert.ErrorIs(t, err, ErrTrustDowngrade)
}

// TestEpochReset_WitnessBound, reset epoch'u tanık sınırından KATİ büyük değilse
// reddedilir (SPEC §4.8).
func TestEpochReset_WitnessBound(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	m := resetManifest(t, prior, priorSHA, 42, priorSHA, roots)
	obj, _, err := SignTrustManifest(m, roots[0], roots[1])
	require.NoError(t, err)

	// witnessBound 42 ≥ reset 42 → reddedilir.
	_, err = VerifyEpochReset(obj, prior, priorSHA, Pin{AdminEpoch: 41}, 42, true)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestEpochReset_NotGreaterThanPrior, reset epoch'u prior'dan büyük değilse
// reddedilir.
func TestEpochReset_NotGreaterThanPrior(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	// reset epoch 41 == prior 41 → reddedilir.
	m := resetManifest(t, prior, priorSHA, 41, priorSHA, roots)
	obj, _, err := SignTrustManifest(m, roots[0], roots[1])
	require.NoError(t, err)

	_, err = VerifyEpochReset(obj, prior, priorSHA, Pin{}, 0, true)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestEpochReset_PrevLinkMismatch, head mevcutken yanlış prev_trust_sha256
// reddedilir.
func TestEpochReset_PrevLinkMismatch(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	m := resetManifest(t, prior, priorSHA, 42, "deadbeef", roots) // yanlış prev link
	obj, _, err := SignTrustManifest(m, roots[0], roots[1])
	require.NoError(t, err)

	_, err = VerifyEpochReset(obj, prior, priorSHA, Pin{}, 0, true)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestEpochReset_LostHead, escrow-restore (prior head kayıp) yolunda prev BOŞ
// olmalıdır: boş kabul, dolu red.
func TestEpochReset_LostHead(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)

	// Kayıp head: prev = "" → kabul.
	mOK := resetManifest(t, prior, priorSHA, 42, "", roots)
	objOK, _, err := SignTrustManifest(mOK, roots[0], roots[1])
	require.NoError(t, err)
	ep, err := VerifyEpochReset(objOK, prior, priorSHA, Pin{}, 0, false)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), ep.Manifest.AdminEpoch)

	// Kayıp head yolunda prev DOLU → red.
	mBad := resetManifest(t, prior, priorSHA, 42, priorSHA, roots)
	objBad, _, err := SignTrustManifest(mBad, roots[0], roots[1])
	require.NoError(t, err)
	_, err = VerifyEpochReset(objBad, prior, priorSHA, Pin{}, 0, false)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestEpochReset_WrongChangeClass, epoch_reset olmayan bir manifest'i reset
// olarak doğrulamak reddedilir.
func TestEpochReset_WrongChangeClass(t *testing.T) {
	prior, priorSHA, roots := buildResetPrior(t, 41)
	m := resetManifest(t, prior, priorSHA, 42, priorSHA, roots)
	m.ChangeClass = ChangeRoster // reset değil
	obj, _, err := SignTrustManifest(m, roots[0], roots[1])
	require.NoError(t, err)
	_, err = VerifyEpochReset(obj, prior, priorSHA, Pin{}, 0, true)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestEpochReset_InChainWalk_RollbackLaundering, zincir-içi bir reset'in bir
// rollback'i AKLAYAMADIĞINI kanıtlar (SPEC §4.8 downgrade guard). Bir saldırgan
// GEÇMİŞ bir epoch'un (E5) ≥M kök imzasını tutuyor: genesis..E5'i, sonra
// reset(prior=5, epoch=100)'ü sunar. İstemci daha önce epoch 7'yi doğrulamıştır
// (pinnedLast={7}). Reset'in prior sınırı (5), istemcinin pin'inden (7) ESKİ
// olduğu için HARD FAIL TRUST_DOWNGRADE olmalıdır — reset yolu artık istemcinin
// GERÇEK pin'ini görür (eskiden Pin{} ile sıfırlanıyordu = güvenlik açığı).
func TestEpochReset_InChainWalk_RollbackLaundering(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	// genesis(1) → E2 → E3 → E4 → E5: no-op roster epoch'ları; her biri bir
	// öncekinin 2-of-3 köküyle imzalanır. parent E5'te (epoch 5) durur.
	chain := []cryptoid.SignedObject{gObj}
	parent, parentObj := gm, gObj
	for e := uint64(2); e <= 5; e++ {
		ep := childOf(parent, parentObj)
		ep.ChangeClass = ChangeRoster
		ep.Roots = append([]RootKey(nil), gm.Roots...)
		epObj, _ := signRoots(t, ep, roots[0], roots[1])
		chain = append(chain, epObj)
		parent, parentObj = ep, epObj
	}

	// reset: prior=E5(5), admin_epoch=100'e sıçrar; E5'in (genesis) kökleriyle imzalı.
	reset := childOf(parent, parentObj)
	reset.AdminEpoch = 100
	reset.ChangeClass = ChangeEpochReset
	reset.Roots = append([]RootKey(nil), gm.Roots...)
	reset.EpochReset = &EpochReset{
		Schema:     SchemaTrustReset,
		ResetID:    "0192-rollback",
		Reason:     "quorum_recovery",
		PriorChain: PriorChain{LastAdminEpoch: 5, LastTrustSHA256: TrustObjectHash(parentObj.Bytes)},
	}
	resetObj, _ := signRoots(t, reset, roots[0], roots[1])
	chain = append(chain, resetObj)

	// İstemci epoch 7'yi görmüş (pinnedLast=7). reset prior=5 < 7 → downgrade.
	pinnedLast := Pin{AdminEpoch: 7, SHA256: "ab" + gPin.SHA256[2:]}
	_, err := VerifyRosterChain(gPin, pinnedLast, chain...)
	assert.ErrorIs(t, err, ErrTrustDowngrade)
}

// TestEpochReset_InChainWalk, VerifyRosterChain'in sonda bir reset epoch'unu
// (head mevcut yol) yürütebildiğini test eder.
func TestEpochReset_InChainWalk(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	// E2: epoch-reset, genesis'i zincirler, admin_epoch 5'e sıçrar.
	reset := childOf(gm, gObj)
	reset.AdminEpoch = 5
	reset.ChangeClass = ChangeEpochReset
	reset.Roots = append([]RootKey(nil), gm.Roots...)
	reset.EpochReset = &EpochReset{
		Schema:     SchemaTrustReset,
		ResetID:    "0192-walk",
		Reason:     "quorum_recovery",
		PriorChain: PriorChain{LastAdminEpoch: 1, LastTrustSHA256: gPin.SHA256},
	}
	obj, _ := signRoots(t, reset, roots[0], roots[1])

	head, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), head.Manifest.AdminEpoch)
}
