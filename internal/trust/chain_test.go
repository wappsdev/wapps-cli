package trust

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// genesis3of, tek insanın (holder) tuttuğu 3 kök + 2-of-3 quorum ile bir genesis
// kurar ve doğrulanmış epoch + pin döner. rootKeys sonraki epoch'ları imzalamak
// için döndürülür.
func genesis3of(t *testing.T, holder string, admins ...adminHuman) (roots []*cryptoid.Ed25519SigningKey, obj cryptoid.SignedObject, pin Pin, m *TrustManifest) {
	t.Helper()
	r0, r1, r2 := edFromSeed(t, 0x10), edFromSeed(t, 0x11), edFromSeed(t, 0x12)
	roots = []*cryptoid.Ed25519SigningKey{r0, r1, r2}
	m = rosterManifest(1, "", ChangeRoster, 2, holdingsOf(holder, r0, r1, r2), admins)
	obj, pin = signRoots(t, m, r0, r1) // 2-of-3
	return roots, obj, pin, m
}

// TestVerifyGenesis, genesis kabul + pin/imza/prev/class red yollarını test eder.
func TestVerifyGenesis(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, obj, pin, gm := genesis3of(t, a.id, a)

	// Kabul.
	ep, err := VerifyGenesis(pin, obj)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), ep.Manifest.AdminEpoch)
	assert.True(t, ep.Manifest.BootstrapSolo)

	// Yanlış pin → chain broken.
	_, err = VerifyGenesis(Pin{AdminEpoch: 1, SHA256: "deadbeef"}, obj)
	assert.ErrorIs(t, err, ErrTrustChainBroken)

	// Pin yok → pin missing.
	_, err = VerifyGenesis(Pin{}, obj)
	assert.ErrorIs(t, err, ErrTrustPinMissing)

	// Yetersiz imza (1-of-3) → quorum unmet.
	obj1, pin1 := signRoots(t, gm, roots[0])
	_, err = VerifyGenesis(pin1, obj1)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)

	// prev boş değil → chain broken.
	bad := rosterManifest(1, "abc", ChangeRoster, 2, holdingsOf(a.id, roots[0], roots[1], roots[2]), []adminHuman{a})
	objBad, pinBad := signRoots(t, bad, roots[0], roots[1])
	_, err = VerifyGenesis(pinBad, objBad)
	assert.ErrorIs(t, err, ErrTrustChainBroken)

	// change_class roster değil → chain broken.
	bad2 := rosterManifest(1, "", ChangeRegistry, 2, holdingsOf(a.id, roots[0], roots[1], roots[2]), []adminHuman{a})
	objBad2, pinBad2 := signRoots(t, bad2, roots[0], roots[1])
	_, err = VerifyGenesis(pinBad2, objBad2)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestRosterChain_Accept, genesis + bir roster epoch'unun kabulünü test eder.
func TestRosterChain_Accept(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	// E2: roster no-op benzeri (aynı kökler, media güncellemesi). 2-of-3 imza.
	e2 := childOf(gm, gObj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	e2.Roots[0].Media = "yubikey-piv-rotated"
	e2Obj, _ := signRoots(t, e2, roots[0], roots[1])

	head, err := VerifyRosterChain(gPin, gPin, gObj, e2Obj)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), head.Manifest.AdminEpoch)
}

// TestRosterChain_InsufficientSigs, E2 tek kökle imzalanırsa reddedilir.
func TestRosterChain_InsufficientSigs(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	obj1, _ := signRoots(t, e2, roots[0]) // 1-of-3
	_, err := VerifyRosterChain(gPin, gPin, gObj, obj1)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestRosterChain_WrongRoot, E1'de OLMAYAN bir kökle imzalanan E2 reddedilir.
func TestRosterChain_WrongRoot(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	foreign := edFromSeed(t, 0x99)
	e2 := childOf(gm, gObj)
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	// 1 gerçek kök + 1 yabancı kök: yabancı sayılmaz → 1 < 2.
	obj, _ := signRoots(t, e2, roots[0], foreign)
	_, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestRosterChain_BrokenLink, prev hash genesis'e bağlanmazsa reddedilir.
func TestRosterChain_BrokenLink(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.PrevTrustSHA256 = "00" + e2.PrevTrustSHA256[2:] // linki boz
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	obj, _ := signRoots(t, e2, roots[0], roots[1])
	_, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestRosterChain_EpochGap, admin_epoch parent+1 değilse reddedilir.
func TestRosterChain_EpochGap(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.AdminEpoch = 3 // boşluk
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	obj, _ := signRoots(t, e2, roots[0], roots[1])
	_, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestRosterChain_Downgrade, sunulan head last-verified pin'in altındaysa
// hard-fail eder; ayrıca pin-fork (aynı epoch, farklı hash) da downgrade'dir.
func TestRosterChain_Downgrade(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	e2.Roots[0].Media = "rotated"
	e2Obj, e2Pin := signRoots(t, e2, roots[0], roots[1])

	// Önce E2'ye kadar doğrula (pin ilerlemiş varsayalım).
	_, err := VerifyRosterChain(gPin, gPin, gObj, e2Obj)
	require.NoError(t, err)

	// Şimdi last-verified E2 iken YALNIZCA genesis sun → head(1) < pin(2) → downgrade.
	_, err = VerifyRosterChain(gPin, e2Pin, gObj)
	assert.ErrorIs(t, err, ErrTrustDowngrade)

	// Pin-fork: E2 pin'i doğru epoch ama FARKLI hash → geçiş sırasında fork.
	forkPin := Pin{AdminEpoch: 2, SHA256: "ff" + e2Pin.SHA256[2:]}
	_, err = VerifyRosterChain(gPin, forkPin, gObj, e2Obj)
	assert.ErrorIs(t, err, ErrTrustDowngrade)
}

// TestRosterChain_TamperSig, bir imza baytı bozulursa quorum unmet olur.
func TestRosterChain_TamperSig(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	obj, _ := signRoots(t, e2, roots[0], roots[1])

	// Her iki imzayı da boz → hiçbir geçerli imza kalmaz.
	tampered := cryptoid.SignedObject{Bytes: obj.Bytes, Sigs: make([]cryptoid.Signature, len(obj.Sigs))}
	for i, s := range obj.Sigs {
		ns := s
		ns.Sig = bytes.Clone(s.Sig)
		ns.Sig[0] ^= 0x01
		tampered.Sigs[i] = ns
	}
	_, err := VerifyRosterChain(gPin, gPin, gObj, tampered)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestRosterChain_TamperPayload, imzalı payload'ın tek baytı bozulursa
// (JSON'u bozmayan bir string değeri) doğrulama başarısız olur.
func TestRosterChain_TamperPayload(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	e2.Roots[0].Media = "yubikey-piv"
	obj, _ := signRoots(t, e2, roots[0], roots[1])

	// "yubikey-piv" string'inin bir baytını değiştir (JSON geçerli kalır ama
	// baytlar imzadan farklılaşır).
	idx := bytes.Index(obj.Bytes, []byte("yubikey-piv"))
	require.GreaterOrEqual(t, idx, 0)
	tamperedBytes := bytes.Clone(obj.Bytes)
	tamperedBytes[idx] = 'Y'
	tampered := cryptoid.SignedObject{Bytes: tamperedBytes, Sigs: obj.Sigs}
	_, err := VerifyRosterChain(gPin, gPin, gObj, tampered)
	require.Error(t, err) // imzalar artık geçmez → quorum unmet
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestRosterChain_SemanticInvariant, roster OLMAYAN bir epoch kökleri
// değiştirirse reddedilir (SPEC §4.5 step 5).
func TestRosterChain_SemanticInvariant(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	// registry-class epoch, ama kökleri değiştiriyor → chain broken.
	e2 := childOf(gm, gObj)
	e2.ChangeClass = ChangeRegistry
	newRoots := append([]RootKey(nil), gm.Roots...)
	newRoots[0].Media = "tampered-in-registry-epoch"
	e2.Roots = newRoots
	// registry epoch'u admin imzasıyla imzalanır.
	obj := signAdmins(t, e2, a.admin)
	_, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
	_ = roots
}

// TestRegistryEpoch_Accept, registry-class bir epoch'un (kimlik ekleme) 1 admin
// imzasıyla kabul edildiğini test eder.
func TestRegistryEpoch_Accept(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, gm := genesis3of(t, a.id, a)

	b := newAdminHuman(t, "bob@wapps.dev")
	e2 := childOf(gm, gObj)
	e2.ChangeClass = ChangeRegistry
	// Yeni bir makine kimliği ekle (roster/admin dokunulmaz).
	e2.Identities = append(append([]registry.Identity(nil), gm.Identities...), b.identity())
	obj := signAdmins(t, e2, a.admin) // 1 admin
	head, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	require.NoError(t, err)
	assert.Len(t, head.Manifest.Identities, 2)

	// Aynı registry epoch'u YALNIZCA daily anahtarıyla imzalanırsa reddedilir
	// (daily bir trust epoch'unda asla geçerli değil).
	objDaily := signAdmins(t, e2, a.daily)
	_, err = VerifyRosterChain(gPin, gPin, gObj, objDaily)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestRosterEpoch_AdminKeyRejected, bir roster epoch'u admin (P-256) anahtarıyla
// imzalanırsa reddedilir — roster yalnızca KÖK anahtar kabul eder.
func TestRosterEpoch_AdminKeyRejected(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	e2.Roots[0].Media = "rotated"
	obj := signAdmins(t, e2, a.admin) // admin anahtarı, kök değil
	_, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestVerifyRosterChain_EmptyAndNoPin, dejenere girdileri test eder.
func TestVerifyRosterChain_EmptyAndNoPin(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, _ := genesis3of(t, a.id, a)

	_, err := VerifyRosterChain(gPin, gPin)
	assert.ErrorIs(t, err, ErrTrustChainBroken)

	_, err = VerifyRosterChain(Pin{}, gPin, gObj)
	assert.ErrorIs(t, err, ErrTrustPinMissing)
}
