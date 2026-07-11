package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// TestTransition_SoloToMultiAdmin, N=1→N≥3 geçişinin TAM zincirini kanıtlar
// (SPEC §4.7): solo(N_h=1) → solo(N_h=2, A hâlâ ≥M tutar) → de-solo(N_h=3).
// Her roster epoch'u BİR ÖNCEKİ epoch'un ≥M köküyle imzalanır.
func TestTransition_SoloToMultiAdmin(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	b := newAdminHuman(t, "bob@wapps.dev")
	c := newAdminHuman(t, "carol@wapps.dev")

	// Kök anahtarlar: A başlangıçta 3'ünü de tutar.
	ra0, ra1, ra2 := edFromSeed(t, 0x20), edFromSeed(t, 0x21), edFromSeed(t, 0x22)
	rb := edFromSeed(t, 0x23)
	rc := edFromSeed(t, 0x24)

	// E1 genesis: 3 kök tek insanda (A), 2-of-3, solo=true, N_h=1.
	e1 := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, ra0, ra1, ra2), []adminHuman{a})
	e1Obj, gPin := signRoots(t, e1, ra0, ra1)
	require.True(t, e1.BootstrapSolo)

	// E2 roster: B'nin kökünü ekle → roots [A,A,A,B] (2-of-4). A hâlâ 3≥2 tutar →
	// solo=true kalır; ama N_h=2 (admins=[A,B]). E1'in kökleriyle (2-of-3) imzalanır.
	e2 := childOf(e1, e1Obj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = []RootKey{
		NewRootKey(ra0, "m", a.id), NewRootKey(ra1, "m", a.id),
		NewRootKey(ra2, "m", a.id), NewRootKey(rb, "m", b.id),
	}
	e2.Quorum = Quorum{M: 2, N: 4}
	e2.BootstrapSolo = true // A hâlâ 3≥2
	e2.Admins = []string{a.id, b.id}
	e2.Identities = []registry.Identity{a.identity(), b.identity()}
	e2Obj, _ := signRoots(t, e2, ra0, ra1)

	// E3 roster (de-solo): kökleri [A,B,C] tek-tek dağıt (2-of-3). Artık kimse
	// ≥2 tutmaz → solo=false ZORUNLU. E2'nin kökleriyle imzalanır.
	e3 := childOf(e2, e2Obj)
	e3.ChangeClass = ChangeRoster
	e3.Roots = []RootKey{
		NewRootKey(ra0, "m", a.id), NewRootKey(rb, "m", b.id), NewRootKey(rc, "m", c.id),
	}
	e3.Quorum = Quorum{M: 2, N: 3}
	e3.BootstrapSolo = false
	e3.Admins = []string{a.id, b.id, c.id}
	e3.Identities = []registry.Identity{a.identity(), b.identity(), c.identity()}
	e3Obj, _ := signRoots(t, e3, ra0, rb) // E2 köklerinden 2 farklı

	head, err := VerifyRosterChain(gPin, gPin, e1Obj, e2Obj, e3Obj)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), head.Manifest.AdminEpoch)
	assert.False(t, head.Manifest.BootstrapSolo)
	assert.Equal(t, 3, head.view.nAdminHumans)
}

// TestTransition_DeSoloTooEarly_Rejected, bir insan hâlâ ≥M kök tutarken
// solo=false kurmak reddedilir (SPEC §4.7 step 3).
func TestTransition_DeSoloTooEarly_Rejected(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	b := newAdminHuman(t, "bob@wapps.dev")
	ra0, ra1, ra2 := edFromSeed(t, 0x30), edFromSeed(t, 0x31), edFromSeed(t, 0x32)
	rb := edFromSeed(t, 0x33)

	e1 := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, ra0, ra1, ra2), []adminHuman{a})
	e1Obj, gPin := signRoots(t, e1, ra0, ra1)

	// E2: roots [A,A,B] (A tutar 2 ≥ m=2) ama solo=false → değişmez ihlali.
	e2 := childOf(e1, e1Obj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = []RootKey{NewRootKey(ra0, "m", a.id), NewRootKey(ra1, "m", a.id), NewRootKey(rb, "m", b.id)}
	e2.Quorum = Quorum{M: 2, N: 3}
	e2.BootstrapSolo = false // YANLIŞ: A hâlâ 2≥2 tutar
	e2.Admins = []string{a.id, b.id}
	e2.Identities = []registry.Identity{a.identity(), b.identity()}
	e2Obj, _ := signRoots(t, e2, ra0, ra1)

	_, err := VerifyRosterChain(gPin, gPin, e1Obj, e2Obj)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestTransition_SoloTooLate_Rejected, custody çok-insanlıyken (kimse ≥M
// tutmuyorken) solo=true bırakmak reddedilir.
func TestTransition_SoloTooLate_Rejected(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	b := newAdminHuman(t, "bob@wapps.dev")
	c := newAdminHuman(t, "carol@wapps.dev")
	ra0, ra1, ra2 := edFromSeed(t, 0x40), edFromSeed(t, 0x41), edFromSeed(t, 0x42)
	rb, rc := edFromSeed(t, 0x43), edFromSeed(t, 0x44)

	e1 := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, ra0, ra1, ra2), []adminHuman{a})
	e1Obj, gPin := signRoots(t, e1, ra0, ra1)

	// E2: roots [A,B,C] tek-tek (kimse ≥2 tutmaz) ama solo=true → değişmez ihlali.
	e2 := childOf(e1, e1Obj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = []RootKey{NewRootKey(ra0, "m", a.id), NewRootKey(rb, "m", b.id), NewRootKey(rc, "m", c.id)}
	e2.Quorum = Quorum{M: 2, N: 3}
	e2.BootstrapSolo = true // YANLIŞ: artık kimse ≥2 tutmuyor
	e2.Admins = []string{a.id, b.id, c.id}
	e2.Identities = []registry.Identity{a.identity(), b.identity(), c.identity()}
	e2Obj, _ := signRoots(t, e2, ra0, ra1)

	_, err := VerifyRosterChain(gPin, gPin, e1Obj, e2Obj)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestTieredGrant_SoloSingleAdmin, bootstrap_solo iken bir PROD grant epoch'u
// TEK admin imzasıyla kabul edilir (§4.6 katman solo'da tekli imzaya düşer).
func TestTieredGrant_SoloSingleAdmin(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, gm := genesis3of(t, a.id, a)

	grant := childOf(gm, gObj)
	grant.ChangeClass = ChangeGrant
	grant.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}}}
	obj := signAdmins(t, grant, a.admin) // 1 admin, solo

	classifier := func(string) ProjectClass { return ProjectProd }
	head, err := VerifyRosterChainWithClassifier(classifier, gPin, gPin, gObj, obj)
	require.NoError(t, err)
	assert.Len(t, head.Manifest.Grants, 1)
}

// TestTieredGrant_SoloTwoAdmins_NeedsTwo, §4.7 step 4'ün SIKI okumasını kanıtlar:
// (bootstrap_solo=true, N_h=2) — §4.7 geçişinde ULAŞILABİLİR bir verified durum —
// içinde bile bir PROD grant 2 FARKLI admin insan imzası gerektirir. Tek admin
// orada prod grant YETKİLENDİREMEZ (eskiden solo muafiyeti tek admine izin
// veriyordu = trust-spine için gevşek okuma).
func TestTieredGrant_SoloTwoAdmins_NeedsTwo(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	b := newAdminHuman(t, "bob@wapps.dev")
	ra0, ra1, ra2 := edFromSeed(t, 0x90), edFromSeed(t, 0x91), edFromSeed(t, 0x92)
	rb := edFromSeed(t, 0x93)

	// E1 genesis: 3 kök tek insanda (A), 2-of-3, solo=true, N_h=1.
	e1 := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, ra0, ra1, ra2), []adminHuman{a})
	e1Obj, gPin := signRoots(t, e1, ra0, ra1)

	// E2 roster: B'nin kökünü ekle → [A,A,A,B] 2-of-4. A hâlâ 3≥2 → solo=true KALIR;
	// admins=[A,B] → N_h=2. Bu §4.7 geçişinde ulaşılabilir bir durumdur.
	e2 := childOf(e1, e1Obj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = []RootKey{
		NewRootKey(ra0, "m", a.id), NewRootKey(ra1, "m", a.id),
		NewRootKey(ra2, "m", a.id), NewRootKey(rb, "m", b.id),
	}
	e2.Quorum = Quorum{M: 2, N: 4}
	e2.BootstrapSolo = true // A hâlâ 3≥2
	e2.Admins = []string{a.id, b.id}
	e2.Identities = []registry.Identity{a.identity(), b.identity()}
	e2Obj, _ := signRoots(t, e2, ra0, ra1)

	prod := func(string) ProjectClass { return ProjectProd }

	// E3 prod grant, TEK admin (A) → reddedilir (solo & N_h=2'de artık 2 gerekir).
	g := childOf(e2, e2Obj)
	g.ChangeClass = ChangeGrant
	g.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}}}
	obj1 := signAdmins(t, g, a.admin)
	_, err := VerifyRosterChainWithClassifier(prod, gPin, gPin, e1Obj, e2Obj, obj1)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)

	// Aynı grant, 2 FARKLI admin (A + B) → kabul (solo hâlâ true olsa da).
	obj2 := signAdmins(t, g, a.admin, b.admin)
	head, err := VerifyRosterChainWithClassifier(prod, gPin, gPin, e1Obj, e2Obj, obj2)
	require.NoError(t, err)
	assert.Len(t, head.Manifest.Grants, 1)
	assert.True(t, head.Manifest.BootstrapSolo)
}

// TestTieredGrant_MultiAdminNeedsTwo, de-solo (N_h≥2) sonrası PROD grant'ı 2
// FARKLI admin İNSAN imzası gerektirir (§4.5/§4.7). 1 imza reddedilir.
func TestTieredGrant_MultiAdminNeedsTwo(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	b := newAdminHuman(t, "bob@wapps.dev")
	c := newAdminHuman(t, "carol@wapps.dev")
	ra, rb, rc := edFromSeed(t, 0x50), edFromSeed(t, 0x51), edFromSeed(t, 0x52)

	// Doğrudan de-solo genesis: 3 kök 3 insanda, 2-of-3, solo=false, N_h=3.
	e1 := rosterManifest(1, "", ChangeRoster, 2, []rootHolding{
		{ra, a.id}, {rb, b.id}, {rc, c.id},
	}, []adminHuman{a, b, c})
	require.False(t, e1.BootstrapSolo)
	e1Obj, gPin := signRoots(t, e1, ra, rb)

	classifier := func(string) ProjectClass { return ProjectProd }

	// Prod grant, 1 admin → quorum unmet.
	g1 := childOf(e1, e1Obj)
	g1.ChangeClass = ChangeGrant
	g1.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}}}
	obj1 := signAdmins(t, g1, a.admin)
	_, err := VerifyRosterChainWithClassifier(classifier, gPin, gPin, e1Obj, obj1)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)

	// Prod grant, aynı insanın 2 anahtarı (admin + daily) → hâlâ 1 farklı insan,
	// daily zaten geçersiz → quorum unmet.
	obj1b := signAdmins(t, g1, a.admin, a.daily)
	_, err = VerifyRosterChainWithClassifier(classifier, gPin, gPin, e1Obj, obj1b)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)

	// Prod grant, 2 FARKLI admin (A + B) → kabul.
	obj2 := signAdmins(t, g1, a.admin, b.admin)
	head, err := VerifyRosterChainWithClassifier(classifier, gPin, gPin, e1Obj, obj2)
	require.NoError(t, err)
	assert.Len(t, head.Manifest.Grants, 1)
}

// TestTieredGrant_LabSingleAdmin, de-solo sonrası bile LAB grant'ı 1 admin +
// audit ile kabul edilir (§4.5).
func TestTieredGrant_LabSingleAdmin(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	b := newAdminHuman(t, "bob@wapps.dev")
	c := newAdminHuman(t, "carol@wapps.dev")
	ra, rb, rc := edFromSeed(t, 0x60), edFromSeed(t, 0x61), edFromSeed(t, 0x62)

	e1 := rosterManifest(1, "", ChangeRoster, 2, []rootHolding{
		{ra, a.id}, {rb, b.id}, {rc, c.id},
	}, []adminHuman{a, b, c})
	e1Obj, gPin := signRoots(t, e1, ra, rb)

	classifier := func(project string) ProjectClass {
		if project == "kreeva-lab" {
			return ProjectLab
		}
		return ProjectProd
	}

	g := childOf(e1, e1Obj)
	g.ChangeClass = ChangeGrant
	g.Grants = []registry.Grant{{Principal: a.id, Project: "kreeva-lab", Verbs: []string{"get"}, Keys: []string{"API_KEY"}}}
	obj := signAdmins(t, g, a.admin) // 1 admin, lab
	head, err := VerifyRosterChainWithClassifier(classifier, gPin, gPin, e1Obj, obj)
	require.NoError(t, err)
	assert.Equal(t, "kreeva-lab", head.Manifest.Grants[0].Project)
}

// TestGrant_DailyKeyRejected, bir grant epoch'u daily anahtarıyla imzalanırsa
// reddedilir — daily anahtarları HİÇBİR trust epoch'unda geçerli değildir.
func TestGrant_DailyKeyRejected(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, gm := genesis3of(t, a.id, a)

	g := childOf(gm, gObj)
	g.ChangeClass = ChangeGrant
	g.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}}}
	obj := signAdmins(t, g, a.daily) // daily, admin değil
	_, err := VerifyRosterChainWithClassifier(func(string) ProjectClass { return ProjectProd }, gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}

// TestGrant_AutomationKeyRejected, automation Ed25519 anahtarı da bir grant
// epoch'unda geçersizdir (admins listesinde olmayan / automation sınıfı).
func TestGrant_AutomationKeyRejected(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, gm := genesis3of(t, a.id, a)

	automation := edFromSeed(t, 0x70) // automation Ed25519 yazılım anahtarı
	g := childOf(gm, gObj)
	g.ChangeClass = ChangeGrant
	g.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"set"}, Keys: []string{"TF_OUT"}}}
	var autoSigner cryptoid.SigningKey = automation
	obj, _, err := SignTrustManifest(g, autoSigner)
	require.NoError(t, err)
	_, err = VerifyRosterChainWithClassifier(func(string) ProjectClass { return ProjectProd }, gPin, gPin, gObj, obj)
	assert.ErrorIs(t, err, ErrTrustQuorumUnmet)
}
