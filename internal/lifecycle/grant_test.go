package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// soloWorld, tek admin (A tüm kökleri tutar, bootstrap_solo) bir genesis kurar.
func soloWorld(t *testing.T, classifier trust.ProjectClassifier) (*Engine, tHuman, tEscrow, *trust.VerifiedEpoch) {
	t.Helper()
	e := New(Config{Now: fixedNow, Classifier: classifier})
	a := newTHuman(t, "adnan@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     nil,
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2,
		solo:       true,
	})
	return e, a, esc, head
}

// deSoloWorld, iki admin (A,B) + üç ayrı kök holder (de-solo) bir genesis kurar.
func deSoloWorld(t *testing.T, classifier trust.ProjectClassifier) (*Engine, tHuman, tHuman, tEscrow, *trust.VerifiedEpoch) {
	t.Helper()
	e := New(Config{Now: fixedNow, Classifier: classifier})
	a := newTHuman(t, "adnan@wapps.dev")
	b := newTHuman(t, "bob@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), b.identity(), esc.id},
		adminIDs:   []string{a.id, b.id},
		grants:     nil,
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, b.id, "human:carol@wapps.dev"},
		m:          2,
		solo:       false,
	})
	return e, a, b, esc, head
}

// TestGrant_SoloSingleAdmin, bootstrap_solo iken bir PROD grant'ın TEK admin
// imzasıyla kabul edildiğini kanıtlar (§4.6 solo katman).
func TestGrant_SoloSingleAdmin(t *testing.T) {
	e, a, _, head := soloWorld(t, prodClassifier)
	// A'yı vaulter (prod) üzerinde grant'la — solo, 1 admin yeter.
	_, next, err := e.Grant(GrantRequest{
		Parent:  head,
		Grant:   readWriteGrant(a.id, "vaulter"),
		Signers: []cryptoid.SigningKey{a.admin},
	})
	require.NoError(t, err)
	assert.True(t, next.Manifest.Registry().VerbAllowed(a.id, "vaulter", "read"))
	assert.Equal(t, trust.ChangeGrant, next.Manifest.ChangeClass)
}

// TestGrant_ProdNeedsTwoAdmins, de-solo (N_h=2) bir PROD grant'ın 2 FARKLI admin
// imzası gerektirdiğini kanıtlar: 1 admin reddedilir, 2 admin kabul (§4.5/§4.7).
func TestGrant_ProdNeedsTwoAdmins(t *testing.T) {
	e, a, b, _, head := deSoloWorld(t, prodClassifier)

	// 1 admin → quorum unmet.
	_, _, err := e.Grant(GrantRequest{
		Parent:  head,
		Grant:   readWriteGrant(a.id, "vaulter"),
		Signers: []cryptoid.SigningKey{a.admin},
	})
	require.ErrorIs(t, err, trust.ErrTrustQuorumUnmet)

	// 2 FARKLI admin → kabul.
	_, next, err := e.Grant(GrantRequest{
		Parent:  head,
		Grant:   readWriteGrant(a.id, "vaulter"),
		Signers: []cryptoid.SigningKey{a.admin, b.admin},
	})
	require.NoError(t, err)
	assert.True(t, next.Manifest.Registry().VerbAllowed(a.id, "vaulter", "read"))
}

// TestGrant_LabSingleAdmin, de-solo olsa bile bir LAB grant'ının 1 admin ile kabul
// edildiğini kanıtlar (§4.5 lab katman).
func TestGrant_LabSingleAdmin(t *testing.T) {
	classifier := func(project string) trust.ProjectClass {
		if project == "kreeva-lab" {
			return trust.ProjectLab
		}
		return trust.ProjectProd
	}
	e, a, _, _, head := deSoloWorld(t, classifier)
	_, next, err := e.Grant(GrantRequest{
		Parent:  head,
		Grant:   registry.Grant{Principal: a.id, Project: "kreeva-lab", Verbs: []string{"read"}, Keys: []string{"API_KEY"}},
		Signers: []cryptoid.SigningKey{a.admin},
	})
	require.NoError(t, err)
	assert.Equal(t, "kreeva-lab", next.Manifest.Grants[len(next.Manifest.Grants)-1].Project)
}

// TestGrant_RejectUnenrolledPrincipal, kayıtlı olmayan bir prensibe grant reddedilir.
func TestGrant_RejectUnenrolledPrincipal(t *testing.T) {
	e, _, _, head := soloWorld(t, prodClassifier)
	_, _, err := e.Grant(GrantRequest{
		Parent:  head,
		Grant:   readWriteGrant("human:ghost@wapps.dev", "vaulter"),
		Signers: []cryptoid.SigningKey{newTHuman(t, "x@x").admin},
	})
	require.ErrorIs(t, err, registry.ErrIdentityNotEnrolled)
}

// TestRevoke_RemovesGrant, revoke'un bir prensibin grant'ını kaldırdığını ve
// sonuç head'de erişimin kaybolduğunu kanıtlar (§8.5.3 step 1).
func TestRevoke_RemovesGrant(t *testing.T) {
	e, a, _, head := soloWorld(t, prodClassifier)
	// Önce grant'la (eve'i de ekle).
	eve := newTHuman(t, "eve@wapps.dev")
	// eve'i kayda ekle (registry epoch) — basitlik için grant öncesi manuel head kur.
	vres, vnext, err := e.Vouch(VouchRequest{
		Parent: head, Enrollment: enrollFor(t, e, eve), Identity: eve.identity(),
		SecondChannelEnc: encFPs(eve), SecondChannelSigning: signFPs(eve),
		CeremonyConfirmed: true, VouchedBy: []string{a.id}, Signers: []cryptoid.SigningKey{a.admin},
	})
	require.NoError(t, err)
	_ = vres
	_, gnext, err := e.Grant(GrantRequest{Parent: vnext, Grant: readWriteGrant(eve.id, "vaulter"), Signers: []cryptoid.SigningKey{a.admin}})
	require.NoError(t, err)
	require.True(t, gnext.Manifest.Registry().VerbAllowed(eve.id, "vaulter", "read"))

	// Revoke.
	_, rnext, err := e.Revoke(RevokeRequest{Parent: gnext, Principal: eve.id, Project: "vaulter", Signers: []cryptoid.SigningKey{a.admin}})
	require.NoError(t, err)
	assert.False(t, rnext.Manifest.Registry().VerbAllowed(eve.id, "vaulter", "read"), "grant must be gone after revoke")
}

// --- küçük yardımcılar ------------------------------------------------------

func enrollFor(t *testing.T, e *Engine, h tHuman) registry.EnrollmentRecord {
	t.Helper()
	rec, err := registry.NewEnrollmentRecord(h.identity(), fixTime)
	require.NoError(t, err)
	return rec
}

func encFPs(h tHuman) []string {
	return []string{h.device.Recipient().Fingerprint(), h.backup.Recipient().Fingerprint()}
}

func signFPs(h tHuman) []string {
	return []string{h.admin.KeyID(), h.daily.KeyID()}
}
