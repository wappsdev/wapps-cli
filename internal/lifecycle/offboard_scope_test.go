package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// TestOffboardStep2_ScopeMustCoverGrantBearingProjects (P1 forward-secrecy §8.5.6):
// ayrılan prensip iki projede grant taşırken offboard scope'u yalnızca BİRİNİ
// listeliyorsa, rewrap-REMOVE atlanan projede DEK'i yenilemez → prensip o projenin
// güncel değerlerini hâlâ çözebilir. Step2 bunu rewrap'e BAŞLAMADAN reddetmeli
// (ErrScopeIncomplete) — sessizce eksik-kapsamlı ilerleyip close'da sahte
// "all_steps_verified" imzalamak yerine.
func TestOffboardStep2_ScopeMustCoverGrantBearingProjects(t *testing.T) {
	const otherProject = "lab"

	mem := NewMemStore()
	e := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)

	// Eve İKİ projede okuma grant'ı taşır: rwProject + otherProject.
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants: []registry.Grant{
			readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject),
			readWriteGrant(a.id, otherProject), readOnlyGrant(eve.id, otherProject),
		},
		roots:   []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders: []string{a.id, a.id, a.id},
		m:       2, solo: true,
	})
	seedData(t, mem, head, rwProject, a.daily, map[string][]byte{"CF_TOKEN": []byte("cf")})
	seedData(t, mem, head, otherProject, a.daily, map[string][]byte{"API_KEY": []byte("k")})

	recID := "ob_scope_1"
	// Scope KASITLI olarak eksik: yalnızca rwProject; otherProject atlanmış.
	_, err := e.OffboardStart(OffboardStartRequest{
		Head:      head,
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: recID,
	})
	require.NoError(t, err)
	_, err = e.OffboardStep1Kill(recID, head, a.id, a.admin)
	require.NoError(t, err)

	_, err = e.OffboardStep2Rewrap(recID, Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin},
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	assert.ErrorIs(t, err, ErrScopeIncomplete,
		"under-scoped offboard (grant-bearing project omitted) must fail closed, not silently proceed")

	// Rewrap adımına GİRİLMEDİĞİNİ doğrula: hiçbir grant revoke edilmemeli
	// (in.Head hâlâ eve'nin her iki grant'ını taşımalı).
	assert.True(t, principalHasGrants(head.Manifest, eve.id), "revoke must not have run")
}

// TestOffboardStep2_ScopeCoversAllGrants_Proceeds, scope TÜM grant-taşıyan projeleri
// kapsadığında Step2'nin ErrScopeIncomplete VERMEDEN ilerlediğini kanıtlar (kontrol
// grubu: gate meşru bir offboard'ı bloklamamalı).
func TestOffboardStep2_ScopeCoversAllGrants_Proceeds(t *testing.T) {
	e, _, a, eve, _, head := offboardSoloWorld(t)
	recID := "ob_scope_ok"
	_, err := e.OffboardStart(OffboardStartRequest{
		Head:      head,
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: recID,
	})
	require.NoError(t, err)
	_, err = e.OffboardStep1Kill(recID, head, a.id, a.admin)
	require.NoError(t, err)

	out2, err := e.OffboardStep2Rewrap(recID, Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin},
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	require.NoError(t, err, "fully-scoped offboard must proceed")
	require.NotNil(t, out2)
}
