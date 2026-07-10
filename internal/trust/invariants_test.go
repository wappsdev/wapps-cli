package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/registry"
)

// TestSemanticInvariant_ProtectedFields, roster OLMAYAN bir epoch'un korunan
// alanları (admins, quorum, worker_receipt_pubkey) değiştirmesinin
// TRUST_CHAIN_BROKEN ile reddedildiğini test eder (SPEC §4.5 step 5).
func TestSemanticInvariant_ProtectedFields(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")

	tests := []struct {
		name   string
		mutate func(e *TrustManifest)
	}{
		{
			name: "changes admins",
			mutate: func(e *TrustManifest) {
				e.Admins = append(append([]string(nil), e.Admins...), "human:ghost@x")
			},
		},
		{
			name: "changes quorum",
			mutate: func(e *TrustManifest) {
				e.Quorum = Quorum{M: 3, N: 3} // roots sabit, ama quorum farklı
			},
		},
		{
			name: "changes worker_receipt_pubkey",
			mutate: func(e *TrustManifest) {
				e.WorkerReceiptPub = ReceiptKey{Kid: "rotated", Alg: "ES256"}
			},
		},
		{
			// Worker token-mint / audit-head ES256 anahtarları yalnızca roster
			// M-of-N epoch'uyla rotasyona uğrar; 1-admin registry epoch'u ASLA.
			name: "changes worker_mint_pubkeys",
			mutate: func(e *TrustManifest) {
				e.WorkerMintPubs = append(append([]ReceiptKey(nil), e.WorkerMintPubs...),
					ReceiptKey{Kid: "mint-rotated", Alg: "ES256"})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gObj, gPin, gm := genesis3of(t, a.id, a)
			e2 := childOf(gm, gObj)
			e2.ChangeClass = ChangeRegistry
			tt.mutate(e2)
			obj := signAdmins(t, e2, a.admin) // registry = 1 admin
			_, err := VerifyRosterChain(gPin, gPin, gObj, obj)
			assert.ErrorIs(t, err, ErrTrustChainBroken)
		})
	}
}

// TestValidateRosterInvariants_QuorumBounds, m<2 ve m>n kök/quorum sınırlarının
// reddedildiğini test eder (SPEC §4.2.2).
func TestValidateRosterInvariants_QuorumBounds(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	r0, r1, r2 := edFromSeed(t, 0xA0), edFromSeed(t, 0xA1), edFromSeed(t, 0xA2)

	// m=1 (<2) → chain broken.
	m1 := rosterManifest(1, "", ChangeRoster, 1, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	obj1, pin1 := signRoots(t, m1, r0)
	_, err := VerifyGenesis(pin1, obj1)
	assert.ErrorIs(t, err, ErrTrustChainBroken)

	// m>n (4>3) → chain broken.
	m2 := rosterManifest(1, "", ChangeRoster, 4, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	obj2, pin2 := signRoots(t, m2, r0, r1)
	_, err = VerifyGenesis(pin2, obj2)
	assert.ErrorIs(t, err, ErrTrustChainBroken)

	// n != aktif kök sayısı → chain broken.
	m3 := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	m3.Quorum.N = 5 // aktif 3 ama n=5
	obj3, pin3 := signRoots(t, m3, r0, r1)
	_, err = VerifyGenesis(pin3, obj3)
	assert.ErrorIs(t, err, ErrTrustChainBroken)
}

// TestVerifyNext_DefaultAndNilClassifier, VerifyRosterChain'in varsayılan
// sınıflandırıcısını (tümü prod) ve VerifyNext'in nil-classifier yolunu test
// eder: solo altında prod grant 1 admin ile geçer.
func TestVerifyNext_DefaultAndNilClassifier(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, gObj, gPin, gm := genesis3of(t, a.id, a)

	grant := childOf(gm, gObj)
	grant.ChangeClass = ChangeGrant
	grant.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}}}
	obj := signAdmins(t, grant, a.admin)

	// Varsayılan VerifyRosterChain (defaultClassifier = prod), solo → 1 admin geçer.
	head, err := VerifyRosterChain(gPin, gPin, gObj, obj)
	require.NoError(t, err)
	assert.Len(t, head.Manifest.Grants, 1)

	// Doğrudan VerifyNext, classifier nil → grantTargetClass prod döner. Grant
	// epoch'u olduğu için pinnedLast/witnessBound yok sayılır (yalnızca reset
	// yolunu etkiler).
	gen, err := VerifyGenesis(gPin, gObj)
	require.NoError(t, err)
	_, err = VerifyNext(gen, obj, nil, gPin, gPin.AdminEpoch)
	require.NoError(t, err)
}

// TestManifest_RegistryAccessor, gömülü kayıt görünümünün grant çözümlemesini
// döndürdüğünü test eder.
func TestManifest_RegistryAccessor(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	_, _, _, gm := genesis3of(t, a.id, a)
	gm.Grants = []registry.Grant{{Principal: a.id, Project: "vaulter", Verbs: []string{"exec"}, Keys: []string{"DB_URL"}}}

	reg := gm.Registry()
	assert.Equal(t, registry.SchemaRegistry, reg.Schema)
	assert.True(t, reg.VerbAllowed(a.id, "vaulter", "exec"))
	assert.True(t, reg.KeyAllowed(a.id, "vaulter", "DB_URL"))
	assert.False(t, reg.KeyAllowed(a.id, "vaulter", "OTHER"))
}
