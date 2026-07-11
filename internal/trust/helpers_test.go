package trust

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// testTime, deterministik created_at.
var testTime = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

// edFromSeed, seed baytından deterministik Ed25519 kök anahtarı üretir (aynı
// anahtarla sonraki epoch'ları yeniden imzalayabilmek için).
func edFromSeed(t *testing.T, b byte) *cryptoid.Ed25519SigningKey {
	t.Helper()
	k, err := cryptoid.NewEd25519FromSeed(bytes.Repeat([]byte{b}, 32))
	require.NoError(t, err)
	return k
}

// adminHuman, bir admin insan kimliğinin tüm anahtar ailelerini tutar.
type adminHuman struct {
	id     string
	admin  *cryptoid.ECDSAP256SigningKey // presence-required admin anahtarı
	daily  *cryptoid.ECDSAP256SigningKey // no-presence daily anahtarı
	device *cryptoid.X25519Identity
	backup *cryptoid.X25519Identity
}

func newAdminHuman(t *testing.T, email string) adminHuman {
	t.Helper()
	admin, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	daily, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	device, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	backup, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	return adminHuman{id: "human:" + email, admin: admin, daily: daily, device: device, backup: backup}
}

// identity, admin insanı registry.Identity'ye çevirir (device+backup enc,
// admin+daily signing).
func (a adminHuman) identity() registry.Identity {
	return registry.Identity{
		ID:         a.id,
		Type:       registry.TypeHuman,
		Status:     registry.StatusActive,
		EnrolledAt: testTime,
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(a.device.Recipient(), registry.EncClassDevice, "secure-enclave", 1),
			registry.NewEncKeyEntry(a.backup.Recipient(), registry.EncClassBackup, "paper-steel", 1),
		},
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(a.admin, registry.SignClassAdmin, "secure-enclave"),
			registry.NewSigningKeyEntry(a.daily, registry.SignClassDaily, "secure-enclave"),
		},
	}
}

// rootHolding, bir kök anahtarını sahibiyle eşler (custody dağılımı için).
type rootHolding struct {
	key    *cryptoid.Ed25519SigningKey
	holder string
}

// rosterManifest, verilen kök dağılımı + admin kümesiyle bir roster manifest'i
// kurar; bootstrap_solo değişmez kuralına göre otomatik hesaplanır.
func rosterManifest(epoch uint64, prev, changeClass string, m int, holdings []rootHolding, admins []adminHuman) *TrustManifest {
	var roots []RootKey
	for _, h := range holdings {
		roots = append(roots, NewRootKey(h.key, "yubikey-piv", h.holder))
	}
	var adminIDs []string
	var ids []registry.Identity
	for _, a := range admins {
		adminIDs = append(adminIDs, a.id)
		ids = append(ids, a.identity())
	}
	return &TrustManifest{
		Schema:          SchemaTrust,
		AdminEpoch:      epoch,
		PrevTrustSHA256: prev,
		CreatedAt:       testTime,
		ChangeClass:     changeClass,
		BootstrapSolo:   maxHolderShare(roots) >= m,
		Quorum:          Quorum{M: m, N: len(roots)},
		Roots:           roots,
		Admins:          adminIDs,
		Identities:      ids,
		WorkerReceiptPub: ReceiptKey{
			Kid: "att-1", Alg: "ES256", JWK: json.RawMessage(`{"kty":"EC","crv":"P-256"}`),
		},
	}
}

// signRoots, manifest'i verilen kök anahtarlarıyla imzalar ve obj + pin döner.
func signRoots(t *testing.T, m *TrustManifest, roots ...*cryptoid.Ed25519SigningKey) (cryptoid.SignedObject, Pin) {
	t.Helper()
	keys := make([]cryptoid.SigningKey, len(roots))
	for i, r := range roots {
		keys[i] = r
	}
	obj, _, err := SignTrustManifest(m, keys...)
	require.NoError(t, err)
	return obj, Pin{AdminEpoch: m.AdminEpoch, SHA256: TrustObjectHash(obj.Bytes)}
}

// signAdmins, manifest'i verilen admin (P-256) anahtarlarıyla imzalar.
func signAdmins(t *testing.T, m *TrustManifest, admins ...*cryptoid.ECDSAP256SigningKey) cryptoid.SignedObject {
	t.Helper()
	keys := make([]cryptoid.SigningKey, len(admins))
	for i, a := range admins {
		keys[i] = a
	}
	obj, _, err := SignTrustManifest(m, keys...)
	require.NoError(t, err)
	return obj
}

// childOf, parent'tan bir halef manifest iskeleti kurar (epoch+1, prev = parent
// payload hash). Çağıran change_class + içeriği değiştirir. Roots/Admins/Grants
// gibi dilimler değiştirilecekse çağıran YENİ dilim atar (parent paylaşılmasın).
func childOf(parent *TrustManifest, parentObj cryptoid.SignedObject) *TrustManifest {
	c := *parent
	c.AdminEpoch = parent.AdminEpoch + 1
	c.PrevTrustSHA256 = TrustObjectHash(parentObj.Bytes)
	return &c
}

// holdingsOf, aynı sahibe ait n kök anahtarı üretir.
func holdingsOf(holder string, keys ...*cryptoid.Ed25519SigningKey) []rootHolding {
	out := make([]rootHolding, 0, len(keys))
	for _, k := range keys {
		out = append(out, rootHolding{key: k, holder: holder})
	}
	return out
}
