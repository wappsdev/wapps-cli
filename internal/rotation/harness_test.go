package rotation

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// Bu dosya, G11 rotasyon motorunu GERÇEK bir offboard (G9) akışına bağlayan testin
// asgari fixture'ını kurar. lifecycle'ın kendi (unexported, package lifecycle) test
// yardımcıları buradan erişilemez → yalnızca DIŞA AÇIK API'lerle (trust/registry/
// cryptoid/manifest/lifecycle) yeniden kurulur. Kripto tekrarı YOK: seed, rotation'ın
// kendi sealDEKToRecipients'ini + lifecycle.RequiredRecipients'i kullanır.

const testProject = "vaulter-test"

var fixTime = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return fixTime }

// tHuman, bir insanın tüm anahtar ailelerini tutar.
type tHuman struct {
	id     string
	admin  *cryptoid.ECDSAP256SigningKey
	daily  *cryptoid.ECDSAP256SigningKey
	device *cryptoid.X25519Identity
	backup *cryptoid.X25519Identity
}

func newTHuman(t *testing.T, email string) tHuman {
	t.Helper()
	admin, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	daily, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	device, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	backup, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	return tHuman{id: "human:" + email, admin: admin, daily: daily, device: device, backup: backup}
}

func (h tHuman) identity() registry.Identity {
	return registry.Identity{
		ID:         h.id,
		Type:       registry.TypeHuman,
		Status:     registry.StatusActive,
		EnrolledAt: fixTime,
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(h.device.Recipient(), registry.EncClassDevice, "software", 1),
			registry.NewEncKeyEntry(h.backup.Recipient(), registry.EncClassBackup, "paper-steel", 1),
		},
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(h.admin, registry.SignClassAdmin, "software"),
			registry.NewSigningKeyEntry(h.daily, registry.SignClassDaily, "software"),
		},
	}
}

// tEscrow, escrow kimliği + çözebilen X25519 identity (her wrap-set'in zorunlu üyesi).
type tEscrow struct {
	id       registry.Identity
	identity *cryptoid.X25519Identity
}

func newTEscrow(t *testing.T) tEscrow {
	t.Helper()
	esc, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	return tEscrow{
		identity: esc,
		id: registry.Identity{
			ID:         "escrow:vault",
			Type:       registry.TypeEscrow,
			Status:     registry.StatusActive,
			EnrolledAt: fixTime,
			EncKeys: []registry.EncKey{
				registry.NewEncKeyEntry(esc.Recipient(), registry.EncClassBackup, "paper-steel", 1),
			},
		},
	}
}

func edFromSeed(t *testing.T, b byte) *cryptoid.Ed25519SigningKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := cryptoid.NewEd25519FromSeed(seed)
	require.NoError(t, err)
	return k
}

func readOnlyGrant(principal, project string) registry.Grant {
	return registry.Grant{Principal: principal, Project: project, Verbs: []string{"read"}, Keys: []string{"*"}}
}

func readWriteGrant(principal, project string) registry.Grant {
	return registry.Grant{
		Principal: principal, Project: project,
		Verbs: []string{"read", "write", "set", "exec", "apply"}, Keys: []string{"*"},
	}
}

// genesisSpec, bir genesis trust manifest'i kurmanın girdisi.
type genesisSpec struct {
	identities []registry.Identity
	adminIDs   []string
	grants     []registry.Grant
	roots      []*cryptoid.Ed25519SigningKey
	holders    []string
	m          int
	solo       bool
}

func prodClassifier(string) trust.ProjectClass { return trust.ProjectProd }

// buildGenesis, bir genesis roster epoch'u kurar, ≥m kökle imzalar ve doğrular.
func buildGenesis(t *testing.T, spec genesisSpec) (*trust.VerifiedEpoch, trust.Pin) {
	t.Helper()
	var roots []trust.RootKey
	for i, rk := range spec.roots {
		roots = append(roots, trust.NewRootKey(rk, "yubikey-piv", spec.holders[i]))
	}
	tm := &trust.TrustManifest{
		Schema:           trust.SchemaTrust,
		AdminEpoch:       1,
		PrevTrustSHA256:  "",
		CreatedAt:        fixTime,
		ChangeClass:      trust.ChangeRoster,
		BootstrapSolo:    spec.solo,
		Quorum:           trust.Quorum{M: spec.m, N: len(spec.roots)},
		Roots:            roots,
		Admins:           spec.adminIDs,
		Identities:       spec.identities,
		Grants:           spec.grants,
		WorkerReceiptPub: trust.ReceiptKey{Kid: "att-1", Alg: "ES256", JWK: json.RawMessage(`{"kty":"EC","crv":"P-256"}`)},
	}
	signers := make([]cryptoid.SigningKey, 0, spec.m)
	for i := 0; i < spec.m; i++ {
		signers = append(signers, spec.roots[i])
	}
	obj, _, err := trust.SignTrustManifest(tm, signers...)
	require.NoError(t, err)
	pin := trust.Pin{AdminEpoch: 1, SHA256: trust.TrustObjectHash(obj.Bytes)}
	head, err := trust.VerifyRosterChainWithClassifier(prodClassifier, pin, pin, obj)
	require.NoError(t, err, "genesis must verify")
	return head, pin
}

// seedDataMeta, epoch1 data manifest'ini verilen değerler + per-key rotasyon metadata
// (JSON) ile kurar; rotation.sealDEKToRecipients + lifecycle.RequiredRecipients ile
// wrap'ler, writer ile imzalar ve MemStore'a commit eder.
func seedDataMeta(t *testing.T, mem *lifecycle.MemStore, head *trust.VerifiedEpoch, project string, writer cryptoid.SigningKey, values map[string][]byte, meta map[string]string) {
	t.Helper()
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)

	entries := make([]manifest.KeyEntry, 0, len(values))
	for _, name := range names {
		slot := cryptoid.Slot{Project: project, KeyName: name, KeyVersion: 1}
		dek, err := cryptoid.NewDEK()
		require.NoError(t, err)
		blob, err := cryptoid.SealBlob(values[name], dek, slot)
		require.NoError(t, err)
		hash := cryptoid.BlobHash(blob)
		require.NoError(t, mem.PutBlob(project, hash, blob))
		recips, err := lifecycle.RequiredRecipients(head.Manifest, project, name)
		require.NoError(t, err)
		wraps, err := sealDEKToRecipients(dek, recips, slot)
		require.NoError(t, err)
		ke := manifest.KeyEntry{KeyName: name, KeyVersion: 1, BlobHash: hash, Wraps: wraps}
		if mj, ok := meta[name]; ok && mj != "" {
			ke.Rotation = manifest.NewRotationMeta([]byte(mj))
		}
		entries = append(entries, ke)
	}
	m := &manifest.DataManifest{
		Schema:             manifest.SchemaDataManifest,
		Project:            project,
		Epoch:              1,
		PrevManifestSha256: "",
		TrustEpoch:         head.Manifest.AdminEpoch,
		CreatedAt:          fixTime,
		Entries:            entries,
	}
	signed, _, err := manifest.SignManifest(m, writer)
	require.NoError(t, err)
	raw, err := manifest.MarshalSignedObject(signed)
	require.NoError(t, err)
	require.NoError(t, mem.CommitManifest(project, raw, ""))
}
