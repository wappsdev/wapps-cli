package lifecycle

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// fixTime, deterministik saat.
var fixTime = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return fixTime }

// tHuman, bir insan kimliğinin tüm anahtar ailelerini tutar (test fixture'ı).
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

// tEscrow, escrow kimliği + çözebilen X25519 identity.
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

func receiptJWK() json.RawMessage {
	return json.RawMessage(`{"kty":"EC","crv":"P-256"}`)
}

// genesisSpec, bir genesis trust manifest'i kurmanın girdisidir.
type genesisSpec struct {
	identities []registry.Identity
	adminIDs   []string
	grants     []registry.Grant
	roots      []*cryptoid.Ed25519SigningKey
	holders    []string // roots[i]'nin custody sahibi
	m          int
	solo       bool
}

// buildGenesis, bir genesis roster epoch'u kurar, ≥m kökle imzalar, doğrular ve
// (head, pin) döner.
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
		WorkerReceiptPub: trust.ReceiptKey{Kid: "att-1", Alg: "ES256", JWK: receiptJWK()},
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

// prodClassifier, tüm projeleri prod sayar (strict).
func prodClassifier(string) trust.ProjectClass { return trust.ProjectProd }

// readWriteGrant, bir prensibe bir projede tam okuma+yazma grant'ı kurar.
func readWriteGrant(principal, project string) registry.Grant {
	return registry.Grant{
		Principal: principal, Project: project,
		Verbs: []string{"read", "write", "set", "exec", "apply"},
		Keys:  []string{"*"},
	}
}

// newEngine, verilen MemStore ile bir test motoru kurar.
func newEngine(mem *MemStore) *Engine {
	return New(Config{
		Data:       mem,
		Records:    mem,
		Classifier: prodClassifier,
		Now:        fixedNow,
	})
}

// seedData, epoch1 data manifest'ini verilen değerlerle kurar (rotasyon metadata
// olmadan).
func seedData(t *testing.T, mem *MemStore, head *trust.VerifiedEpoch, project string, writer cryptoid.SigningKey, values map[string][]byte) {
	t.Helper()
	seedDataMeta(t, mem, head, project, writer, values, nil)
}

// seedDataMeta, epoch1 data manifest'ini verilen değerler + opsiyonel per-key
// rotasyon metadata (JSON) ile kurar (RequiredRecipients + escrow ile wrap'lenir),
// writer ile imzalanır ve MemStore'a commit edilir. Rewrap motorunun aynı
// primitiflerini (RequiredRecipients, sealToRecipients) YENİDEN KULLANIR.
func seedDataMeta(t *testing.T, mem *MemStore, head *trust.VerifiedEpoch, project string, writer cryptoid.SigningKey, values map[string][]byte, meta map[string]string) {
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
		recips, err := RequiredRecipients(head.Manifest, project, name)
		require.NoError(t, err)
		wraps, err := sealToRecipients(dek, recips, slot)
		require.NoError(t, err)
		ke := manifest.KeyEntry{KeyName: name, KeyVersion: 1, BlobHash: hash, Wraps: wraps}
		if meta != nil {
			if mj, ok := meta[name]; ok && mj != "" {
				ke.Rotation = manifest.NewRotationMeta([]byte(mj))
			}
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

// decryptAs, MemStore'daki current manifest'ten bir anahtarı verilen X25519
// kimlikle çözer (store.Decrypt mantığını yansıtır). Wrap yoksa/çözemezse hata.
func decryptAs(t *testing.T, mem *MemStore, project, keyName string, id *cryptoid.X25519Identity) ([]byte, error) {
	t.Helper()
	wrapper, blobs, _, _, ok, err := mem.CurrentManifest(project)
	require.NoError(t, err)
	require.True(t, ok, "project must have data")
	obj, err := manifest.ParseSignedObject(wrapper)
	require.NoError(t, err)
	man, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)
	var entry *manifest.KeyEntry
	for i := range man.Entries {
		if man.Entries[i].KeyName == keyName {
			entry = &man.Entries[i]
			break
		}
	}
	require.NotNil(t, entry, "key %q must be in manifest", keyName)
	fp := id.Fingerprint()
	var wrap []byte
	for _, w := range entry.Wraps {
		if w.Recipient == fp {
			wrap = w.Wrap
			break
		}
	}
	if wrap == nil {
		return nil, ErrNotAReader // bu kimliğin wrap'i yok
	}
	dek, derr := cryptoid.UnsealDEK(wrap, id)
	if derr != nil {
		return nil, derr
	}
	blob := blobs[entry.BlobHash]
	if verr := cryptoid.VerifyBlobHash(blob, entry.BlobHash); verr != nil {
		return nil, verr
	}
	slot := cryptoid.Slot{Project: project, KeyName: keyName, KeyVersion: entry.KeyVersion}
	return cryptoid.OpenBlob(blob, dek, slot)
}

// currentEntry, current manifest'ten bir anahtarın girdisini döner (test iddiaları).
func currentEntry(t *testing.T, mem *MemStore, project, keyName string) manifest.KeyEntry {
	t.Helper()
	wrapper, _, _, _, ok, err := mem.CurrentManifest(project)
	require.NoError(t, err)
	require.True(t, ok)
	obj, err := manifest.ParseSignedObject(wrapper)
	require.NoError(t, err)
	man, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)
	for _, e := range man.Entries {
		if e.KeyName == keyName {
			return e
		}
	}
	t.Fatalf("key %q not found", keyName)
	return manifest.KeyEntry{}
}

// currentEpoch, current data epoch'unu döner.
func currentEpoch(t *testing.T, mem *MemStore, project string) uint64 {
	t.Helper()
	_, _, epoch, _, ok, err := mem.CurrentManifest(project)
	require.NoError(t, err)
	require.True(t, ok)
	return epoch
}

// blobCount, MemStore'daki proje blob sayısını döner.
func blobCount(mem *MemStore, project string) int {
	mem.mu.Lock()
	defer mem.mu.Unlock()
	p, ok := mem.proj[project]
	if !ok {
		return 0
	}
	return len(p.blobs)
}
