package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

const rwProject = "vaulter"

func readOnlyGrant(principal, project string) registry.Grant {
	return registry.Grant{Principal: principal, Project: project, Verbs: []string{"read"}, Keys: []string{"*"}}
}

// TestRewrap_AddIsManifestOnly, ADD yolunun manifest-only olduğunu kanıtlar
// (§3.8.1): blob'lar DEĞİŞMEZ (aynı blobHash + keyVersion, sıfır yeni blob), yeni
// epoch, eklenen alıcı çözebilir, escrow + mevcut okuyucu korunur.
func TestRewrap_AddIsManifestOnly(t *testing.T) {
	mem := NewMemStore()
	e := newEngine(mem)

	a := newTHuman(t, "adnan@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})
	seedData(t, mem, head, rwProject, a.daily, map[string][]byte{
		"A": []byte("secret-A"), "DB": []byte("postgres://u:p@h/db"), "TOKEN": []byte("tok"),
	})

	// Enroll + vouch + grant B (read).
	b := newTHuman(t, "bob@wapps.dev")
	_, vnext, err := e.Vouch(VouchRequest{
		Parent: head, Enrollment: enrollFor(t, e, b), Identity: b.identity(),
		SecondChannelEnc: encFPs(b), SecondChannelSigning: signFPs(b),
		CeremonyConfirmed: true, VouchedBy: []string{a.id}, Signers: []cryptoid.SigningKey{a.admin},
	})
	require.NoError(t, err)
	_, gnext, err := e.Grant(GrantRequest{Parent: vnext, Grant: readOnlyGrant(b.id, rwProject), Signers: []cryptoid.SigningKey{a.admin}})
	require.NoError(t, err)

	// Rewrap öncesi durum.
	blobsBefore := blobCount(mem, rwProject)
	epochBefore := currentEpoch(t, mem, rwProject)
	entryABefore := currentEntry(t, mem, rwProject, "A")

	// ADD rewrap: B'nin device+backup'ını her anahtara ekle (yeni alıcı kümesi head3).
	res, err := e.Rewrap(RewrapRequest{
		Project: rwProject, TrustHead: gnext,
		Reader: a.device, Writer: a.daily, WriterID: a.id,
	})
	require.NoError(t, err)

	assert.Equal(t, 3, res.KeysAdd, "all 3 keys wrap-only ADD")
	assert.Equal(t, 0, res.KeysRemint, "ADD must not re-mint any DEK")
	assert.Equal(t, blobsBefore, blobCount(mem, rwProject), "ADD is manifest-only — zero new blobs")

	entryAAfter := currentEntry(t, mem, rwProject, "A")
	assert.Equal(t, entryABefore.BlobHash, entryAAfter.BlobHash, "blob unchanged (no re-encrypt)")
	assert.Equal(t, entryABefore.KeyVersion, entryAAfter.KeyVersion, "keyVersion unchanged on ADD")
	assert.Greater(t, currentEpoch(t, mem, rwProject), epochBefore, "new signed epoch")

	// Eklenen alıcı (B) artık çözebilir.
	pt, err := decryptAs(t, mem, rwProject, "A", b.device)
	require.NoError(t, err, "added recipient must decrypt after ADD")
	assert.Equal(t, "secret-A", string(pt))

	// Mevcut okuyucu (A) ve escrow hâlâ çözebilir.
	ptA, err := decryptAs(t, mem, rwProject, "A", a.device)
	require.NoError(t, err)
	assert.Equal(t, "secret-A", string(ptA))
	ptE, err := decryptAs(t, mem, rwProject, "A", esc.identity)
	require.NoError(t, err)
	assert.Equal(t, "secret-A", string(ptE))
}

// removeWorld, A (admin+reader+writer, granted) + EVE (granted read) + escrow olan
// bir dünya kurar ve seed'ler; REMOVE/resume/offboard testleri paylaşır.
func removeWorld(t *testing.T, values map[string][]byte) (*Engine, *MemStore, tHuman, tHuman, tEscrow, *trust.VerifiedEpoch) {
	t.Helper()
	mem := NewMemStore()
	e := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})
	seedData(t, mem, head, rwProject, a.daily, values)
	return e, mem, a, eve, esc, head
}

// revokeAndRetire, EVE'nin grant'ını kaldırır + kimliğini emekliye ayırır ve
// post-revoke head'i döner (rewrap REMOVE hedefi).
func revokeAndRetire(t *testing.T, e *Engine, a, eve tHuman, head *trust.VerifiedEpoch) *trust.VerifiedEpoch {
	t.Helper()
	_, h1, err := e.Revoke(RevokeRequest{Parent: head, Principal: eve.id, Signers: []cryptoid.SigningKey{a.admin}})
	require.NoError(t, err)
	_, h2, err := e.RetireIdentity(RetireRequest{Parent: h1, Principal: eve.id, Signers: []cryptoid.SigningKey{a.admin}})
	require.NoError(t, err)
	return h2
}

// TestRewrap_RemoveMintsNewDEK, REMOVE yolunun yeni DEK bastığını kanıtlar
// (§3.8.2): kaldırılan alıcı YENİ değeri çözemez, kalanlar + escrow çözer, değer
// değişmez, keyVersion artar, FullyRotated + attestation üretilir.
func TestRewrap_RemoveMintsNewDEK(t *testing.T) {
	e, mem, a, eve, esc, head := removeWorld(t, map[string][]byte{
		"A": []byte("secret-A"), "DB": []byte("postgres://u:p@h/db"),
	})

	// EVE önce çözebiliyor olmalı (baseline).
	pt, err := decryptAs(t, mem, rwProject, "A", eve.device)
	require.NoError(t, err)
	require.Equal(t, "secret-A", string(pt))
	entryBefore := currentEntry(t, mem, rwProject, "A")

	head2 := revokeAndRetire(t, e, a, eve, head)
	removed := []string{eve.device.Recipient().Fingerprint(), eve.backup.Recipient().Fingerprint()}

	res, err := e.Rewrap(RewrapRequest{
		Project: rwProject, TrustHead: head2,
		Reader: a.device, Writer: a.daily, WriterID: a.id,
		Removed: removed, RecordID: "ob_test",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res.KeysRemint, "both keys re-minted")
	assert.Equal(t, 0, res.KeysAdd)
	assert.True(t, res.FullyRotated, "no entry may wrap to a removed recipient")
	require.NotNil(t, res.Attestation, "fully-rotated attestation emitted")
	assert.Equal(t, AttestSchema, res.Attestation.Schema)

	entryAfter := currentEntry(t, mem, rwProject, "A")
	assert.NotEqual(t, entryBefore.BlobHash, entryAfter.BlobHash, "REMOVE mints a new blob (new DEK)")
	assert.Equal(t, entryBefore.KeyVersion+1, entryAfter.KeyVersion, "keyVersion increments on re-mint")

	// Kaldırılan (EVE) YENİ değeri çözemez (wrap yok).
	_, err = decryptAs(t, mem, rwProject, "A", eve.device)
	require.Error(t, err, "removed recipient must NOT decrypt the new value")
	_, err = decryptAs(t, mem, rwProject, "A", eve.backup)
	require.Error(t, err, "removed backup must NOT decrypt the new value")

	// Kalan (A) + escrow çözebilir; değer AYNIDIR (yalnızca DEK re-mint).
	ptA, err := decryptAs(t, mem, rwProject, "A", a.device)
	require.NoError(t, err)
	assert.Equal(t, "secret-A", string(ptA))
	ptE, err := decryptAs(t, mem, rwProject, "A", esc.identity)
	require.NoError(t, err)
	assert.Equal(t, "secret-A", string(ptE))

	for _, fp := range removed {
		assert.True(t, res.RemovedGone[fp], "removed fp %s excluded from every entry", fp)
	}
}

// TestRewrap_Resumable, rewrap'in ortada kesildiğinde (commit hatası) RESUME ile
// tamamlandığını kanıtlar (§8.5.3 ledger-driven idempotent resume).
func TestRewrap_Resumable(t *testing.T) {
	e, mem, a, eve, _, head := removeWorld(t, map[string][]byte{
		"A": []byte("val-A"), "B": []byte("val-B"), "C": []byte("val-C"),
	})
	head2 := revokeAndRetire(t, e, a, eve, head)
	removed := []string{eve.device.Recipient().Fingerprint(), eve.backup.Recipient().Fingerprint()}
	req := RewrapRequest{
		Project: rwProject, TrustHead: head2,
		Reader: a.device, Writer: a.daily, WriterID: a.id,
		Removed: removed, RecordID: "ob_resume",
	}

	// İlk commit'ten SONRA kes (3 anahtardan 1'i işlenir, sonra hata).
	mem.FailCommitAfter(1)
	_, err := e.Rewrap(req)
	require.Error(t, err, "rewrap must fail mid-way when commit is interrupted")

	// İyileş + RESUME → kalan işi current'tan türetip tamamlar (idempotent).
	mem.Heal()
	res, err := e.Rewrap(req)
	require.NoError(t, err, "resume must complete the remaining keys")
	assert.True(t, res.FullyRotated, "after resume, no entry wraps a removed recipient")
	assert.GreaterOrEqual(t, res.KeysSkipped, 1, "already-rotated key(s) skipped on resume")
	assert.GreaterOrEqual(t, res.KeysRemint, 2, "remaining keys re-minted on resume")

	// Her anahtar re-mint edildi (keyVersion=2) ve EVE hiçbirini çözemez.
	for _, k := range []string{"A", "B", "C"} {
		assert.EqualValues(t, 2, currentEntry(t, mem, rwProject, k).KeyVersion)
		_, derr := decryptAs(t, mem, rwProject, k, eve.device)
		require.Error(t, derr, "EVE must not decrypt %q after resume", k)
		ptA, derr := decryptAs(t, mem, rwProject, k, a.device)
		require.NoError(t, derr)
		assert.Equal(t, "val-"+k, string(ptA))
	}
}

// TestRewrap_RejectsDepartingReader, ayrılan (kaldırılan) prensibin okuyucu olarak
// rewrap çalıştırmasını reddeder — ayrılan asla tek çalıştırıcı olamaz (§8.5).
func TestRewrap_RejectsDepartingReader(t *testing.T) {
	e, _, a, eve, _, head := removeWorld(t, map[string][]byte{"A": []byte("x")})
	head2 := revokeAndRetire(t, e, a, eve, head)
	_, err := e.Rewrap(RewrapRequest{
		Project: rwProject, TrustHead: head2,
		Reader:            eve.device, // AYRILAN okuyucu
		ReaderFingerprint: eve.device.Recipient().Fingerprint(),
		Writer:            a.daily, WriterID: a.id,
		Removed: []string{eve.device.Recipient().Fingerprint()},
	})
	require.ErrorIs(t, err, ErrDepartingRunner)
}
