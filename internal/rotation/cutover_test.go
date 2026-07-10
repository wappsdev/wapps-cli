package rotation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
	"github.com/wappsdev/wapps-cli/internal/manifest"
)

const legacyPass = "correct-horse-battery-staple-16+"

// fakeLegacyArchive, gerçek tofu-output arşiv şeklinde ({"KEY":{"value":..}}) bir
// sahte scrypt all.enc.age üretir (ageutil ile). Cutover'ın legacy okuma yolunu sürer.
func fakeLegacyArchive(t *testing.T, values map[string]string) []byte {
	t.Helper()
	obj := map[string]map[string]string{}
	for k, v := range values {
		obj[k] = map[string]string{"value": v}
	}
	pt, err := json.Marshal(obj)
	require.NoError(t, err)
	ct, err := ageutil.Encrypt(pt, legacyPass)
	require.NoError(t, err)
	return ct
}

// cutoverFixture, cutover için alıcı kümesi (admin device + escrow) + writer + ring
// + verifier kurar.
type cutoverFixture struct {
	recipients []lifecycle.Recipient
	escrowFP   string
	verifier   *cryptoid.X25519Identity
	writer     *cryptoid.Ed25519SigningKey
	ring       manifest.WriterKeyring
}

func newCutoverFixture(t *testing.T) cutoverFixture {
	t.Helper()
	device, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	escrow, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	writer, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	vk, err := cryptoid.NewVerifierKey(writer.Alg(), writer.PublicKeyBytes())
	require.NoError(t, err)
	return cutoverFixture{
		recipients: []lifecycle.Recipient{
			{Fingerprint: device.Fingerprint(), Recipient: device.Recipient()},
			{Fingerprint: escrow.Fingerprint(), Recipient: escrow.Recipient()},
		},
		escrowFP: escrow.Fingerprint(),
		verifier: device,
		writer:   writer,
		ring:     manifest.WriterKeyring{writer.KeyID(): vk},
	}
}

func (f cutoverFixture) input(project string, legacy []byte, inv map[string]KeyInventory, data lifecycle.DataStore) CutoverInput {
	return CutoverInput{
		Project: project, Legacy: LegacyArchiveFromBytes(legacy), Passphrase: legacyPass,
		Recipients: f.recipients, EscrowFPs: []string{f.escrowFP},
		Writer: f.writer, Ring: f.ring, TrustEpoch: 1,
		Inventory: inv, Verifier: f.verifier, Data: data, Now: fixedNow,
	}
}

// TestCutover_RoundtripByteEqual, cutover'ın her anahtarı byte-identical taşıdığını
// (roundtrip: fetch + decrypt = legacy düz-metni) kanıtlar (§10.2 Phase 1).
func TestCutover_RoundtripByteEqual(t *testing.T) {
	f := newCutoverFixture(t)
	legacy := fakeLegacyArchive(t, map[string]string{
		"DB_URL":   "postgres://user:pw@host/db",
		"CF_TOKEN": "cf-abc-123",
	})
	mem := lifecycle.NewMemStore()
	inv := map[string]KeyInventory{
		"DB_URL":   {Recipe: RecipeDBRolePhase1, Origin: OriginStatic, BlastTier: lifecycle.TierProdShared},
		"CF_TOKEN": {Recipe: RecipeCFManual, Origin: OriginStatic, BlastTier: lifecycle.TierPlatformAnchor},
	}
	res, err := Cutover(context.Background(), f.input(testProject, legacy, inv, mem))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), res.Epoch)
	assert.Equal(t, 2, res.Keys)

	// Bağımsız roundtrip: store'dan çöz ve legacy'yle byte-compare et.
	legacyVals, err := LegacyArchiveFromBytes(legacy).Values(legacyPass)
	require.NoError(t, err)
	for _, key := range []string{"DB_URL", "CF_TOKEN"} {
		got := decryptFromStore(t, mem, testProject, key, f.verifier)
		assert.Equal(t, legacyVals[key], got, "cutover value byte-identical to legacy for %s", key)
	}
}

// TestCutover_MismatchAbortsLeavingLegacyAuthoritative, roundtrip doğrulaması
// başarısız olursa (store bozulması) cutover'ın İPTAL ettiğini ve legacy'nin
// otoritatif KALDIĞINI (dokunulmadığı için hâlâ çözülebilir) kanıtlar (§10.2).
func TestCutover_MismatchAbortsLeavingLegacyAuthoritative(t *testing.T) {
	f := newCutoverFixture(t)
	legacy := fakeLegacyArchive(t, map[string]string{"DB_URL": "postgres://x"})
	corrupt := &corruptStore{MemStore: lifecycle.NewMemStore()}
	inv := map[string]KeyInventory{"DB_URL": {Recipe: RecipeDBRolePhase1, Origin: OriginStatic, BlastTier: lifecycle.TierProdShared}}

	_, err := Cutover(context.Background(), f.input(testProject, legacy, inv, corrupt))
	require.ErrorIs(t, err, ErrCutoverVerifyMismatch, "cutover aborts on roundtrip mismatch")

	// Legacy DOKUNULMADI (IRON RULE) → hâlâ otoritatif: orijinal değerler çözülür.
	vals, verr := LegacyArchiveFromBytes(legacy).Values(legacyPass)
	require.NoError(t, verr)
	assert.Equal(t, []byte("postgres://x"), vals["DB_URL"], "legacy remains authoritative — config is NOT flipped to store")
}

// TestCutover_TFOriginMarkedMirrorOnly, TF-origin anahtarların store'a mirror
// olarak taşındığını AMA origin:"tofu" ile işaretlendiğini (mirror-only §8.6.5)
// kanıtlar → sonraki store-tarafı rotate onları reddeder.
func TestCutover_TFOriginMarkedMirrorOnly(t *testing.T) {
	f := newCutoverFixture(t)
	legacy := fakeLegacyArchive(t, map[string]string{
		"DATABASE_URL": "postgres://tf", // tofu-origin (mirror-only)
		"APP_SECRET":   "static-secret", // static
	})
	mem := lifecycle.NewMemStore()
	inv := map[string]KeyInventory{
		"DATABASE_URL": {Recipe: RecipeDBRolePhase1, Origin: OriginTofu, BlastTier: lifecycle.TierProdShared},
		"APP_SECRET":   {Recipe: RecipeCoolifyStart, Origin: OriginStatic, BlastTier: lifecycle.TierProdSingle},
	}
	res, err := Cutover(context.Background(), f.input(testProject, legacy, inv, mem))
	require.NoError(t, err)
	assert.Equal(t, []string{"DATABASE_URL"}, res.TFOriginKeys, "TF-origin key reported as mirror-only")

	// Manifest girdisinin rotasyon-metadata'sı origin:"tofu" taşımalı.
	origin := entryOrigin(t, mem, testProject, "DATABASE_URL")
	assert.Equal(t, OriginTofu, origin, "TF-origin key marked mirror-only in the manifest")
	assert.Equal(t, OriginStatic, entryOrigin(t, mem, testProject, "APP_SECRET"))
}

// TestCutover_IronRuleNoLegacyWrite, LegacyArchive'ın SALT-OKUNUR olduğunu (hiçbir
// yazma yolu yok) — cutover'ın legacy'e yazamayacağını statik olarak kanıtlar: tek
// izinli legacy yazım guard'lı tombstone'dur (IRON RULE §10.5). Burada legacy
// ciphertext cutover ÖNCESİ ve SONRASI byte-identical kalır.
func TestCutover_IronRuleNoLegacyWrite(t *testing.T) {
	f := newCutoverFixture(t)
	legacy := fakeLegacyArchive(t, map[string]string{"K": "v"})
	before := append([]byte(nil), legacy...)
	mem := lifecycle.NewMemStore()
	inv := map[string]KeyInventory{"K": {Recipe: RecipeCoolifyStart, Origin: OriginStatic, BlastTier: lifecycle.TierDev}}
	_, err := Cutover(context.Background(), f.input(testProject, legacy, inv, mem))
	require.NoError(t, err)
	assert.Equal(t, before, legacy, "cutover never writes back to the legacy archive (IRON RULE)")
}

// TestCutover_EscrowInvariantStructural, escrow-wrap değişmezinin (§9.1) çağıran-
// özenine bağlı OLMADIĞINI kanıtlar: boş EscrowFPs VEYA alıcı kümesinde olmayan bir
// escrow fp → cutover İPTAL (ErrEscrowMissing), hiçbir genesis commit edilmez →
// legacy otoritatif kalır.
func TestCutover_EscrowInvariantStructural(t *testing.T) {
	f := newCutoverFixture(t)
	legacy := fakeLegacyArchive(t, map[string]string{"DB_URL": "postgres://x"})
	inv := map[string]KeyInventory{"DB_URL": {Recipe: RecipeDBRolePhase1, Origin: OriginStatic, BlastTier: lifecycle.TierProdShared}}

	// (a) Boş EscrowFPs → yapısal ret.
	memA := lifecycle.NewMemStore()
	inA := f.input(testProject, legacy, inv, memA)
	inA.EscrowFPs = nil
	_, err := Cutover(context.Background(), inA)
	require.ErrorIs(t, err, ErrEscrowMissing, "empty EscrowFPs aborts — escrow-wrap invariant is structural")
	_, _, _, _, ok, cerr := memA.CurrentManifest(testProject)
	require.NoError(t, cerr)
	assert.False(t, ok, "no genesis committed — legacy stays authoritative")

	// (b) Alıcı kümesinde olmayan escrow fp → yine ret.
	memB := lifecycle.NewMemStore()
	inB := f.input(testProject, legacy, inv, memB)
	inB.EscrowFPs = []string{"blake3:not-in-recipient-set"}
	_, err = Cutover(context.Background(), inB)
	require.ErrorIs(t, err, ErrEscrowMissing, "escrow fp absent from recipient set aborts")
	_, _, _, _, ok, cerr = memB.CurrentManifest(testProject)
	require.NoError(t, cerr)
	assert.False(t, ok, "no genesis committed when escrow is not a recipient")

	// Legacy DOKUNULMADI → hâlâ otoritatif.
	vals, verr := LegacyArchiveFromBytes(legacy).Values(legacyPass)
	require.NoError(t, verr)
	assert.Equal(t, []byte("postgres://x"), vals["DB_URL"])
}

// TestCutover_PostCommitDroppedEntryAborts, post-commit roundtrip'in EKSİKSİZLİK
// kontrolünü kanıtlar (§10.2): okuma-sırasında bir girdiyi DÜŞÜREN bir store/transport
// hatası fark edilmeden geçmez — daha az anahtar karşılaştırılsa bile cutover İPTAL
// eder ve legacy otoritatif kalır (bu, post-commit pass'in var olma sebebi olan
// store-bozulma sınıfının ta kendisidir).
func TestCutover_PostCommitDroppedEntryAborts(t *testing.T) {
	f := newCutoverFixture(t)
	legacy := fakeLegacyArchive(t, map[string]string{
		"DB_URL":   "postgres://user:pw@host/db",
		"CF_TOKEN": "cf-abc-123",
	})
	drop := &droppingStore{MemStore: lifecycle.NewMemStore(), writer: f.writer, drop: "CF_TOKEN"}
	inv := map[string]KeyInventory{
		"DB_URL":   {Recipe: RecipeDBRolePhase1, Origin: OriginStatic, BlastTier: lifecycle.TierProdShared},
		"CF_TOKEN": {Recipe: RecipeCFManual, Origin: OriginStatic, BlastTier: lifecycle.TierPlatformAnchor},
	}
	_, err := Cutover(context.Background(), f.input(testProject, legacy, inv, drop))
	require.ErrorIs(t, err, ErrCutoverVerifyMismatch, "a store that drops an entry on read aborts cutover")

	// Legacy hâlâ otoritatif (config store'a flip edilmedi).
	vals, verr := LegacyArchiveFromBytes(legacy).Values(legacyPass)
	require.NoError(t, verr)
	assert.Equal(t, []byte("cf-abc-123"), vals["CF_TOKEN"], "dropped key still readable from legacy")
}

// --- test doubles + helpers -------------------------------------------------

// corruptStore, CurrentManifest'in döndürdüğü her blob'u bozarak roundtrip
// doğrulamasını başarısız kılan bir DataStore'dur (store/transport bozulması).
type corruptStore struct {
	*lifecycle.MemStore
}

// droppingStore, CurrentManifest okumasında manifest'ten BİR girdiyi DÜŞÜREN bir
// DataStore'dur (store/transport girdi-düşürme hatası). Azaltılmış manifest'i writer
// ile yeniden imzalar — post-commit doğrulama imzayı denetlemez, body'yi ayrıştırıp
// per-key byte-compare eder → eksiklik ancak TAMLIK kontrolüyle yakalanır.
type droppingStore struct {
	*lifecycle.MemStore
	writer cryptoid.SigningKey
	drop   string
}

func (d *droppingStore) CurrentManifest(project string) ([]byte, map[string][]byte, uint64, string, bool, error) {
	wrapper, blobs, epoch, objHash, ok, err := d.MemStore.CurrentManifest(project)
	if err != nil || !ok {
		return wrapper, blobs, epoch, objHash, ok, err
	}
	obj, perr := manifest.ParseSignedObject(wrapper)
	if perr != nil {
		return nil, nil, 0, "", false, perr
	}
	man, berr := manifest.ParseManifestBody(obj.Bytes)
	if berr != nil {
		return nil, nil, 0, "", false, berr
	}
	kept := make([]manifest.KeyEntry, 0, len(man.Entries))
	for _, e := range man.Entries {
		if e.KeyName == d.drop {
			continue // okuma-sırasında bir girdiyi düşür
		}
		kept = append(kept, e)
	}
	man.Entries = kept
	signed, _, serr := manifest.SignManifest(man, d.writer)
	if serr != nil {
		return nil, nil, 0, "", false, serr
	}
	raw, merr := manifest.MarshalSignedObject(signed)
	if merr != nil {
		return nil, nil, 0, "", false, merr
	}
	return raw, blobs, epoch, objHash, true, nil
}

func (c *corruptStore) CurrentManifest(project string) ([]byte, map[string][]byte, uint64, string, bool, error) {
	wrapper, blobs, epoch, objHash, ok, err := c.MemStore.CurrentManifest(project)
	if ok {
		for h, b := range blobs {
			if len(b) > 8 {
				b[8] ^= 0xFF // blob'u boz → VerifyBlobHash başarısız
			}
			blobs[h] = b
		}
	}
	return wrapper, blobs, epoch, objHash, ok, err
}

func decryptFromStore(t *testing.T, data lifecycle.DataStore, project, key string, id *cryptoid.X25519Identity) []byte {
	t.Helper()
	wrapper, blobs, _, _, ok, err := data.CurrentManifest(project)
	require.NoError(t, err)
	require.True(t, ok)
	obj, err := manifest.ParseSignedObject(wrapper)
	require.NoError(t, err)
	man, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)
	for i := range man.Entries {
		if man.Entries[i].KeyName == key {
			got, derr := decryptEntry(project, man.Entries[i], blobs, id.Fingerprint(), id)
			require.NoError(t, derr)
			return got
		}
	}
	t.Fatalf("key %q not found", key)
	return nil
}

func entryOrigin(t *testing.T, mem *lifecycle.MemStore, project, key string) string {
	t.Helper()
	wrapper, _, _, _, ok, err := mem.CurrentManifest(project)
	require.NoError(t, err)
	require.True(t, ok)
	obj, err := manifest.ParseSignedObject(wrapper)
	require.NoError(t, err)
	man, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)
	for i := range man.Entries {
		if man.Entries[i].KeyName == key {
			require.NotNil(t, man.Entries[i].Rotation, "entry %q must carry rotation metadata", key)
			var doc struct {
				Origin string `json:"origin"`
			}
			require.NoError(t, json.Unmarshal(man.Entries[i].Rotation.Raw(), &doc))
			return doc.Origin
		}
	}
	t.Fatalf("key %q not found", key)
	return ""
}
