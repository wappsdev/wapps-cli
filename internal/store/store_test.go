package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

func init() { noSleep = true } // rebase backoff'unu testlerde atla

// errDoer, her isteği taşıma hatasıyla reddeder (çevrimdışı simülasyonu).
type errDoer struct{}

func (errDoer) Do(*http.Request) (*http.Response, error) { return nil, errors.New("offline") }

func (f *fixture) storeDir(t *testing.T) string {
	t.Helper()
	if f.dirCache == "" {
		f.dirCache = t.TempDir()
		require.NoError(t, trust.NewPinStore(f.genesisPin).Save(f.dirCache+"/roots.json"))
	}
	return f.dirCache
}

func (f *fixture) store(t *testing.T, doer httpDoer) *WorkerStore {
	t.Helper()
	dir := f.storeDir(t)
	if doer == nil {
		doer = f.server.srv.Client()
	}
	return New(Config{
		BaseURL:      f.server.srv.URL,
		Doer:         doer,
		PinPath:      dir + "/roots.json",
		CacheDir:     dir + "/cache",
		EpochPinPath: dir + "/epochs.json",
		Witness:      intent.NoWitness{}, // deploy testleri için tanık wire'lı (stub)
		Now:          f.server.now,
	})
}

// seed, epoch1 data manifest'ini iki anahtarla (A, DB) kurar (Commit üzerinden).
func (f *fixture) seed(t *testing.T) *WorkerStore {
	t.Helper()
	st := f.store(t, nil)
	res, err := st.Commit(context.Background(), testProject, f.delta(map[string][]byte{
		"A":  []byte("secret-A"),
		"DB": []byte("postgres://user:pw@host/db"),
	}))
	require.NoError(t, err)
	require.EqualValues(t, 1, res.EpochAfter)
	return st
}

func TestCommitAndFetch_Roundtrip(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t)

	snap, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Dev})
	require.NoError(t, err)
	require.EqualValues(t, 1, snap.Epoch)
	require.ElementsMatch(t, []string{"A", "DB"}, snap.Keys())

	// CLI ÇÖZER (Worker aksine): device kimliğiyle düz metin.
	a, err := snap.Decrypt(f.human.device, "A")
	require.NoError(t, err)
	require.Equal(t, "secret-A", string(a))

	db, err := snap.Decrypt(f.human.device, "DB")
	require.NoError(t, err)
	require.Equal(t, "postgres://user:pw@host/db", string(db))

	// Backup kimliği de çözebilmeli (wrap-set device+backup+escrow içerir).
	ab, err := snap.Decrypt(f.human.backup, "A")
	require.NoError(t, err)
	require.Equal(t, "secret-A", string(ab))

	// Escrow da çözebilir (escrow recipient wrap-set'te zorunlu).
	ae, err := snap.Decrypt(f.escrow, "A")
	require.NoError(t, err)
	require.Equal(t, "secret-A", string(ae))
}

func TestFetch_304Reuse(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t)

	_, err := st.Fetch(context.Background(), testProject, FetchOpts{})
	require.NoError(t, err)
	blobsAfterFirst := f.server.blobGets

	// İkinci fetch: cache'teki ETag → 304 → hiçbir blob yeniden çekilmez.
	snap, err := st.Fetch(context.Background(), testProject, FetchOpts{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, f.server.notModified, 1, "second fetch must hit the 304 path")
	require.Equal(t, blobsAfterFirst, f.server.blobGets, "304 reuse must fetch no blobs")

	// 304 sonrası cache'ten çözme çalışmalı.
	a, err := snap.Decrypt(f.human.device, "A")
	require.NoError(t, err)
	require.Equal(t, "secret-A", string(a))
}

func TestFetch_OfflineCacheFallback(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t)
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{}) // cache doldur
	require.NoError(t, err)

	// Çevrimdışı store (aynı dizin, hatalı taşıma).
	off := f.store(t, errDoer{})
	snap, err := off.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Dev})
	require.NoError(t, err)
	require.True(t, snap.FromCache)
	require.NotEmpty(t, snap.Warnings, "offline read must warn (key-count + age only)")
	require.NotContains(t, snap.Warnings[0], "secret-A", "warning must never contain a value")

	a, err := snap.Decrypt(f.human.device, "A")
	require.NoError(t, err)
	require.Equal(t, "secret-A", string(a))
}

func TestFetch_OfflineDeployFailsClosed(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t)
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{})
	require.NoError(t, err)

	off := f.store(t, errDoer{})
	_, err = off.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Deploy})
	require.True(t, clierr.Is(err, clierr.StaleReceipt), "deploy offline must fail closed: %v", err)
}

func TestFetch_TamperManifestSig(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	// İmzayı boz + pointer hash'ini eşleştir → hash-link geçer, İMZA düşer.
	f.server.mu.Lock()
	corrupt := corruptManifestSig(t, f.server.projManifests[1])
	f.server.installCurrent(1, corrupt)
	f.server.mu.Unlock()

	fresh := f.freshStore(t)
	_, err := fresh.Fetch(context.Background(), testProject, FetchOpts{})
	require.True(t, clierr.Is(err, clierr.SigInvalid), "tampered manifest sig must be rejected: %v", err)
}

func TestFetch_TamperBlobHash(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	// A'nın blob'unu bozuk baytlarla değiştir (hash artık eşleşmez).
	f.server.mu.Lock()
	obj, _ := manifest.ParseSignedObject(f.server.projManifests[1])
	m, _ := manifest.ParseManifestBody(obj.Bytes)
	var aHash string
	for _, e := range m.Entries {
		if e.KeyName == "A" {
			aHash = e.BlobHash
		}
	}
	orig := f.server.blobs[aHash]
	tampered := append([]byte(nil), orig...)
	tampered[len(tampered)-1] ^= 0xFF
	f.server.blobs[aHash] = tampered
	f.server.mu.Unlock()

	fresh := f.freshStore(t)
	_, err := fresh.Fetch(context.Background(), testProject, FetchOpts{})
	require.True(t, clierr.Is(err, clierr.BlobHashMismatch), "tampered blob must be rejected: %v", err)
}

func TestFetch_UnpinnedTrustRejected(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	// Yanlış genesis pin ile store → trust zinciri doğrulanamaz.
	dir := t.TempDir()
	badPin := trust.Pin{AdminEpoch: 1, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}
	require.NoError(t, trust.NewPinStore(badPin).Save(dir+"/roots.json"))
	st := New(Config{
		BaseURL: f.server.srv.URL, Doer: f.server.srv.Client(),
		PinPath: dir + "/roots.json", CacheDir: dir + "/cache", EpochPinPath: dir + "/epochs.json",
		Now: f.server.now,
	})
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{})
	require.True(t, clierr.Is(err, clierr.SigInvalid), "wrong genesis pin must reject the chain: %v", err)
}

func TestCommit_AutoRebaseDisjoint(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t) // epoch1: A, DB

	// Kazanan epoch2, A'yı değiştirir (bizim set'imiz B — disjoint).
	winner := mkWinner(t, f, "A")
	f.server.mu.Lock()
	f.server.injectQueue = append(f.server.injectQueue, winner)
	f.server.mu.Unlock()

	res, err := st.Commit(context.Background(), testProject, f.delta(map[string][]byte{
		"B": []byte("secret-B"),
	}))
	require.NoError(t, err)
	require.Equal(t, 1, res.Rebased, "disjoint conflict must auto-rebase exactly once")
	require.EqualValues(t, 3, res.EpochAfter, "rebased commit lands at epoch 3")
}

func TestCommit_SameKeyConflictAborts(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t) // epoch1: A, DB

	// Kazanan epoch2, B'yi değiştirir; biz de B set ediyoruz → aynı-key abort.
	winner := mkWinner(t, f, "B")
	// Kazananın B girdisi yok (epoch1'de B yok) — mkWinner ekler.
	f.server.mu.Lock()
	f.server.injectQueue = append(f.server.injectQueue, winner)
	f.server.mu.Unlock()

	_, err := st.Commit(context.Background(), testProject, f.delta(map[string][]byte{
		"B": []byte("mine-B"),
	}))
	require.True(t, clierr.Is(err, clierr.CASConflict), "same-key race must abort with CAS_CONFLICT: %v", err)
	var e *clierr.Error
	require.True(t, errors.As(err, &e))
	require.Contains(t, e.Recovery, "conflicting writers", "recovery must name both writers")
}

func TestFetch_DeployFreshOK(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t)
	snap, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Deploy})
	require.NoError(t, err)
	require.NotNil(t, snap.Receipt, "deploy fetch must carry a verified liveness receipt")
}

func TestFetch_DeployStaleReceiptRejected(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t)
	// Receipt iat'ı 20dk geriye al → tazelik penceresi dışında.
	f.server.mu.Lock()
	f.server.receiptIAT = f.server.clock.Add(-20 * time.Minute).Unix()
	f.server.mu.Unlock()

	_, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Deploy})
	require.True(t, clierr.Is(err, clierr.StaleReceipt), "stale receipt must be rejected: %v", err)
}

func TestFetch_EpochDowngradeRejected(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t) // epoch1

	// epoch2 yaz → pin=2.
	_, err := st.Commit(context.Background(), testProject, f.delta(map[string][]byte{"C": []byte("c")}))
	require.NoError(t, err)
	_, err = st.Fetch(context.Background(), testProject, FetchOpts{})
	require.NoError(t, err)

	// Sunucuyu epoch1'e geri sar → sunulan epoch < pin → EPOCH_DOWNGRADE.
	f.server.mu.Lock()
	f.server.rollbackTo(1)
	f.server.mu.Unlock()

	_, err = st.Fetch(context.Background(), testProject, FetchOpts{})
	require.True(t, clierr.Is(err, clierr.EpochDowngrade), "epoch rollback must be rejected: %v", err)
}

func TestCommit_OfflineWriteBlocked(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	off := f.store(t, errDoer{})
	_, err := off.Commit(context.Background(), testProject, f.delta(map[string][]byte{"X": []byte("x")}))
	require.True(t, clierr.Is(err, clierr.OfflineWriteBlocked), "offline write must fail closed: %v", err)
}

// TestCommit_WorkerInflatedEpochRejected (P2-a): başarılı bir 200 commit'te Worker
// YEREL imzalı epoch'tan farklı (şişirilmiş) bir epoch echo'larsa, İstemci bunu
// kurcalama sayar (SIG_INVALID) ve monotonik pin'i İLERLETMEZ — aksi halde pin
// ileriye zehirlenip gelecekteki tüm okumaları EPOCH_DOWNGRADE ile brick'lerdi.
func TestCommit_WorkerInflatedEpochRejected(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t) // epoch1, pin=1

	f.server.mu.Lock()
	f.server.commitEpochOverride = 999 // >> newEpoch(2)
	f.server.mu.Unlock()

	_, err := st.Commit(context.Background(), testProject, f.delta(map[string][]byte{"C": []byte("secret-C")}))
	require.True(t, clierr.Is(err, clierr.SigInvalid), "inflated epoch echo must be rejected as tampering: %v", err)

	// Pin, newEpoch(2)'nin ötesine (hatta ona) ilerlememeli — seed'deki 1'de kalmalı.
	pin, perr := st.pinnedEpoch(testProject)
	require.NoError(t, perr)
	require.EqualValues(t, 1, pin, "pin must not advance on a tampered epoch echo")
}

// TestCommit_WriteThroughCacheKeepsOfflineReadCoherent (P2-b): commit ciphertext
// cache'i write-through etmezse ama pin'i ilerletirse, write→çevrimdışı→dev-read
// bayat cache'i ESKİ epoch'ta yükleyip EPOCH_DOWNGRADE ile bozulurdu. Write-through
// ile cache epoch'u ve pin epoch'u coherent kalır → çevrimdışı okuma başarılı.
func TestCommit_WriteThroughCacheKeepsOfflineReadCoherent(t *testing.T) {
	f := newFixture(t)
	st := f.seed(t) // epoch1

	// Önce online oku → cache epoch1'de.
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Dev})
	require.NoError(t, err)

	// Yeni anahtar yaz → epoch2; pin=2 VE write-through cache de epoch2'ye.
	res, err := st.Commit(context.Background(), testProject, f.delta(map[string][]byte{"C": []byte("secret-C")}))
	require.NoError(t, err)
	require.EqualValues(t, 2, res.EpochAfter)

	// Çevrimdışı dev okuma: coherent cache → EPOCH_DOWNGRADE YOK.
	off := f.store(t, errDoer{})
	snap, err := off.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Dev})
	require.NoError(t, err, "write-through cache must keep the offline read coherent (no EPOCH_DOWNGRADE)")
	require.True(t, snap.FromCache)
	require.EqualValues(t, 2, snap.Epoch, "offline read must serve the new epoch, not the stale old one")

	// Yeni anahtar cache'ten çözülebilmeli (blob write-through ile yazıldı).
	c, err := snap.Decrypt(f.human.device, "C")
	require.NoError(t, err)
	require.Equal(t, "secret-C", string(c))
}

// TestFetch_DeployWitnessNotWiredFailsClosed (P3-a): --intent deploy, wire'lı bir
// Witness olmadan SESSİZCE ilerleyemez — fail-closed (WITNESS_NOT_WIRED). Bu, stub
// bir tanıkla witness-blind deploy'un shipping'ini engeller (G10 gerçek non-CF
// origin'i enjekte edecek).
func TestFetch_DeployWitnessNotWiredFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.seed(t) // epoch1 (f.store, tanık wire'lı — seed = commit, tanıktan etkilenmez)

	// Tanık wire'lanMAMIŞ bir store (Witness alanı boş).
	dir := f.storeDir(t)
	st := New(Config{
		BaseURL: f.server.srv.URL, Doer: f.server.srv.Client(),
		PinPath: dir + "/roots.json", CacheDir: dir + "/cache", EpochPinPath: dir + "/epochs.json",
		Now: f.server.now,
		// Witness: nil
	})
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Deploy})
	require.True(t, clierr.Is(err, clierr.WitnessNotWired), "deploy without a wired witness must fail closed: %v", err)
}

// TestFetch_WriterOverreachRejected (P3-b): geçerli imzalı ama imzalayanın yazma
// grant'ı OLMAYAN bir anahtarı değiştiren bir manifest, okuma doğrulama boru
// hattında reddedilir (WRITER_NOT_ALLOWED). Compromised bir Worker, düşük-yetkili
// bir yazar imzasıyla yetkisiz anahtarlara taşan bir manifest sunamaz.
func TestFetch_WriterOverreachRejected(t *testing.T) {
	f := newFixture(t)
	f.seed(t) // epoch1: A, DB (insan-imzalı)

	// machine:limited YALNIZCA "B"yi yazabilir; "A"yı değiştiren epoch2 imzalar → taşma.
	tampered := mkManifestSignedBy(t, f, "A", f.limitedWriter)
	f.server.mu.Lock()
	f.server.installCurrent(2, tampered)
	f.server.mu.Unlock()

	fresh := f.freshStore(t)
	_, err := fresh.Fetch(context.Background(), testProject, FetchOpts{})
	require.True(t, clierr.Is(err, clierr.WriterNotAllowed), "writer overreach must be rejected: %v", err)
}

// --- test yardımcıları ------------------------------------------------------

// freshStore, cache'siz taze bir store döner (tamper testleri blob'u yeniden
// çekmeli, cache'ten okumamalı).
func (f *fixture) freshStore(t *testing.T) *WorkerStore {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, trust.NewPinStore(f.genesisPin).Save(dir+"/roots.json"))
	return New(Config{
		BaseURL: f.server.srv.URL, Doer: f.server.srv.Client(),
		PinPath: dir + "/roots.json", CacheDir: dir + "/cache", EpochPinPath: dir + "/epochs.json",
		Now: f.server.now,
	})
}

func (fw *fakeWorker) rollbackTo(epoch uint64) {
	wrapper := fw.projManifests[epoch]
	fw.installCurrent(epoch, wrapper)
}

// mkWinner, changeKey'i değiştiren (varsa keyVersion+1/blobHash, yoksa yeni
// girdi ekleyen) imzalı bir epoch2 manifest'i kurar (yarış kazananı; insan daily
// anahtarıyla imzalanır).
func mkWinner(t *testing.T, f *fixture, changeKey string) []byte {
	t.Helper()
	return mkManifestSignedBy(t, f, changeKey, f.human.daily)
}

// mkManifestSignedBy, epoch1 tabanı üzerine changeKey'i değiştiren (keyVersion+1/
// blobHash veya yeni girdi) bir epoch2 manifest'i kurar ve VERİLEN anahtarla
// imzalar. Yarış kazananı (insan daily) VE yazar-yetkisi taşma (sınırlı otomasyon
// yazarı) senaryolarını paylaşır.
func mkManifestSignedBy(t *testing.T, f *fixture, changeKey string, signer cryptoid.SigningKey) []byte {
	t.Helper()
	f.server.mu.Lock()
	cur := f.server.projManifests[1]
	f.server.mu.Unlock()
	obj, err := manifest.ParseSignedObject(cur)
	require.NoError(t, err)
	m, err := manifest.ParseManifestBody(obj.Bytes)
	require.NoError(t, err)

	entries := append([]manifest.KeyEntry(nil), m.Entries...)
	found := false
	for i := range entries {
		if entries[i].KeyName == changeKey {
			entries[i].KeyVersion++
			entries[i].BlobHash = sha256Hex([]byte("changed-blob-" + changeKey))
			found = true
		}
	}
	if !found {
		entries = append(entries, manifest.KeyEntry{
			KeyName: changeKey, KeyVersion: 1,
			BlobHash: sha256Hex([]byte("changed-blob-" + changeKey)),
		})
	}
	wm := &manifest.DataManifest{
		Schema: manifest.SchemaDataManifest, Project: testProject, Epoch: 2,
		PrevManifestSha256: manifest.ManifestObjectHash(cur), TrustEpoch: 1,
		CreatedAt: fixTime, Entries: entries,
	}
	wobj, _, err := manifest.SignManifest(wm, signer)
	require.NoError(t, err)
	raw, err := manifest.MarshalSignedObject(wobj)
	require.NoError(t, err)
	return raw
}

// corruptManifestSig, imzalı sarmalayıcının imza baytlarından birini bozar
// (baytlar aynı kalır → hash-link kurtarılabilir, ama imza artık geçmez).
func corruptManifestSig(t *testing.T, wrapper []byte) []byte {
	t.Helper()
	obj, err := manifest.ParseSignedObject(wrapper)
	require.NoError(t, err)
	require.NotEmpty(t, obj.Sigs)
	sig := append([]byte(nil), obj.Sigs[0].Sig...)
	sig[0] ^= 0xFF
	obj.Sigs[0].Sig = sig
	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	return raw
}
