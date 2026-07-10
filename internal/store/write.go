package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// maxRebase, aynı-key olmayan (disjoint) çakışmalarda auto-rebase deneme sayısı
// (SPEC §7.3.5).
const maxRebase = 3

// Commit, epoch+1 CAS yazımı yapar (SPEC §7.3.5). Çevrimdışıysa fail-closed
// (OFFLINE_WRITE_BLOCKED). 412'de (kayıp yarış): disjoint anahtar kümesi ise
// yerel delta'yı yeni head'e rebase eder, yeniden imzalar ve tekrar dener (max 3,
// jittered); AYNI anahtar dokunulmuşsa CAS_CONFLICT (iki yazarı gösterir).
func (w *WorkerStore) Commit(ctx context.Context, project string, delta ManifestDelta) (*CommitResult, error) {
	if len(delta.Sets) == 0 {
		return nil, clierr.New(clierr.Internal, "commit: no changes")
	}
	if delta.Writer == nil {
		return nil, clierr.New(clierr.IdentityMissing, "commit: no writer signing key")
	}
	in, err := intent.Parse(string(delta.Intent))
	if err != nil {
		return nil, err
	}

	pins, err := w.loadPins()
	if err != nil {
		return nil, err
	}
	head, chainWrappers, err := w.fetchTrustHead(ctx, pins)
	if errors.Is(err, errOffline) {
		return nil, intent.BlockOfflineWrite()
	}
	if err != nil {
		return nil, err
	}
	ring := dataWriterKeyring(head.Manifest)

	// Temel (base) durumu çek.
	base, err := w.fetchCurrentState(ctx, project, ring)
	if errors.Is(err, errOffline) {
		return nil, intent.BlockOfflineWrite()
	}
	if err != nil {
		return nil, err
	}

	rebased := 0
	for attempt := 0; ; attempt++ {
		signed, newBlobs, newEpoch, err := w.buildManifest(project, head, base, delta)
		if err != nil {
			return nil, err
		}

		// Blob'ları PUT et (içerik-adresli; idempotent).
		for hash, blob := range newBlobs {
			if err := w.putBlob(ctx, project, hash, blob, in); err != nil {
				return nil, err
			}
		}

		// Commit POST.
		res, err := w.postCommit(ctx, project, signed, delta, in)
		if errors.Is(err, errOffline) {
			return nil, intent.BlockOfflineWrite()
		}
		if err == nil {
			// İstemci Worker'ın döndürdüğü epoch'a GÜVENMEZ (tehdit modeli): DO,
			// epoch==current+1'i TAM imzalı baytlar üzerinde zorladı → başarılı bir
			// 200'de res.epoch YEREL imzalı newEpoch ile AYNI OLMALIDIR. Şişirilmiş
			// bir echo, monotonik pin'i (~/.config/wapps/epochs.json) ileriye zehirleyip
			// gelecekteki TÜM okumaları EPOCH_DOWNGRADE ile kalıcı brick'ler → kurcalama
			// say, pin'i İLERLETME (P2-a).
			if res.epoch != newEpoch {
				return nil, clierr.Newf(clierr.SigInvalid,
					"commit: worker echoed epoch %d but the locally-signed epoch is %d", res.epoch, newEpoch)
			}
			// Pin'i YEREL imzalı newEpoch'tan ilerlet (Worker'ın res.epoch'undan DEĞİL).
			if err := w.checkAndAdvanceEpochPin(project, newEpoch); err != nil {
				return nil, err
			}
			// §7.3.3 write-through: ciphertext cache'i yeni imzalı manifest + blob'larla
			// newEpoch'a taşı ki cache epoch'u ile pin epoch'u COHERENT kalsın. Aksi halde
			// write→çevrimdışı→dev-read bayat cache'i ESKİ epoch'ta yükler ve
			// checkAndAdvanceEpochPin'de EPOCH_DOWNGRADE ile meşru bir çevrimdışı okumayı
			// bozar (P2-b).
			w.writeThroughCache(project, signed, newBlobs, newEpoch, ring, head, chainWrappers)
			return &CommitResult{EpochBefore: base.epoch, EpochAfter: newEpoch, Rebased: rebased}, nil
		}

		// Yalnızca EPOCH_CONFLICT (412) rebase edilir; diğer hatalar döndürülür.
		if !clierr.Is(err, clierr.CASConflict) {
			return nil, err
		}
		if attempt >= maxRebase {
			return nil, clierr.New(clierr.CASConflict, fmt.Sprintf("write lost the race after %d rebase attempts", maxRebase)).
				WithRecovery(fmt.Sprintf("re-run the command; conflicting writer holds epoch ≥ %d", newEpoch))
		}

		// Yeni head'i çek + yeniden doğrula.
		newBase, ferr := w.fetchCurrentState(ctx, project, ring)
		if errors.Is(ferr, errOffline) {
			return nil, intent.BlockOfflineWrite()
		}
		if ferr != nil {
			return nil, ferr
		}
		// Kazananın dokunduğu anahtarlar ∩ bizim değişikliklerimiz → aynı-key abort.
		winner := winnerTouched(base.entries, newBase.entries)
		if overlaps(winner, delta.Sets) {
			return nil, sameKeyConflict(delta, base, newBase)
		}
		// Disjoint: yeni head'e rebase et, jittered backoff, tekrar dene.
		base = newBase
		rebased++
		jitterSleep(w, attempt)
	}
}

// writeThroughCache, başarılı bir commit'ten sonra ciphertext cache'i yeni imzalı
// manifest + blob'larla günceller (§7.3.3). saveCache gibi BEST-EFFORT'tur: cache
// bir optimizasyondur, commit başarısı SAYILMAZ (herhangi bir adım hata verirse
// sessizce vazgeçilir). Blob'lar önceki cache ∪ yeni blob'lar olarak birleştirilir
// ki taşınan (değişmeyen) anahtarların ciphertext'i de çevrimdışı okumada mevcut
// olsun. ETag, YEREL imzalı sarmalayıcının obje hash'idir (Worker'a güvenmeden).
func (w *WorkerStore) writeThroughCache(project string, signed []byte, newBlobs map[string][]byte, epoch uint64, ring manifest.WriterKeyring, head *trust.VerifiedEpoch, chainWrappers [][]byte) {
	obj, err := manifest.ParseSignedObject(signed)
	if err != nil {
		return
	}
	// Kendi imzamızı ring'e karşı yeniden doğrula (öz-kontrol; bozuksa cache'leme).
	man, err := manifest.VerifyDataManifest(obj, ring)
	if err != nil {
		return
	}
	blobs := map[string][]byte{}
	if prev := w.loadCacheEntry(project); prev != nil {
		for h, b := range prev.Blobs {
			blobs[h] = b
		}
	}
	for h, b := range newBlobs {
		blobs[h] = b
	}
	snap := &VerifiedSnapshot{
		Project:      project,
		Epoch:        epoch,
		ETag:         manifest.ManifestObjectHash(signed),
		Manifest:     man,
		Trust:        head,
		wrapperBytes: signed,
		blobs:        blobs,
		FetchedAt:    w.now().UTC(),
	}
	w.saveCache(project, snap, chainWrappers, head)
}

// commitOK, başarılı commit yanıtıdır.
type commitOK struct {
	epoch          uint64
	manifestSha256 string
	receipt        json.RawMessage
}

// postCommit, imzalı manifest sarmalayıcısını commit rotasına POST eder.
// 412 EPOCH_CONFLICT → CASConflict (döngü rebase eder); 200 → commitOK.
func (w *WorkerStore) postCommit(ctx context.Context, project string, signed []byte, delta ManifestDelta, in intent.Intent) (*commitOK, error) {
	headers := map[string]string{
		"Content-Type":   "application/json",
		"X-Wapps-Intent": string(in),
	}
	r, err := w.do(ctx, http.MethodPost, "/v1/projects/"+project+"/commit", "", signed, headers)
	if err != nil {
		return nil, err // errOffline dahil
	}
	if r.status == http.StatusOK {
		var body struct {
			Epoch          uint64          `json:"epoch"`
			ManifestSha256 string          `json:"manifestSha256"`
			Receipt        json.RawMessage `json:"receipt"`
		}
		if err := json.Unmarshal(r.body, &body); err != nil {
			return nil, clierr.Wrapf(clierr.Internal, err, "commit response malformed")
		}
		return &commitOK{epoch: body.Epoch, manifestSha256: body.ManifestSha256, receipt: body.Receipt}, nil
	}
	if r.status == http.StatusPreconditionFailed {
		return nil, clierr.New(clierr.CASConflict, "epoch conflict")
	}
	return nil, mapHTTPError(r, "commit")
}

// putBlob, tek bir blob'u PUT eder (içerik-adresli, idempotent).
func (w *WorkerStore) putBlob(ctx context.Context, project, hash string, blob []byte, in intent.Intent) error {
	headers := map[string]string{"Content-Type": "application/octet-stream"}
	r, err := w.do(ctx, http.MethodPut, "/v1/projects/"+project+"/blobs/"+hash, "", blob, headers)
	if err != nil {
		return err // errOffline dahil
	}
	if r.status != http.StatusOK {
		return mapHTTPError(r, "put blob")
	}
	return nil
}

// baseState, mevcut manifest durumudur (rebase temeli).
type baseState struct {
	entries []manifest.KeyEntry
	epoch   uint64
	objHash string // current manifest obje hash'i (prevManifestSha256)
	// winnerKeyID/winnerAt, en son yazarın kimliği/zamanı (CAS mesajı için).
	winnerKeyID string
	winnerAt    time.Time
}

// fetchCurrentState, current data manifest'i çeker + DOĞRULAR (sig against ring)
// ve prev entries/epoch/objHash'i döner. 404 → genesis (boş base).
func (w *WorkerStore) fetchCurrentState(ctx context.Context, project string, ring manifest.WriterKeyring) (*baseState, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/projects/"+project+"/manifests/current", "", nil, nil)
	if err != nil {
		return nil, err // errOffline dahil
	}
	if r.status == http.StatusNotFound {
		return &baseState{}, nil // genesis
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "fetch current for write")
	}
	obj, err := manifest.ParseSignedObject(r.body)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "current manifest malformed")
	}
	man, err := manifest.VerifyDataManifest(obj, ring)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "current manifest signature invalid")
	}
	if err := manifest.CheckProject(man, project); err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "current manifest project mismatch")
	}
	bs := &baseState{
		entries:  man.Entries,
		epoch:    man.Epoch,
		objHash:  manifest.ManifestObjectHash(r.body),
		winnerAt: man.CreatedAt,
	}
	if len(obj.Sigs) > 0 {
		bs.winnerKeyID = obj.Sigs[0].KeyID
	}
	return bs, nil
}

// buildManifest, epoch+1 data manifest'ini + yeni blob'ları kurar ve imzalar
// (SPEC §7.9.3 write path). Değişen her anahtar: fresh DEK + re-key (keyVersion
// +1) + wrap-set = requiredRecipients (grant alıcıları device+backup + escrow) +
// zorunlu WrapVerify. Değişmeyen anahtarlar aynen taşınır.
func (w *WorkerStore) buildManifest(project string, head *trust.VerifiedEpoch, base *baseState, delta ManifestDelta) (signed []byte, newBlobs map[string][]byte, newEpoch uint64, err error) {
	prevByName := map[string]manifest.KeyEntry{}
	for _, e := range base.entries {
		prevByName[e.KeyName] = e
	}

	newBlobs = map[string][]byte{}
	// Değişmeyen girdileri kopyala.
	entries := make([]manifest.KeyEntry, 0, len(base.entries)+len(delta.Sets))
	for _, e := range base.entries {
		if _, changed := delta.Sets[e.KeyName]; changed {
			continue // aşağıda yeniden kurulacak
		}
		entries = append(entries, e)
	}

	// Escrow parmak izleri (client pre-flight §9.1).
	escrow := escrowFingerprints(head.Manifest)

	// Değişen/eklenen anahtarları kur.
	setKeys := make([]string, 0, len(delta.Sets))
	for k := range delta.Sets {
		setKeys = append(setKeys, k)
	}
	sort.Strings(setKeys)

	for _, keyName := range setKeys {
		value := delta.Sets[keyName]
		var version uint64 = 1
		if prev, ok := prevByName[keyName]; ok {
			version = prev.KeyVersion + 1 // re-key: tam +1 (§5.4.3 rule 2)
		}
		slot := cryptoid.Slot{Project: project, KeyName: keyName, KeyVersion: version}
		dek, derr := cryptoid.NewDEK()
		if derr != nil {
			return nil, nil, 0, clierr.Wrapf(clierr.Internal, derr, "new DEK")
		}
		blob, berr := cryptoid.SealBlob(value, dek, slot)
		if berr != nil {
			if errors.Is(berr, cryptoid.ErrValueTooLarge) {
				return nil, nil, 0, clierr.Newf(clierr.BlobTooLarge, "value for %q exceeds the 64KB cap", keyName)
			}
			return nil, nil, 0, clierr.Wrapf(clierr.Internal, berr, "seal blob for %q", keyName)
		}
		blobHash := cryptoid.BlobHash(blob)
		newBlobs[blobHash] = blob

		recips, rerr := requiredRecipients(head.Manifest, project, keyName)
		if rerr != nil {
			return nil, nil, 0, rerr
		}
		wraps := make([]manifest.DEKWrap, 0, len(recips))
		haveEscrow := map[string]bool{}
		for _, rc := range recips {
			wrap, werr := cryptoid.SealDEK(dek, rc.recipient, slot)
			if werr != nil {
				return nil, nil, 0, clierr.Wrapf(clierr.Internal, werr, "wrap DEK to recipient for %q", keyName)
			}
			// Zorunlu çift-yollu öz-kontrol (§3.5.5): imzadan ÖNCE.
			if verr := cryptoid.WrapVerify(dek, rc.recipient, slot, wrap); verr != nil {
				return nil, nil, 0, clierr.Wrapf(clierr.Internal, verr, "wrap self-check failed for %q", keyName)
			}
			wraps = append(wraps, manifest.DEKWrap{Recipient: rc.fingerprint, Wrap: wrap})
			if escrow[rc.fingerprint] {
				haveEscrow[rc.fingerprint] = true
			}
		}
		// Client-enforced escrow (§7.9.3): her aktif escrow alıcısı wrap-set'te olmalı.
		for fp := range escrow {
			if !haveEscrow[fp] {
				return nil, nil, 0, clierr.Newf(clierr.EscrowWrapMissing, "key %q missing escrow wrap", keyName)
			}
		}
		entries = append(entries, manifest.KeyEntry{
			KeyName:    keyName,
			KeyVersion: version,
			BlobHash:   blobHash,
			Wraps:      wraps,
		})
	}

	newEpoch = base.epoch + 1
	prevSha := base.objHash
	if base.epoch == 0 {
		prevSha = "" // genesis
	}
	m := &manifest.DataManifest{
		Schema:             manifest.SchemaDataManifest,
		Project:            project,
		Epoch:              newEpoch,
		PrevManifestSha256: prevSha,
		TrustEpoch:         head.Manifest.AdminEpoch,
		CreatedAt:          w.now().UTC(),
		Entries:            entries,
	}
	obj, _, serr := manifest.SignManifest(m, delta.Writer)
	if serr != nil {
		return nil, nil, 0, clierr.Wrapf(clierr.Internal, serr, "sign manifest")
	}
	raw, merr := manifest.MarshalSignedObject(obj)
	if merr != nil {
		return nil, nil, 0, clierr.Wrapf(clierr.Internal, merr, "marshal signed manifest")
	}
	return raw, newBlobs, newEpoch, nil
}

// recipientEntry, gerekli bir alıcının parmak izi + native X25519 recipient'ıdır.
type recipientEntry struct {
	fingerprint string
	recipient   *cryptoid.X25519Recipient
}

// requiredRecipients, §6.2 step 9'un gerekli recipient kümesini kurar (Worker'ın
// requiredRecipients'ıyla AYNI): read-grant'lı her insanın device+backup enc
// anahtarları ∪ read-grant'lı her makinenin device enc anahtarı ∪ escrow. Native
// (age1...) olmayan (plugin/donanım) alıcılar deterministik wrap üretemez →
// donanım wrap yolu G8 kapsamı DIŞINDA (açık hata).
func requiredRecipients(m *trust.TrustManifest, project, keyName string) ([]recipientEntry, error) {
	snap := m.Registry()
	seen := map[string]bool{}
	var out []recipientEntry
	add := func(ek registry.EncKey) error {
		fp := ek.KeyID
		if fp == "" {
			fp = ek.Fingerprint()
		}
		if seen[fp] {
			return nil
		}
		rec, err := cryptoid.ParseX25519Recipient(ek.Pubkey)
		if err != nil {
			return clierr.Newf(clierr.Internal, "recipient %q is a hardware/plugin key; deterministic client wrap not supported (hardware wrap path deferred)", safeCode(ek.Media))
		}
		seen[fp] = true
		out = append(out, recipientEntry{fingerprint: fp, recipient: rec})
		return nil
	}
	for _, id := range m.Identities {
		if id.Status == registry.StatusRevoked {
			continue
		}
		if id.Type != registry.TypeHuman && id.Type != registry.TypeMachine {
			continue
		}
		if !snap.KeyAllowed(id.ID, project, keyName) || !snap.VerbAllowed(id.ID, project, "read") {
			continue
		}
		for _, ek := range id.EncKeys {
			if ek.Status != registry.StatusActive {
				continue
			}
			if id.Type == registry.TypeHuman && ek.Class != registry.EncClassDevice && ek.Class != registry.EncClassBackup {
				continue
			}
			if id.Type == registry.TypeMachine && ek.Class != registry.EncClassDevice {
				continue
			}
			if err := add(ek); err != nil {
				return nil, err
			}
		}
	}
	// Escrow alıcıları.
	for _, id := range m.Identities {
		if id.Type != registry.TypeEscrow || id.Status == registry.StatusRevoked {
			continue
		}
		for _, ek := range id.EncKeys {
			if ek.Status != registry.StatusActive {
				continue
			}
			if err := add(ek); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// escrowFingerprints, aktif escrow enc-key parmak izleri kümesini döner.
func escrowFingerprints(m *trust.TrustManifest) map[string]bool {
	out := map[string]bool{}
	for _, id := range m.Identities {
		if id.Type != registry.TypeEscrow || id.Status == registry.StatusRevoked {
			continue
		}
		for _, ek := range id.EncKeys {
			if ek.Status != registry.StatusActive {
				continue
			}
			fp := ek.KeyID
			if fp == "" {
				fp = ek.Fingerprint()
			}
			out[fp] = true
		}
	}
	return out
}

// winnerTouched, base → newBase arasında kazanan yazarın DOKUNDUĞU anahtar
// adları kümesini döner (eklenen/silinen/değişen blobHash|keyVersion).
func winnerTouched(base, newBase []manifest.KeyEntry) map[string]bool {
	baseByName := map[string]manifest.KeyEntry{}
	for _, e := range base {
		baseByName[e.KeyName] = e
	}
	newByName := map[string]manifest.KeyEntry{}
	for _, e := range newBase {
		newByName[e.KeyName] = e
	}
	touched := map[string]bool{}
	for name, ne := range newByName {
		be, ok := baseByName[name]
		if !ok || be.BlobHash != ne.BlobHash || be.KeyVersion != ne.KeyVersion {
			touched[name] = true
		}
	}
	for name := range baseByName {
		if _, ok := newByName[name]; !ok {
			touched[name] = true // silinen
		}
	}
	return touched
}

// overlaps, kazananın dokunduğu anahtarlar ile bizim set'lerimizin kesişip
// kesişmediğini döner.
func overlaps(winner map[string]bool, sets map[string][]byte) bool {
	for k := range sets {
		if winner[k] {
			return true
		}
	}
	return false
}

// sameKeyConflict, aynı-key CAS çakışması hatasını iki yazarı isimlendirerek
// kurar (SPEC §7.3.5). CLI aynı-key çakışmalarını ASLA auto-merge etmez.
func sameKeyConflict(delta ManifestDelta, base, newBase *baseState) error {
	me := delta.WriterID
	if me == "" {
		me = "self"
	}
	winner := newBase.winnerKeyID
	if winner == "" {
		winner = "unknown"
	}
	recovery := fmt.Sprintf("re-run the command; conflicting writers: %s@%d, %s@%d",
		me, base.epoch, safeCode(winner), newBase.epoch)
	return clierr.New(clierr.CASConflict, "same-key write race; not auto-merged").WithRecovery(recovery)
}

// jitterSleep, rebase denemeleri arasında jittered backoff uygular.
// Deterministik testler için WAPPS_TEST_NO_SLEEP=1 ile atlanabilir.
func jitterSleep(w *WorkerStore, attempt int) {
	if noSleep {
		return
	}
	base := time.Duration(1<<uint(attempt)) * 20 * time.Millisecond
	jitter := time.Duration(rand.Int63n(int64(base) + 1))
	time.Sleep(base/2 + jitter/2)
}

// noSleep, testlerin rebase backoff'unu atlaması için.
var noSleep = strings.EqualFold(os.Getenv("WAPPS_TEST_NO_SLEEP"), "1")
