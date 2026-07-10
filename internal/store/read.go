package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/wappsdev/wapps-cli/internal/cache"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// currentTrustDoc, trust/current objesinin şeklidir (trust-loader.ts ile aynı):
// admin_epoch + doğrulanmış head'in payload hash'i (locator tutarlılığı).
type currentTrustDoc struct {
	AdminEpoch  uint64 `json:"admin_epoch"`
	TrustSHA256 string `json:"trustSha256"`
}

// Fetch, çevrimiçi-first conditional GET ile doğrulanmış bir anlık görüntü döner
// (SPEC §7.3.2). İstemci Worker'a GÜVENMEZ: trust zincirini pinlere karşı, data
// manifest imzasını ring'e karşı, her blob hash'ini içerik-adresine karşı doğrular.
func (w *WorkerStore) Fetch(ctx context.Context, project string, opts FetchOpts) (*VerifiedSnapshot, error) {
	in, err := intent.Parse(string(opts.Intent))
	if err != nil {
		return nil, err
	}

	pins, err := w.loadPins()
	if err != nil {
		return nil, err
	}

	// --- Trust head (çevrimiçi) --------------------------------------------
	head, chainWrappers, err := w.fetchTrustHead(ctx, pins)
	if errors.Is(err, errOffline) {
		return w.fetchOffline(ctx, project, opts, in, pins)
	}
	if err != nil {
		return nil, err
	}
	ring := dataWriterKeyring(head.Manifest)

	// --- Data manifest (conditional GET) -----------------------------------
	prev := w.loadCacheEntry(project) // nil olabilir
	inm := ""
	if prev != nil {
		inm = prev.ETag
	}
	r, err := w.do(ctx, http.MethodGet, "/v1/projects/"+project+"/manifests/current", inm, nil, nil)
	if errors.Is(err, errOffline) {
		return w.fetchOffline(ctx, project, opts, in, pins)
	}
	if err != nil {
		return nil, err
	}

	var wrapperBytes []byte
	var etag string
	switch r.status {
	case http.StatusNotModified: // 304 — önbellekteki manifest'i YEREL yeniden doğrula
		if prev == nil {
			return nil, clierr.New(clierr.Internal, "worker returned 304 without a cached manifest")
		}
		wrapperBytes = prev.ManifestWrapper
		etag = prev.ETag
	case http.StatusOK: // 200
		wrapperBytes = r.body
		etag = r.etag
		if etag == "" {
			etag = manifest.ManifestObjectHash(wrapperBytes)
		}
		// Locator tutarlılığı: dönen ETag, obje baytlarının hash'i olmalı.
		if manifest.ManifestObjectHash(wrapperBytes) != etag {
			return nil, clierr.New(clierr.SigInvalid, "manifest object hash does not match ETag")
		}
	default:
		return nil, mapHTTPError(r, "fetch manifest")
	}

	// İmza + zincir doğrulaması (verify-before-parse, §3.6.3).
	obj, err := manifest.ParseSignedObject(wrapperBytes)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "manifest wrapper malformed")
	}
	man, err := manifest.VerifyDataManifest(obj, ring)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "manifest signature invalid")
	}
	if err := manifest.CheckProject(man, project); err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "manifest project mismatch")
	}

	// --- Yazar yetkisi (defense-in-depth §6.2 step 8; İstemci Worker'a GÜVENMEZ) ---
	// YALNIZCA TAZE (200) manifest'te: 304/çevrimdışı manifest önceki bir okumada
	// zaten yetki-doğrulandı (cache'e yalnızca bu kontrolü geçtikten sonra yazılır).
	// İmzalayan, önceki epoch'a göre DEĞİŞEN her anahtar için yazma yetkisine sahip
	// olmalı; compromised bir Worker düşük-yetkili bir yazar imzasıyla yetkisiz
	// anahtarlara taşan (overreach) bir manifest sunamaz. Epoch pin'i İLERLETMEDEN
	// ÖNCE çalışır ki bir çevrimdışı-fallback pin'i bozmasın (P3-b).
	if r.status == http.StatusOK {
		if err := w.verifyWriterAuthorityOnline(ctx, project, head.Manifest, ring, obj, man); err != nil {
			if errors.Is(err, errOffline) {
				return w.fetchOffline(ctx, project, opts, in, pins)
			}
			return nil, err
		}
	}

	// Epoch pin: monotonik, forward-only (sunulan < pinned → EPOCH_DOWNGRADE).
	if err := w.checkAndAdvanceEpochPin(project, man.Epoch); err != nil {
		return nil, err
	}

	// --- Blob'lar (yalnızca kapsam anahtarları, blast-radius min §7.3.3) ----
	scope := scopeKeys(man, opts.Keys)
	blobs := map[string][]byte{}
	if prev != nil {
		for h, b := range prev.Blobs {
			blobs[h] = b
		}
	}
	for _, e := range man.Entries {
		if !scope[e.KeyName] {
			continue
		}
		if _, ok := blobs[e.BlobHash]; ok {
			continue // önbellekten geldi
		}
		br, err := w.do(ctx, http.MethodGet, "/v1/projects/"+project+"/blobs/"+e.BlobHash, "", nil, nil)
		if errors.Is(err, errOffline) {
			return w.fetchOffline(ctx, project, opts, in, pins)
		}
		if err != nil {
			return nil, err
		}
		if br.status != http.StatusOK {
			return nil, mapHTTPError(br, "fetch blob")
		}
		if err := cryptoid.VerifyBlobHash(br.body, e.BlobHash); err != nil {
			return nil, clierr.Wrapf(clierr.BlobHashMismatch, err, "blob %s content-address mismatch", safeCode(e.BlobHash))
		}
		blobs[e.BlobHash] = br.body
	}

	// --- Deploy intent: liveness receipt (fresh-or-fail) --------------------
	var receipt *intent.Receipt
	if in == intent.Deploy {
		rec, err := w.verifyDeployReceipt(ctx, project, head, etag, man.Epoch)
		if err != nil {
			return nil, err
		}
		receipt = rec
		// Escrow-tanık çapraz kontrolü (§7.3.4/§9.3): deploy witness-blind İLERLEYEMEZ
		// (F6 fail-closed). Non-nil bir Witness ZORUNLU — wire edilmemişse fail-closed,
		// böylece stub SESSİZCE witness-blind bir deploy YAPAMAZ (G10 gerçek non-CF
		// origin'i enjekte edecek) (P3-a).
		if w.cfg.Witness == nil {
			return nil, clierr.New(clierr.WitnessNotWired,
				"deploy intent requires an escrow witness; none is wired")
		}
		if err := intent.CheckWitness(w.cfg.Witness, man.Epoch); err != nil {
			return nil, err
		}
	}

	snap := &VerifiedSnapshot{
		Project:      project,
		Epoch:        man.Epoch,
		ETag:         etag,
		Manifest:     man,
		Trust:        head,
		wrapperBytes: wrapperBytes,
		blobs:        blobs,
		Receipt:      receipt,
		FetchedAt:    w.now().UTC(),
	}

	// --- Write-through cache (ciphertext-only) ------------------------------
	w.saveCache(project, snap, chainWrappers, head)
	return snap, nil
}

// scopeKeys, kapsam anahtar kümesini döner: keys boşsa manifest'teki TÜM
// anahtarlar; doluysa yalnızca istenenler (profil∩grant daraltması çağırandan).
func scopeKeys(man *manifest.DataManifest, keys []string) map[string]bool {
	scope := map[string]bool{}
	if len(keys) == 0 {
		for _, e := range man.Entries {
			scope[e.KeyName] = true
		}
		return scope
	}
	for _, k := range keys {
		scope[k] = true
	}
	return scope
}

// verifyDeployReceipt, deploy-intent liveness receipt'ini çeker + doğrular.
func (w *WorkerStore) verifyDeployReceipt(ctx context.Context, project string, head *trust.VerifiedEpoch, manifestSha string, epoch uint64) (*intent.Receipt, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/projects/"+project+"/receipt", "", nil, nil)
	if errors.Is(err, errOffline) {
		return nil, clierr.New(clierr.StaleReceipt, "deploy intent: worker unreachable for liveness receipt")
	}
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "fetch receipt")
	}
	var rec intent.Receipt
	if err := json.Unmarshal(r.body, &rec); err != nil {
		return nil, clierr.Wrapf(clierr.StaleReceipt, err, "receipt body malformed")
	}
	pinnedEpoch, err := w.pinnedEpoch(project)
	if err != nil {
		return nil, err
	}
	if _, err := intent.VerifyReceipt(rec, head.Manifest.WorkerReceiptPub.JWK, manifestSha, pinnedEpoch, w.now()); err != nil {
		return nil, err
	}
	return &rec, nil
}

// --- Yazar yetkisi (defense-in-depth §6.2 step 8) ---------------------------

// authzWriteVerb, §6.3 yazma verb'üdür (Worker writer-do.ts AUTHZ_WRITE_VERB ile
// aynı: read|write|rotate kümesinden "write").
const authzWriteVerb = "write"

// verifyWriterAuthorityOnline, TAZE (200) bir data manifest için imzalayanın,
// önceki epoch'a göre DEĞİŞEN her anahtar üzerinde yazma yetkisine sahip olduğunu
// doğrular (İstemci Worker'a GÜVENMEZ). Değişen küme, chain-bağlı bir önceki
// manifest'e (epoch-1) karşı diff'lenir; genesis'te (epoch 1) tüm girdiler
// "eklenen" sayılır. Önceki manifest getirilirken çevrimdışıya düşülürse errOffline
// yayılır (çağıran çevrimdışı-fallback'e geçer).
func (w *WorkerStore) verifyWriterAuthorityOnline(ctx context.Context, project string, tm *trust.TrustManifest, ring manifest.WriterKeyring, obj manifest.SignedObject, man *manifest.DataManifest) error {
	touched := map[string]bool{}
	if man.Epoch <= 1 {
		// Genesis: tüm girdiler yazar tarafından oluşturuldu → hepsi kontrol edilir.
		for _, e := range man.Entries {
			touched[e.KeyName] = true
		}
	} else {
		prevMan, prevWrapper, err := w.fetchVerifiedManifestAt(ctx, project, man.Epoch-1, ring)
		if err != nil {
			return err // errOffline dahil
		}
		// Chain-bağı: getirilen "prev" GERÇEKTEN current'ın öncülü olmalı (§5.5) —
		// aksi halde Worker sahte bir önceki manifest ile diff'i masumlaştırabilir.
		if err := manifest.VerifyChainLink(prevWrapper, man.Epoch-1, man); err != nil {
			return clierr.Wrapf(clierr.SigInvalid, err, "prior manifest does not chain to current")
		}
		touched = winnerTouched(prevMan.Entries, man.Entries)
	}
	return verifyWriterAuthority(tm, project, obj, touched)
}

// fetchVerifiedManifestAt, belirli bir epoch'un data manifest'ini çeker ve DOĞRULAR
// (imza ring'e karşı + proje eşleşmesi). Doğrulanmış manifest + TAM sarmalayıcı
// baytlarını (chain-bağı kontrolü için) döner.
func (w *WorkerStore) fetchVerifiedManifestAt(ctx context.Context, project string, epoch uint64, ring manifest.WriterKeyring) (*manifest.DataManifest, []byte, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/projects/"+project+"/manifests/"+itoa(epoch), "", nil, nil)
	if err != nil {
		return nil, nil, err // errOffline dahil
	}
	if r.status != http.StatusOK {
		return nil, nil, mapHTTPError(r, "fetch prior manifest")
	}
	obj, err := manifest.ParseSignedObject(r.body)
	if err != nil {
		return nil, nil, clierr.Wrapf(clierr.SigInvalid, err, "prior manifest malformed")
	}
	man, err := manifest.VerifyDataManifest(obj, ring)
	if err != nil {
		return nil, nil, clierr.Wrapf(clierr.SigInvalid, err, "prior manifest signature invalid")
	}
	if err := manifest.CheckProject(man, project); err != nil {
		return nil, nil, clierr.Wrapf(clierr.SigInvalid, err, "prior manifest project mismatch")
	}
	return man, r.body, nil
}

// verifyWriterAuthority, imzalayanın (obj.Sigs[0].KeyID → sahibi kimlik) touched
// anahtar kümesinin HER biri üzerinde yazma yetkisine sahip olduğunu, imzalı
// roster/registry'ye karşı doğrular (Worker writer-do.ts step 8 ile AYNI model):
// otomasyon yazarları writer_allowlists ile, insan yazarları "write" verb-grant'ı
// ile. Taşma (overreach) → WRITER_NOT_ALLOWED.
func verifyWriterAuthority(tm *trust.TrustManifest, project string, obj manifest.SignedObject, touched map[string]bool) error {
	if len(touched) == 0 {
		return nil
	}
	if len(obj.Sigs) == 0 {
		// VerifyDataManifest tam 1 imza garanti eder; savunmacı kontrol.
		return clierr.New(clierr.SigInvalid, "data manifest carries no signature")
	}
	principal, isAutomation, ok := resolveWriterPrincipal(tm, obj.Sigs[0].KeyID)
	if !ok {
		return clierr.New(clierr.SigInvalid, "data manifest writer key is not in the roster")
	}
	reg := tm.Registry()
	for key := range touched {
		var allowed bool
		if isAutomation {
			allowed = reg.WriterKeyAllowed(principal, project, key)
		} else {
			allowed = reg.VerbAllowed(principal, project, authzWriteVerb) && reg.KeyAllowed(principal, project, key)
		}
		if !allowed {
			return clierr.Newf(clierr.WriterNotAllowed, "manifest writer lacks write authority for key %s", safeCode(key))
		}
	}
	return nil
}

// resolveWriterPrincipal, bir imza key_id'sini (§3.7 parmak izi) sahibi kimliğe
// eşler ve otomasyon (automation-class) yazar olup olmadığını döner. Eşleşme
// HER ZAMAN pubkey'den türetilen parmak izi üzerinden yapılır (self-declared
// key_id'ye güvenilmez). Yalnızca aktif kimlik + aktif imzalama anahtarı sayılır.
func resolveWriterPrincipal(tm *trust.TrustManifest, keyID string) (principal string, isAutomation bool, ok bool) {
	for _, id := range tm.Identities {
		if id.Status == registry.StatusRevoked {
			continue
		}
		for _, sk := range id.SigningKeys {
			if sk.Status != registry.StatusActive {
				continue
			}
			fp, err := sk.Fingerprint()
			if err != nil {
				continue
			}
			if fp == keyID {
				return id.ID, sk.Class == registry.SignClassAutomation, true
			}
		}
	}
	return "", false, false
}

// --- Trust head loading -----------------------------------------------------

// fetchTrustHead, trust/current + genesis→head zincirini çeker ve M-of-N
// doğrular (SPEC §4.5, trust-loader.ts ile aynı algoritma; ama İSTEMCİ pinlere
// dayanır). Doğrulanmış head + zincir sarmalayıcıları (cache için) döner.
func (w *WorkerStore) fetchTrustHead(ctx context.Context, pins *trust.PinStore) (*trust.VerifiedEpoch, [][]byte, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/trust/current", "", nil, nil)
	if err != nil {
		return nil, nil, err // errOffline dahil
	}
	if r.status != http.StatusOK {
		return nil, nil, mapHTTPError(r, "fetch trust/current")
	}
	var doc currentTrustDoc
	if err := json.Unmarshal(r.body, &doc); err != nil || doc.AdminEpoch < 1 {
		return nil, nil, clierr.New(clierr.SigInvalid, "trust/current malformed")
	}
	chain := make([]cryptoid.SignedObject, 0, doc.AdminEpoch)
	wrappers := make([][]byte, 0, doc.AdminEpoch)
	for e := uint64(1); e <= doc.AdminEpoch; e++ {
		tr, err := w.do(ctx, http.MethodGet, "/v1/trust/"+itoa(e), "", nil, nil)
		if err != nil {
			return nil, nil, err
		}
		if tr.status != http.StatusOK {
			return nil, nil, mapHTTPError(tr, "fetch trust epoch")
		}
		obj, err := manifest.ParseSignedObject(tr.body)
		if err != nil {
			return nil, nil, clierr.Wrapf(clierr.SigInvalid, err, "trust epoch %d malformed", e)
		}
		chain = append(chain, obj)
		wrappers = append(wrappers, tr.body)
	}
	head, err := trust.VerifyRosterChain(pins.Genesis, pins.LastVerified, chain...)
	if err != nil {
		return nil, nil, clierr.Wrapf(clierr.SigInvalid, err, "trust chain verification failed")
	}
	if doc.TrustSHA256 != "" && head.BytesSHA256 != doc.TrustSHA256 {
		return nil, nil, clierr.New(clierr.SigInvalid, "trust/current points to a different epoch than the verified head")
	}
	// last_verified pin'i ilerlet (monotonik) ve kaydet.
	if err := w.advancePin(pins, head); err != nil {
		return nil, nil, err
	}
	return head, wrappers, nil
}

// --- Offline fallback -------------------------------------------------------

// fetchOffline, çevrimdışı okuma yolunu uygular (SPEC §7.3.4): doğrulanmış
// önbelleğe düşer (dev, ≤24h) veya fail-closed (deploy). Önbellek yeniden
// doğrulanır — pinlere karşı trust, ring'e karşı manifest, blob hash'leri.
func (w *WorkerStore) fetchOffline(ctx context.Context, project string, opts FetchOpts, in intent.Intent, pins *trust.PinStore) (*VerifiedSnapshot, error) {
	_ = ctx
	ent := w.loadCacheEntry(project)
	if ent == nil {
		if in == intent.Deploy {
			return nil, clierr.New(clierr.StaleReceipt, "deploy intent: offline and no verified cache")
		}
		return nil, clierr.New(clierr.CacheStale, "offline and no verified cache for this project")
	}

	// Trust'ı önbellekteki zincirden pinlere karşı yeniden doğrula.
	chain := make([]cryptoid.SignedObject, 0, len(ent.TrustChain))
	for i, raw := range ent.TrustChain {
		obj, err := manifest.ParseSignedObject(raw)
		if err != nil {
			return nil, clierr.Wrapf(clierr.SigInvalid, err, "cached trust epoch %d malformed", i+1)
		}
		chain = append(chain, obj)
	}
	head, err := trust.VerifyRosterChain(pins.Genesis, pins.LastVerified, chain...)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "cached trust chain verification failed")
	}
	ring := dataWriterKeyring(head.Manifest)

	obj, err := manifest.ParseSignedObject(ent.ManifestWrapper)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "cached manifest malformed")
	}
	man, err := manifest.VerifyDataManifest(obj, ring)
	if err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "cached manifest signature invalid")
	}
	if err := manifest.CheckProject(man, project); err != nil {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "cached manifest project mismatch")
	}
	if err := w.checkAndAdvanceEpochPin(project, man.Epoch); err != nil {
		return nil, err
	}

	// Intent tazelik: dev ≤24h uyarıyla; deploy fail-closed.
	age := w.now().UTC().Sub(ent.FetchedAt)
	warn, err := intent.EvaluateOfflineRead(in, age, len(man.Entries), ent.FetchedAt)
	if err != nil {
		return nil, err
	}

	snap := &VerifiedSnapshot{
		Project:      project,
		Epoch:        man.Epoch,
		ETag:         ent.ETag,
		Manifest:     man,
		Trust:        head,
		wrapperBytes: ent.ManifestWrapper,
		blobs:        ent.Blobs,
		FetchedAt:    ent.FetchedAt,
		FromCache:    true,
	}
	if warn != "" {
		snap.Warnings = append(snap.Warnings, warn)
	}
	return snap, nil
}

// --- Cache helpers ----------------------------------------------------------

func (w *WorkerStore) cacheDir() (string, error) {
	if w.cfg.CacheDir != "" {
		return w.cfg.CacheDir, nil
	}
	return cache.DefaultDir()
}

func (w *WorkerStore) loadCacheEntry(project string) *cache.Entry {
	dir, err := w.cacheDir()
	if err != nil {
		return nil
	}
	ent, err := cache.Load(cache.PathFor(dir, project))
	if err != nil {
		return nil
	}
	return ent
}

// saveCache, doğrulanmış anlık görüntüyü ciphertext-only olarak yazar. Hata
// best-effort loglanmaz (önbellek bir optimizasyon; okuma başarısız SAYILMAZ).
func (w *WorkerStore) saveCache(project string, snap *VerifiedSnapshot, chainWrappers [][]byte, head *trust.VerifiedEpoch) {
	dir, err := w.cacheDir()
	if err != nil {
		return
	}
	var receiptRaw json.RawMessage
	if snap.Receipt != nil {
		if b, err := json.Marshal(snap.Receipt); err == nil {
			receiptRaw = b
		}
	}
	ent := &cache.Entry{
		Schema:          cache.Schema,
		Project:         project,
		Epoch:           snap.Epoch,
		ManifestWrapper: snap.wrapperBytes,
		ETag:            snap.ETag,
		Blobs:           snap.blobs,
		TrustChain:      chainWrappers,
		TrustEpoch:      head.Manifest.AdminEpoch,
		TrustSHA256:     head.BytesSHA256,
		Receipt:         receiptRaw,
		FetchedAt:       snap.FetchedAt,
	}
	_ = ent.Save(cache.PathFor(dir, project))
}

// --- Pin helpers ------------------------------------------------------------

// loadPins, trust pin deposunu (roots.json) yükler; yoksa derlenmiş genesis'ten
// bootstrap eder. Hiçbiri yoksa TRUST_PIN_MISSING → SIG_INVALID.
func (w *WorkerStore) loadPins() (*trust.PinStore, error) {
	path, err := w.pinPath()
	if err != nil {
		return nil, err
	}
	ps, err := trust.LoadPinStore(path)
	if err == nil {
		return ps, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, clierr.Wrapf(clierr.SigInvalid, err, "load trust pins")
	}
	if g, ok := trust.CompiledGenesis(); ok {
		return trust.NewPinStore(g), nil
	}
	return nil, clierr.New(clierr.SigInvalid, "no trust pins and no compiled genesis")
}

func (w *WorkerStore) pinPath() (string, error) {
	if w.cfg.PinPath != "" {
		return w.cfg.PinPath, nil
	}
	return trust.DefaultPinPath()
}

// advancePin, doğrulanmış head'e last_verified'ı ilerletir ve kaydeder.
func (w *WorkerStore) advancePin(pins *trust.PinStore, head *trust.VerifiedEpoch) error {
	if err := pins.AdvanceLastVerified(head.Pin()); err != nil {
		return clierr.Wrapf(clierr.EpochDowngrade, err, "advance trust pin")
	}
	path, err := w.pinPath()
	if err != nil {
		return err
	}
	if err := pins.Save(path); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "persist trust pin")
	}
	return nil
}

// itoa, uint64 → decimal string (küçük yardımcı; strconv importunu tek yerde tut).
func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
