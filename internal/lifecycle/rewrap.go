package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// AttestSchema, "fully rotated at epoch N" attestation şeması (SPEC §8.5.3 step 4).
const AttestSchema = "wapps.offboard.attest/1"

// RewrapRequest, rewrap motorunun girdisidir (SPEC §3.8.1/§3.8.2, §8.5.3). Motor,
// OTORİTATİF trust head'inden per-key gereken alıcı kümesini türetir ve mevcut
// wrap-set ile diff'leyerek her anahtar için modu OTOMATİK saptar:
//   - hedef ⊇ mevcut (yalnızca eklenecek alıcı)  → ADD  = manifest-only wrap (§3.8.1)
//   - mevcut, hedefte olmayan alıcı taşıyorsa      → REMOVE = yeni DEK + re-encrypt (§3.8.2)
type RewrapRequest struct {
	// Project, rewrap edilen proje.
	Project string
	// TrustHead, DEĞİŞİKLİK SONRASI (grant/revoke landlenmiş) doğrulanmış trust
	// head'i — gereken alıcı kümesinin TEK gerçek kaynağı.
	TrustHead *trust.VerifiedEpoch
	// Reader, MEVCUT DEK'leri açabilen KALAN bir okuyucu kimliği (admin cihazı,
	// escrow veya backup). ASLA ayrılan prensip olamaz (§8.5: ≥2 admin).
	Reader *cryptoid.X25519Identity
	// ReaderFingerprint, Reader'ın alıcı parmak izi; boşsa Reader'dan türetilir.
	ReaderFingerprint string
	// Writer, epoch+1 manifest'lerini imzalayan hardware daily / automation anahtarı.
	Writer cryptoid.SigningKey
	// WriterID, Writer'ın sahibi principal id (ledger `by` alanı).
	WriterID string
	// Removed, kaldırılan alıcı parmak izleri (REMOVE doğrulaması + attestation).
	// Boş olabilir (saf ADD). Reader bunlardan biri OLAMAZ.
	Removed []string
	// LedgerKey, per-key completion ledger anahtarı (§8.5.3); boşsa üretilir.
	LedgerKey string
	// RecordID, attestation'a gömülecek offboard record_id (opsiyonel).
	RecordID string
}

// RewrapLedgerRow, per-key completion ledger'ının bir satırıdır (SPEC §8.5.3).
type RewrapLedgerRow struct {
	Project     string    `json:"project"`
	Key         string    `json:"key"`
	OldEpoch    uint64    `json:"old_epoch"`
	NewEpoch    uint64    `json:"new_epoch"`
	DEKReminted bool      `json:"dek_reminted"`
	BlobSHA256  string    `json:"blob_sha256"`
	At          time.Time `json:"at"`
	By          string    `json:"by"`
}

// RotationAttestation, bir projenin rewrap'i tamamlandığında admin'in imzaladığı
// "fully rotated at epoch N" beyanıdır (SPEC §8.5.3 step 4). Escrow VM verifier
// (§9) her saatlik pull'da bu değişmezi ≥N tüm epoch'lar için doğrular.
type RotationAttestation struct {
	Schema    string    `json:"schema"`
	RecordID  string    `json:"record_id,omitempty"`
	Project   string    `json:"project"`
	Epoch     uint64    `json:"epoch"`
	Statement string    `json:"statement"`
	KeyCount  int       `json:"key_count"`
	At        time.Time `json:"at"`
}

// RewrapResult, bir rewrap çalışmasının sonucudur.
type RewrapResult struct {
	Project     string
	StartEpoch  uint64
	FinalEpoch  uint64
	KeysAdd     int // wrap-only ADD uygulanan anahtar sayısı
	KeysRemint  int // yeni DEK basılan (REMOVE) anahtar sayısı
	KeysSkipped int // hedefi zaten karşılayan anahtar sayısı (idempotent/resume)
	PerKey      []RewrapLedgerRow
	// FullyRotated, HİÇBİR girdinin herhangi bir Removed alıcıya wrap taşımadığı
	// (100%) durumdur — "alarming until 100%" (§8.5.3).
	FullyRotated bool
	// RemovedGone, her Removed parmak izinin artık her girdiden dışlandığını gösterir.
	RemovedGone map[string]bool
	// Attestation, Removed dolu + FullyRotated ise üretilir (§8.5.3 step 4).
	Attestation *RotationAttestation
}

// Rewrap, verilen trust head'ine karşı bir projenin wrap-set'lerini yeniden kurar
// (SPEC §3.8.1/§3.8.2). İDEMPOTENT + RESUMABLE: her anahtar tek bir epoch'ta
// (per-key) CAS ile commit edilir; bir kesintiden sonra Rewrap yeniden çağrıldığında
// current manifest'ten kalan işi yeniden türetir (ledger-driven değil,
// manifest-driven — daha güçlü). Bir anahtar SKIP edilir ancak-ve-ancak mevcut
// wrap-set zaten hedefi karşılıyorsa (Removed alıcı yok + gereken alıcılar var).
func (e *Engine) Rewrap(req RewrapRequest) (*RewrapResult, error) {
	if req.TrustHead == nil {
		return nil, fmt.Errorf("lifecycle.Rewrap: nil trust head")
	}
	if req.Reader == nil {
		return nil, fmt.Errorf("lifecycle.Rewrap: nil reader identity")
	}
	if req.Writer == nil {
		return nil, fmt.Errorf("lifecycle.Rewrap: nil writer")
	}
	readerFP := req.ReaderFingerprint
	if readerFP == "" {
		readerFP = req.Reader.Fingerprint()
	}
	removedSet := map[string]bool{}
	for _, fp := range req.Removed {
		removedSet[fp] = true
	}
	// Okuyucu ASLA kaldırılan (ayrılan) taraf olamaz — ayrılan tek çalıştırıcı olamaz
	// (§8.5, kripto-katmanı yaptırımı).
	if removedSet[readerFP] {
		return nil, ErrDepartingRunner
	}

	ledgerKey := req.LedgerKey
	if ledgerKey == "" {
		ledgerKey = "rewrap/" + req.Project + "/ledger.jsonl"
	}

	// Mevcut durumu çek.
	wrapper, blobs, epoch, objHash, ok, err := e.cfg.Data.CurrentManifest(req.Project)
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Rewrap: fetch current: %w", err)
	}
	res := &RewrapResult{Project: req.Project, StartEpoch: epoch, FinalEpoch: epoch, RemovedGone: map[string]bool{}}
	if !ok {
		// Henüz veri yok → rewrap edilecek bir şey yok; hiçbir Removed alıcı bir şey
		// okuyamaz → tam rotasyon (boş küme).
		res.FullyRotated = true
		for fp := range removedSet {
			res.RemovedGone[fp] = true
		}
		return res, nil
	}

	ring := buildWriterKeyring(req.TrustHead.Manifest)
	obj, perr := manifest.ParseSignedObject(wrapper)
	if perr != nil {
		return nil, fmt.Errorf("lifecycle.Rewrap: parse current: %w", perr)
	}
	man, verr := manifest.VerifyDataManifest(obj, ring)
	if errors.Is(verr, manifest.ErrWriterUnknown) {
		// Mevcut manifest'in yazarı bu rewrap'in trust değişikliğiyle emekliye
		// ayrılmış olabilir; manifest yazım anında ÖNCEKİ epoch altında imza-geçerliydi
		// ve GÜVENDİĞİMİZ commit edilmiş durumdur → body'yi doğrudan parse et.
		man, verr = manifest.ParseManifestBody(obj.Bytes)
	}
	if verr != nil {
		return nil, fmt.Errorf("lifecycle.Rewrap: verify current: %w", verr)
	}

	// Çalışan girdi kümesi (her commit'ten sonra yerinde güncellenir).
	working := make([]manifest.KeyEntry, len(man.Entries))
	copy(working, man.Entries)
	byName := func(name string) int {
		for i := range working {
			if working[i].KeyName == name {
				return i
			}
		}
		return -1
	}

	names := make([]string, len(working))
	for i, e0 := range working {
		names[i] = e0.KeyName
	}
	sort.Strings(names)

	escrow := escrowFingerprints(req.TrustHead.Manifest)

	for _, name := range names {
		idx := byName(name)
		entry := working[idx]
		target, terr := RequiredRecipients(req.TrustHead.Manifest, req.Project, name)
		if terr != nil {
			return nil, fmt.Errorf("lifecycle.Rewrap: required recipients for %q: %w", name, terr)
		}
		targetFPs := fingerprintSet(target)
		curFPs := wrapFingerprints(entry)

		var toAdd []Recipient
		for _, r := range target {
			if !curFPs[r.Fingerprint] {
				toAdd = append(toAdd, r)
			}
		}
		hasRemove := false
		for fp := range curFPs {
			if !targetFPs[fp] {
				hasRemove = true
				break
			}
		}

		if !hasRemove && len(toAdd) == 0 {
			res.KeysSkipped++ // hedefi zaten karşılıyor (idempotent/resume)
			continue
		}

		var newEntry manifest.KeyEntry
		var newBlob []byte
		reminted := false
		if hasRemove {
			newEntry, newBlob, err = e.remintEntry(req, name, entry, target, blobs, readerFP)
			reminted = true
		} else {
			newEntry, err = e.addWraps(req, name, entry, toAdd, readerFP)
		}
		if err != nil {
			return nil, err
		}

		// Yeni epoch manifest'ini kur (tüm girdiler; bu anahtar değiştirildi).
		nextEntries := make([]manifest.KeyEntry, len(working))
		copy(nextEntries, working)
		nextEntries[idx] = newEntry

		newEpoch := epoch + 1
		prevSha := objHash
		m := &manifest.DataManifest{
			Schema:             manifest.SchemaDataManifest,
			Project:            req.Project,
			Epoch:              newEpoch,
			PrevManifestSha256: prevSha,
			TrustEpoch:         req.TrustHead.Manifest.AdminEpoch,
			CreatedAt:          e.now(),
			Entries:            nextEntries,
		}
		// Client-enforced escrow (§9.1): her girdinin wrap-set'inde escrow olmalı.
		for fp := range escrow {
			if cerr := manifest.CheckEscrowWraps(m, fp); cerr != nil {
				return nil, fmt.Errorf("lifecycle.Rewrap: %w", cerr)
			}
		}
		signed, sobj, serr := manifest.SignManifest(m, req.Writer)
		if serr != nil {
			return nil, fmt.Errorf("lifecycle.Rewrap: sign %q: %w", name, serr)
		}
		_ = sobj
		raw, merr := manifest.MarshalSignedObject(signed)
		if merr != nil {
			return nil, fmt.Errorf("lifecycle.Rewrap: marshal %q: %w", name, merr)
		}
		// Öz-doğrulama: ürettiğimiz manifest yazar ring'ine karşı geçmeli (Writer
		// head'de aktif olmalı).
		if _, cverr := manifest.VerifyDataManifest(signed, ring); cverr != nil {
			return nil, fmt.Errorf("lifecycle.Rewrap: self-verify %q: %w", name, cverr)
		}

		// REMOVE ise yeni blob'u PUT et (ADD wrap-only → blob değişmez, PUT yok).
		if reminted {
			if perr := e.cfg.Data.PutBlob(req.Project, newEntry.BlobHash, newBlob); perr != nil {
				return nil, fmt.Errorf("lifecycle.Rewrap: put blob %q: %w", name, perr)
			}
		}

		// CAS commit. Bir yarış (ErrCASConflict) veya taşıma kesintisi RESUME ile
		// kurtarılır (§8.5.3: iki admin DO tarafından serileştirilir; motor resume'a
		// dayanır) — yeniden çağrıldığında current'tan kalan işi türetir. Bu yüzden
		// burada in-line rebase YOK; hata yayılır, caller/offboard --resume eder.
		if cerr := e.cfg.Data.CommitManifest(req.Project, raw, prevSha); cerr != nil {
			return nil, fmt.Errorf("lifecycle.Rewrap: commit %q: %w", name, cerr)
		}

		// Commit başarılı: çalışan durumu ilerlet.
		working = nextEntries
		epoch = newEpoch
		objHash = manifest.ManifestObjectHash(raw)
		res.FinalEpoch = newEpoch
		if reminted {
			res.KeysRemint++
		} else {
			res.KeysAdd++
		}
		row := RewrapLedgerRow{
			Project:     req.Project,
			Key:         name,
			OldEpoch:    entry.KeyVersion, // önceki keyVersion (girdinin sürümü)
			NewEpoch:    newEntry.KeyVersion,
			DEKReminted: reminted,
			BlobSHA256:  newEntry.BlobHash,
			At:          e.now(),
			By:          req.WriterID,
		}
		res.PerKey = append(res.PerKey, row)
		if line, jerr := json.Marshal(row); jerr == nil {
			_ = e.cfg.Records.AppendLedger(ledgerKey, line)
		}
	}

	// Tam-rotasyon değişmezi: hiçbir girdi herhangi bir Removed alıcıya wrap taşımamalı.
	res.FullyRotated = true
	for fp := range removedSet {
		gone := true
		for _, en := range working {
			if wrapFingerprints(en)[fp] {
				gone = false
				break
			}
		}
		res.RemovedGone[fp] = gone
		if !gone {
			res.FullyRotated = false
		}
	}
	if len(removedSet) > 0 && res.FullyRotated {
		res.Attestation = &RotationAttestation{
			Schema:    AttestSchema,
			RecordID:  req.RecordID,
			Project:   req.Project,
			Epoch:     res.FinalEpoch,
			Statement: "no manifest with epoch >= N wraps any DEK to a removed recipient",
			KeyCount:  len(working),
			At:        e.now(),
		}
	}
	return res, nil
}

// remintEntry, REMOVE yolu (§3.8.2): mevcut değeri okuyucuyla çöz, TAZE DEK bas,
// keyVersion+1 ile yeniden şifrele (taze nonce), hedef alıcı kümesine (kaldırılanlar
// HARİÇ, escrow+backup DAHİL) yeniden wrap'le. Yeni girdi + yeni blob döner.
func (e *Engine) remintEntry(req RewrapRequest, name string, entry manifest.KeyEntry, target []Recipient, blobs map[string][]byte, readerFP string) (manifest.KeyEntry, []byte, error) {
	// 1) Mevcut DEK'i okuyucuyla aç.
	dek0, err := unwrapWith(entry, readerFP, req.Reader)
	if err != nil {
		return manifest.KeyEntry{}, nil, err
	}
	// 2) Mevcut değeri çöz.
	blob0, ok := blobs[entry.BlobHash]
	if !ok {
		return manifest.KeyEntry{}, nil, fmt.Errorf("lifecycle.Rewrap: blob for %q not available", name)
	}
	if err := cryptoid.VerifyBlobHash(blob0, entry.BlobHash); err != nil {
		return manifest.KeyEntry{}, nil, fmt.Errorf("lifecycle.Rewrap: blob hash %q: %w", name, err)
	}
	slot0 := cryptoid.Slot{Project: req.Project, KeyName: name, KeyVersion: entry.KeyVersion}
	pt, err := cryptoid.OpenBlob(blob0, dek0, slot0)
	if err != nil {
		return manifest.KeyEntry{}, nil, fmt.Errorf("lifecycle.Rewrap: open blob %q: %w", name, err)
	}
	// 3) TAZE DEK + yeni sürüm + yeniden şifrele (§3.8.2: keyVersion MUTLAKA artar).
	newVersion := entry.KeyVersion + 1
	slot1 := cryptoid.Slot{Project: req.Project, KeyName: name, KeyVersion: newVersion}
	dek1, err := cryptoid.NewDEK()
	if err != nil {
		return manifest.KeyEntry{}, nil, err
	}
	blob1, err := cryptoid.SealBlob(pt, dek1, slot1)
	if err != nil {
		return manifest.KeyEntry{}, nil, fmt.Errorf("lifecycle.Rewrap: seal %q: %w", name, err)
	}
	blobHash1 := cryptoid.BlobHash(blob1)
	// 4) Hedef alıcı kümesine wrap'le (+ zorunlu WrapVerify öz-kontrolü, §3.5.5).
	wraps, err := sealToRecipients(dek1, target, slot1)
	if err != nil {
		return manifest.KeyEntry{}, nil, fmt.Errorf("lifecycle.Rewrap: wrap %q: %w", name, err)
	}
	// Rotasyon metadata'sı (§8.6.2) DEĞER'i tanımlar; DEK re-mint değeri
	// değiştirmez → metadata AYNEN korunur (worklist tier'ları kaybolmasın).
	return manifest.KeyEntry{KeyName: name, KeyVersion: newVersion, BlobHash: blobHash1, Wraps: wraps, Rotation: entry.Rotation}, blob1, nil
}

// addWraps, ADD yolu (§3.8.1): mevcut DEK'i okuyucuyla aç ve yalnızca EKLENECEK
// alıcılara yeni wrap'ler mühürle — blob + keyVersion DEĞİŞMEZ (manifest-only,
// O(1), sıfır blob churn, re-encrypt YOK). Mevcut wrap'ler korunur.
func (e *Engine) addWraps(req RewrapRequest, name string, entry manifest.KeyEntry, toAdd []Recipient, readerFP string) (manifest.KeyEntry, error) {
	dek, err := unwrapWith(entry, readerFP, req.Reader)
	if err != nil {
		return manifest.KeyEntry{}, err
	}
	slot := cryptoid.Slot{Project: req.Project, KeyName: name, KeyVersion: entry.KeyVersion}
	wraps := make([]manifest.DEKWrap, len(entry.Wraps))
	copy(wraps, entry.Wraps)
	added, err := sealToRecipients(dek, toAdd, slot)
	if err != nil {
		return manifest.KeyEntry{}, fmt.Errorf("lifecycle.Rewrap: add-wrap %q: %w", name, err)
	}
	wraps = append(wraps, added...)
	// blobHash + keyVersion + rotasyon metadata AYNEN korunur (re-encrypt yok).
	return manifest.KeyEntry{KeyName: name, KeyVersion: entry.KeyVersion, BlobHash: entry.BlobHash, Wraps: wraps, Rotation: entry.Rotation}, nil
}

// unwrapWith, girdideki readerFP wrap'ini bulur ve id ile DEK'i açar. Wrap yoksa
// ErrNotAReader (okuyucu bu anahtarı okuyamıyor → rewrap edemez).
func unwrapWith(entry manifest.KeyEntry, readerFP string, id *cryptoid.X25519Identity) (cryptoid.DEK, error) {
	for _, w := range entry.Wraps {
		if w.Recipient == readerFP {
			dek, err := cryptoid.UnsealDEK(w.Wrap, id)
			if err != nil {
				return cryptoid.DEK{}, fmt.Errorf("lifecycle.Rewrap: unseal DEK: %w", err)
			}
			return dek, nil
		}
	}
	return cryptoid.DEK{}, ErrNotAReader
}

// sealToRecipients, bir DEK'i verilen alıcılara DETERMİNİSTİK olarak wrap'ler ve
// her wrap için zorunlu çift-yollu öz-kontrolü (WrapVerify) imzadan ÖNCE yaptırır
// (§3.5.5). cryptoid primitiflerini YENİDEN KULLANIR.
func sealToRecipients(dek cryptoid.DEK, recips []Recipient, slot cryptoid.Slot) ([]manifest.DEKWrap, error) {
	out := make([]manifest.DEKWrap, 0, len(recips))
	for _, rc := range recips {
		wrap, err := cryptoid.SealDEK(dek, rc.Recipient, slot)
		if err != nil {
			return nil, fmt.Errorf("seal to recipient: %w", err)
		}
		if err := cryptoid.WrapVerify(dek, rc.Recipient, slot, wrap); err != nil {
			return nil, fmt.Errorf("wrap self-check: %w", err)
		}
		out = append(out, manifest.DEKWrap{Recipient: rc.Fingerprint, Wrap: wrap})
	}
	return out, nil
}
