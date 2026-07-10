package rotation

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// KeyInventory, migration ÖNCESİ hazırlanan per-key envanterdir (§10.4.1: her
// legacy anahtara bir recipe + origin ATANMALI). Cutover, her anahtarın manifest
// girdisine bunu §8.6.2 rotasyon-metadata objesi olarak yazar → sonraki worklist
// üretimi (lifecycle.EmitWorklist) bunu okur.
type KeyInventory struct {
	Recipe              string            `json:"recipe"`
	Origin              string            `json:"origin"` // "tofu" (mirror-only §8.6.5) | "static"
	BlastTier           string            `json:"blast_tier"`
	Consumers           []string          `json:"consumers,omitempty"`
	OrderingConstraints []string          `json:"ordering_constraints,omitempty"`
	Verify              string            `json:"verify,omitempty"`
	RecipeParams        map[string]string `json:"recipe_params,omitempty"`
}

// OriginTofu / OriginStatic (§8.6.2/§8.6.5).
const (
	OriginTofu   = "tofu"
	OriginStatic = "static"
)

// --- Legacy arşiv (SALT-OKUNUR: IRON RULE §10.5) ---------------------------

// LegacyArchive, eski scrypt all.enc.age arşivinin SALT-OKUNUR bir handle'ıdır.
// KASITLI olarak HİÇBİR yazma metodu YOKTUR — store'a rotate edilen bir değer
// buraya geri yazılamaz (IRON RULE §10.5). Yalnızca tombstone.go'daki guard'lı
// yol legacy'e (o da SADECE __MIGRATED__ sentinel'i) yazabilir.
type LegacyArchive struct {
	ciphertext []byte
}

// LegacyArchiveFromBytes, ham ciphertext'ten salt-okunur bir handle kurar (test +
// bellek). Dosyadan okuma CLI tarafında (resolveArchivePath) yapılır.
func LegacyArchiveFromBytes(ciphertext []byte) *LegacyArchive {
	cp := make([]byte, len(ciphertext))
	copy(cp, ciphertext)
	return &LegacyArchive{ciphertext: cp}
}

// Values, legacy arşivi passphrase ile ÇÖZER (§10.2 — passphrase'in SON kullanımı)
// ve her anahtar için düz-metin değeri döner. __MIGRATED__ tombstone'u taşıyorsa
// ErrArchiveMigrated (bayat/tombstoned arşiv — cutover tekrar edilmez).
func (a *LegacyArchive) Values(passphrase string) (map[string][]byte, error) {
	plaintext, err := ageutil.Decrypt(a.ciphertext, passphrase)
	if err != nil {
		return nil, fmt.Errorf("rotation.Values: legacy decrypt: %w", err)
	}
	var outputs map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &outputs); err != nil {
		return nil, fmt.Errorf("rotation.Values: parse legacy archive: %w", err)
	}
	if _, ok := outputs[MigratedSentinelKey]; ok {
		return nil, ErrArchiveMigrated
	}
	out := make(map[string][]byte, len(outputs))
	for k, raw := range outputs {
		out[k] = legacyValueBytes(raw)
	}
	return out, nil
}

// legacyValueBytes, bir legacy arşiv değerini kanonik düz-metin baytlarına çevirir.
// tofu-output arşiv şekli {"KEY":{"value":..}} VEYA düz {"KEY":"val"} destekler:
// {value:X} sarmalayıcısını açar, JSON string'i unquote eder, aksi halde compact
// JSON. Cutover + verify AYNI fonksiyonu kullanır → roundtrip byte-tutarlı.
func legacyValueBytes(raw json.RawMessage) []byte {
	// {value: X} sarmalayıcısı (tofu output) → X'i al.
	var wrapper struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Value) > 0 {
		raw = wrapper.Value
	}
	// JSON string → unquote (legacy rawValueToString ile aynı semantik).
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []byte(s)
	}
	// Diğer (obje/sayı/bool) → compact JSON.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err == nil {
		return compact.Bytes()
	}
	return bytes.TrimSpace(raw)
}

// --- Cutover (Phase 1: byte-identical import + roundtrip verify) ------------

// CutoverInput, `wapps migrate cutover <project>` girdisidir (SPEC §10.2 Phase 1).
type CutoverInput struct {
	Project    string
	Legacy     *LegacyArchive
	Passphrase string                 // WAPPS_SECRETS_PASSPHRASE — passphrase'in SON kullanımı
	Recipients []lifecycle.Recipient  // proje alıcı kümesi (backup + escrow DAHİL)
	EscrowFPs  []string               // escrow parmak izleri (client-enforced §9.1)
	Writer     cryptoid.SigningKey    // genesis'i imzalayan yazar
	Ring       manifest.WriterKeyring // imza sonrası öz-doğrulama
	TrustEpoch uint64
	Inventory  map[string]KeyInventory  // per-key origin + recipe (§10.4.1)
	Verifier   *cryptoid.X25519Identity // roundtrip çözümü (Recipients'ta OLMALI)
	Data       lifecycle.DataStore      // genesis commit hedefi
	Now        func() time.Time
}

// CutoverResult, cutover sonucudur.
type CutoverResult struct {
	Project      string
	Epoch        uint64
	Keys         int
	TFOriginKeys []string // origin:"tofu" işaretli (mirror-only §8.6.5) anahtarlar
	ObjHash      string
}

// Cutover, legacy arşivi YENİ store'a byte-identical taşır (SPEC §10.2 Phase 1):
// her anahtarı per-key DEK zarfı olarak (SealDEK → proje alıcı kümesi incl backup+
// escrow, WrapVerify) yeniden şifreler, imzalı bir GENESIS epoch'u olarak commit
// eder, SONRA roundtrip DOĞRULAR (her anahtarı fetch+decrypt, legacy düz-metniyle
// byte-compare — herhangi bir uyuşmazlıkta İPTAL, legacy otoritatif kalır).
// TF-origin anahtarlar origin:"tofu" ile işaretlenir (mirror-only §8.6.5).
//
// IRON RULE (§10.5): Cutover HİÇBİR legacy-yazma yolu içermez — yalnızca legacy'i
// OKUR (Values) ve DataStore'a yazar.
func Cutover(ctx context.Context, in CutoverInput) (*CutoverResult, error) {
	now := in.Now
	if now == nil {
		now = time.Now
	}
	if len(in.Recipients) == 0 {
		return nil, ErrRecipientMissing
	}
	if in.Verifier == nil || !recipientSetHas(in.Recipients, in.Verifier.Fingerprint()) {
		return nil, fmt.Errorf("rotation.Cutover: verifier identity must be in the recipient set: %w", ErrRecipientMissing)
	}

	// (§9.1) Escrow-wrap değişmezini YAPISAL kıl — çağıran-özenine bağlı bırakma:
	// en az bir escrow parmak izi ZORUNLU ve her escrow fp alıcı kümesinde OLMALI.
	// Aksi halde boş EscrowFPs, escrow-wrap'siz bir genesis'i sessizce commit+byte-
	// doğrular; recipients escrow'suz olursa da escrow wrap üretilmez → İPTAL.
	if len(in.EscrowFPs) == 0 {
		return nil, fmt.Errorf("rotation.Cutover: at least one escrow fingerprint required (§9.1): %w", ErrEscrowMissing)
	}
	for _, fp := range in.EscrowFPs {
		if !recipientSetHas(in.Recipients, fp) {
			return nil, fmt.Errorf("rotation.Cutover: escrow fp %q absent from recipient set (§9.1): %w", fp, ErrEscrowMissing)
		}
	}

	// (0) Legacy'i ÇÖZ — passphrase'in SON kullanımı (§10.2).
	values, err := in.Legacy.Values(in.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("rotation.Cutover: %w", err)
	}

	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)

	// (1) Her anahtarı per-key DEK zarfı olarak kur (blob + wrap-set + rotasyon-meta).
	entries := make([]manifest.KeyEntry, 0, len(names))
	blobs := map[string][]byte{}
	var tfOrigin []string
	for _, name := range names {
		slot := cryptoid.Slot{Project: in.Project, KeyName: name, KeyVersion: 1}
		dek, derr := cryptoid.NewDEK()
		if derr != nil {
			return nil, fmt.Errorf("rotation.Cutover: dek %q: %w", name, derr)
		}
		blob, berr := cryptoid.SealBlob(values[name], dek, slot)
		if berr != nil {
			return nil, fmt.Errorf("rotation.Cutover: seal %q: %w", name, berr)
		}
		hash := cryptoid.BlobHash(blob)
		blobs[hash] = blob

		wraps, werr := sealDEKToRecipients(dek, in.Recipients, slot)
		if werr != nil {
			return nil, fmt.Errorf("rotation.Cutover: wrap %q: %w", name, werr)
		}
		ke := manifest.KeyEntry{KeyName: name, KeyVersion: 1, BlobHash: hash, Wraps: wraps}

		if inv, ok := in.Inventory[name]; ok {
			meta, merr := marshalRotationMeta(inv)
			if merr != nil {
				return nil, fmt.Errorf("rotation.Cutover: meta %q: %w", name, merr)
			}
			ke.Rotation = manifest.NewRotationMeta(meta)
			if inv.Origin == OriginTofu {
				tfOrigin = append(tfOrigin, name) // mirror-only işaretli (§8.6.5)
			}
		}
		entries = append(entries, ke)
	}

	// (2) Genesis manifest'i kur + escrow-wrap değişmezi (§9.1) + imzala + öz-doğrula.
	m := &manifest.DataManifest{
		Schema:             manifest.SchemaDataManifest,
		Project:            in.Project,
		Epoch:              1,
		PrevManifestSha256: "",
		TrustEpoch:         in.TrustEpoch,
		CreatedAt:          now().UTC(),
		Entries:            entries,
	}
	for _, fp := range in.EscrowFPs {
		if cerr := manifest.CheckEscrowWraps(m, fp); cerr != nil {
			return nil, fmt.Errorf("rotation.Cutover: %w", cerr)
		}
	}
	signed, _, serr := manifest.SignManifest(m, in.Writer)
	if serr != nil {
		return nil, fmt.Errorf("rotation.Cutover: sign genesis: %w", serr)
	}
	raw, merr := manifest.MarshalSignedObject(signed)
	if merr != nil {
		return nil, fmt.Errorf("rotation.Cutover: marshal genesis: %w", merr)
	}
	if in.Ring != nil {
		if _, cverr := manifest.VerifyDataManifest(signed, in.Ring); cverr != nil {
			return nil, fmt.Errorf("rotation.Cutover: self-verify genesis: %w", cverr)
		}
	}

	// (3) PRE-COMMIT roundtrip doğrulaması (in-memory) — kripto/mantık hatasını SIFIR
	// store-yazımıyla yakalar → İPTAL legacy'i otoritatif bırakır (hiçbir şey yazılmadı).
	if verr := verifyRoundtrip(in.Project, entries, blobs, in.Verifier, values); verr != nil {
		return nil, verr
	}

	// (4) Commit: blob'lar + genesis (CAS: prev "").
	for hash, blob := range blobs {
		if perr := in.Data.PutBlob(in.Project, hash, blob); perr != nil {
			return nil, fmt.Errorf("rotation.Cutover: put blob: %w", perr)
		}
	}
	if cerr := in.Data.CommitManifest(in.Project, raw, ""); cerr != nil {
		return nil, fmt.Errorf("rotation.Cutover: commit genesis: %w", cerr)
	}

	// (5) POST-COMMIT roundtrip: store'dan FETCH + decrypt + byte-compare (§10.2).
	// Store/transport bozması burada yakalanır → uyuşmazlıkta İPTAL; çağıran
	// .wapps.yaml'ı store'a FLİP ETMEZ → legacy otoritatif kalır (§10.2 rollback).
	if verr := verifyRoundtripFromStore(in.Project, in.Data, in.Verifier, values); verr != nil {
		return nil, verr
	}

	sort.Strings(tfOrigin)
	return &CutoverResult{
		Project:      in.Project,
		Epoch:        1,
		Keys:         len(entries),
		TFOriginKeys: tfOrigin,
		ObjHash:      manifest.ManifestObjectHash(raw),
	}, nil
}

// sealDEKToRecipients, bir DEK'i verilen alıcılara DETERMİNİSTİK olarak wrap'ler ve
// her wrap için zorunlu çift-yollu öz-kontrolü (WrapVerify) yaptırır (§3.5.5).
// cryptoid primitiflerini YENİDEN KULLANIR (kripto tekrarı YOK).
func sealDEKToRecipients(dek cryptoid.DEK, recips []lifecycle.Recipient, slot cryptoid.Slot) ([]manifest.DEKWrap, error) {
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

// recipientSetHas, alıcı kümesinde bir parmak izi var mı.
func recipientSetHas(recips []lifecycle.Recipient, fp string) bool {
	for _, r := range recips {
		if r.Fingerprint == fp {
			return true
		}
	}
	return false
}

// marshalRotationMeta, KeyInventory'i §8.6.2 rotasyon-metadata JSON'una çevirir.
func marshalRotationMeta(inv KeyInventory) ([]byte, error) {
	doc := map[string]any{
		"recipe":     inv.Recipe,
		"origin":     inv.Origin,
		"blast_tier": inv.BlastTier,
	}
	if len(inv.Consumers) > 0 {
		doc["consumers"] = inv.Consumers
	}
	if len(inv.OrderingConstraints) > 0 {
		doc["ordering_constraints"] = inv.OrderingConstraints
	}
	if inv.Verify != "" {
		doc["verify"] = inv.Verify
	}
	if len(inv.RecipeParams) > 0 {
		doc["recipe_params"] = inv.RecipeParams
	}
	return json.Marshal(doc)
}

// verifyRoundtrip, in-memory kurulan girdiler+blob'lardan her anahtarı Verifier ile
// çözer ve legacy düz-metniyle byte-compare eder. Uyuşmazlıkta ErrCutoverVerifyMismatch.
func verifyRoundtrip(project string, entries []manifest.KeyEntry, blobs map[string][]byte, verifier *cryptoid.X25519Identity, expected map[string][]byte) error {
	fp := verifier.Fingerprint()
	for _, en := range entries {
		got, err := decryptEntry(project, en, blobs, fp, verifier)
		if err != nil {
			return fmt.Errorf("rotation.Cutover: pre-commit verify %q: %w", en.KeyName, ErrCutoverVerifyMismatch)
		}
		if subtle.ConstantTimeCompare(got, expected[en.KeyName]) != 1 {
			return fmt.Errorf("rotation.Cutover: pre-commit verify %q value mismatch: %w", en.KeyName, ErrCutoverVerifyMismatch)
		}
	}
	return nil
}

// verifyRoundtripFromStore, store'dan FETCH edip her anahtarı çözer ve legacy
// düz-metniyle byte-compare eder (§10.2 post-commit). Uyuşmazlık → İPTAL.
func verifyRoundtripFromStore(project string, data lifecycle.DataStore, verifier *cryptoid.X25519Identity, expected map[string][]byte) error {
	wrapper, blobs, _, _, ok, err := data.CurrentManifest(project)
	if err != nil {
		return fmt.Errorf("rotation.Cutover: post-commit fetch: %w", err)
	}
	if !ok {
		return fmt.Errorf("rotation.Cutover: post-commit fetch: no current manifest: %w", ErrCutoverVerifyMismatch)
	}
	obj, perr := manifest.ParseSignedObject(wrapper)
	if perr != nil {
		return fmt.Errorf("rotation.Cutover: post-commit parse: %w", perr)
	}
	man, berr := manifest.ParseManifestBody(obj.Bytes)
	if berr != nil {
		return fmt.Errorf("rotation.Cutover: post-commit body: %w", berr)
	}
	fp := verifier.Fingerprint()
	seen := make(map[string]bool, len(man.Entries))
	for i := range man.Entries {
		en := man.Entries[i]
		got, derr := decryptEntry(project, en, blobs, fp, verifier)
		if derr != nil {
			return fmt.Errorf("rotation.Cutover: post-commit verify %q: %w", en.KeyName, ErrCutoverVerifyMismatch)
		}
		if subtle.ConstantTimeCompare(got, expected[en.KeyName]) != 1 {
			return fmt.Errorf("rotation.Cutover: post-commit verify %q value mismatch: %w", en.KeyName, ErrCutoverVerifyMismatch)
		}
		seen[en.KeyName] = true
	}
	// TAMLIK (§10.2): döndürülen küme EKSİKSİZ olmalı — girdiyi okuma-sırasında
	// DÜŞÜREN bir store/transport hatası fark edilmeden geçmemeli (daha az anahtar
	// karşılaştırılır → sessiz nil). Beklenen HER anahtar ziyaret edilmiş olmalı;
	// aksi halde İPTAL, legacy otoritatif kalır.
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("rotation.Cutover: post-commit verify: entry %q dropped by store: %w", name, ErrCutoverVerifyMismatch)
		}
	}
	return nil
}

// decryptEntry, bir manifest girdisini verilen okuyucu parmak izi + kimliğiyle çözer.
func decryptEntry(project string, en manifest.KeyEntry, blobs map[string][]byte, readerFP string, id *cryptoid.X25519Identity) ([]byte, error) {
	var wrap []byte
	for _, w := range en.Wraps {
		if w.Recipient == readerFP {
			wrap = w.Wrap
			break
		}
	}
	if wrap == nil {
		return nil, fmt.Errorf("no wrap for verifier")
	}
	dek, err := cryptoid.UnsealDEK(wrap, id)
	if err != nil {
		return nil, err
	}
	blob, ok := blobs[en.BlobHash]
	if !ok {
		return nil, fmt.Errorf("blob missing")
	}
	if err := cryptoid.VerifyBlobHash(blob, en.BlobHash); err != nil {
		return nil, err
	}
	slot := cryptoid.Slot{Project: project, KeyName: en.KeyName, KeyVersion: en.KeyVersion}
	return cryptoid.OpenBlob(blob, dek, slot)
}
