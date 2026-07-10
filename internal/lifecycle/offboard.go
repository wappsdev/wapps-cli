package lifecycle

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// Offboard şema + durum sabitleri (SPEC §8.5.1).
const (
	OffboardSchema = "wapps.offboard/1"

	StepPending    = "pending"
	StepInProgress = "in_progress"
	StepDone       = "done"
	// StepRotationPending, değer-rotasyon worklist'i ÜRETİLDİ ama henüz YÜRÜTÜLMEDİ
	// (§8.5.5.4). Rotate adımı emisyon üzerine "done" OLMAZ — G11 run'ı terminal
	// bildirene kadar bu ara durumda kalır (close bunu bekler; sahte attestation yok).
	StepRotationPending = "rotation_pending"

	RecordOpen   = "open"
	RecordClosed = "closed"
)

// OffboardScope, offboard'ın kapsamıdır (SPEC §8.5.1).
type OffboardScope struct {
	Projects               []string `json:"projects"`
	Devices                []string `json:"devices,omitempty"`
	EscrowShareHolder      bool     `json:"escrow_share_holder"`
	LegacyPassphraseHolder bool     `json:"legacy_passphrase_holder"`
}

// StepState, tek bir offboard adımının durumudur (SPEC §8.5.1).
type StepState struct {
	Status       string            `json:"status"`
	At           time.Time         `json:"at,omitempty"`
	By           string            `json:"by,omitempty"`
	Evidence     json.RawMessage   `json:"evidence,omitempty"`
	LedgerRef    string            `json:"ledger_ref,omitempty"`       // rewrap ledger (§8.5.3)
	Attestations []json.RawMessage `json:"attestations,omitempty"`     // "fully rotated at N" (§8.5.3)
	WorklistRuns []string          `json:"worklist_run_ids,omitempty"` // step 3 (§8.5.5)
}

// OffboardSteps, 5 adımlı durum makinesidir (SPEC §8.5): kill → rewrap → rotate →
// escrow → close. NOT: escrow re-key (§8.5.4) spec'te step 2 içinde iç içe geçer;
// bu motor kullanıcı direktifine göre onu AYRI bir step (escrow) olarak modeller —
// close yalnızca 1-4 doğrulandığında işaretlenir.
type OffboardSteps struct {
	Kill   StepState `json:"kill"`
	Rewrap StepState `json:"rewrap"`
	Rotate StepState `json:"rotate"`
	Escrow StepState `json:"escrow"`
	Close  StepState `json:"close"`
}

// OffboardRecord, laptop kaybından sağ çıkan imzalı offboard kaydıdır (SPEC
// §8.5.1). R2'de (RecordStore) yaşar → herhangi bir admin --resume edebilir.
type OffboardRecord struct {
	Schema    string        `json:"schema"`
	RecordID  string        `json:"record_id"`
	Principal string        `json:"principal"`
	Reason    string        `json:"reason"`
	OpenedAt  time.Time     `json:"opened_at"`
	OpenedBy  string        `json:"opened_by"`
	Status    string        `json:"status"` // open | closed
	Scope     OffboardScope `json:"scope"`
	Steps     OffboardSteps `json:"steps"`
}

// recordKey, bir offboard kaydının RecordStore anahtarı (SPEC §8.5.1:
// offboard/<principal>/<record_id>.json — burada record_id benzersiz).
func recordKey(recordID string) string { return "offboard/" + recordID + ".json" }

// newRecordID, "ob_<hex>" biçiminde benzersiz bir kayıt id'si üretir.
func newRecordID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return "ob_" + hex.EncodeToString(b)
}

// --- İmzalı kayıt kalıcılığı (detached-sig envelope §3.6.1) ------------------

// signAndStore, kaydı admin anahtarıyla imzalar ve RecordStore'a yazar. Her adım
// geçişi kaydı YENİ imzalı bir sürüm olarak yeniden yazar (§8.5.1).
func (e *Engine) signAndStore(rec *OffboardRecord, signer cryptoid.SigningKey) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("lifecycle.offboard: marshal record: %w", err)
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return fmt.Errorf("lifecycle.offboard: sign record: %w", err)
	}
	obj := cryptoid.SignedObject{Bytes: body, Sigs: []cryptoid.Signature{sig}}
	raw, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("lifecycle.offboard: marshal envelope: %w", err)
	}
	return e.cfg.Records.PutRecord(recordKey(rec.RecordID), raw)
}

// adminVerifierRing, doğrulanmış trust head'inin admins[] kimliklerindeki aktif
// admin-class (P-256) imzalama anahtarlarından bir doğrulama keyring'i kurar —
// offboard kaydının BİR ADMIN tarafından imzalandığını doğrulamak için.
func adminVerifierRing(head *trust.TrustManifest) map[string]cryptoid.VerifierKey {
	adminSet := map[string]bool{}
	for _, a := range head.Admins {
		adminSet[a] = true
	}
	ring := map[string]cryptoid.VerifierKey{}
	for _, id := range head.Identities {
		if !adminSet[id.ID] || id.Status != registry.StatusActive {
			continue
		}
		for _, sk := range id.SigningKeys {
			if sk.Class != registry.SignClassAdmin || sk.Status != registry.StatusActive {
				continue
			}
			vk, err := verifierKeyFromEntry(sk)
			if err != nil {
				continue
			}
			ring[vk.KeyID()] = vk
		}
	}
	return ring
}

// verifierKeyFromEntry, bir registry imzalama girdisinden VerifierKey türetir.
func verifierKeyFromEntry(sk registry.SigningKey) (cryptoid.VerifierKey, error) {
	raw, err := base64.StdEncoding.DecodeString(sk.Pubkey)
	if err != nil {
		return cryptoid.VerifierKey{}, err
	}
	return cryptoid.NewVerifierKey(sk.Alg, raw)
}

// LoadOffboard, imzalı offboard kaydını RecordStore'dan yükler ve BİR ADMIN
// imzasına karşı doğrular (verify-before-parse §3.6.3), sonra body'yi ayrıştırır.
// Bu, herhangi bir admin'in (laptop'u fark etmeksizin) kaydı devralabilmesinin
// (§8.5.1) mekanizmasıdır.
func (e *Engine) LoadOffboard(recordID string, head *trust.VerifiedEpoch) (*OffboardRecord, error) {
	raw, ok, err := e.cfg.Records.GetRecord(recordKey(recordID))
	if err != nil {
		return nil, fmt.Errorf("lifecycle.LoadOffboard: %w", err)
	}
	if !ok {
		return nil, ErrRecordNotFound
	}
	var obj cryptoid.SignedObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("lifecycle.LoadOffboard: envelope: %w", err)
	}
	ring := adminVerifierRing(head.Manifest)
	signerKeyID, err := verifySignedByAdmin(obj, ring)
	if err != nil {
		return nil, err
	}
	var rec OffboardRecord
	if err := json.Unmarshal(obj.Bytes, &rec); err != nil {
		return nil, fmt.Errorf("lifecycle.LoadOffboard: body: %w", err)
	}
	if rec.Schema != OffboardSchema {
		return nil, fmt.Errorf("lifecycle.LoadOffboard: unexpected schema %q", rec.Schema)
	}
	// Defense-in-depth (P3-a §8.5): imzalayan BİR admin olsa yetmez — imzalayan
	// AYRILAN prensip OLMAMALI. adminVerifierRing hâlâ aktif olan ayrılan bir
	// admin'i (step-2 retire ÖNCESİ) içerir; kaydı kendisi imzalayıp süremesin.
	if signerID, ok := adminIdentityForSigningKey(head.Manifest, signerKeyID); ok && signerID == rec.Principal {
		return nil, ErrDepartingRunner
	}
	return &rec, nil
}

// verifySignedByAdmin, en az bir GEÇERLİ admin imzası arar (fail-closed) ve
// doğrulanan imzanın anahtar parmak izini (KeyID) döner — çağıran, imzalayanın
// kimliğini (ayrılan-mı?) bu parmak izinden çözer (P3-a: çalıştırıcı KRİPTOGRAFİK
// olarak bağlanır, caller'ın string'ine güvenilmez).
func verifySignedByAdmin(obj cryptoid.SignedObject, ring map[string]cryptoid.VerifierKey) (string, error) {
	for _, s := range obj.Sigs {
		vk, ok := ring[s.KeyID]
		if !ok {
			continue
		}
		if err := cryptoid.VerifySignatureEnvelope(obj.Bytes, s, vk); err == nil {
			return s.KeyID, nil
		}
	}
	return "", fmt.Errorf("lifecycle.offboard: record not signed by a known admin: %w", cryptoid.ErrSigInvalid)
}

// adminIdentityForSigningKey, verilen imzalama-anahtarı parmak izinin SAHİBİ olan
// AKTİF admin kimliğinin ID'sini döner (admins[] üyesi + identity active + admin-
// sınıfı anahtar active). Bulunamazsa ok=false. Bu, bir imzayı somut bir çalıştırıcı
// kimliğine bağlamanın (P3-a) tek gerçek kaynağıdır.
func adminIdentityForSigningKey(tm *trust.TrustManifest, keyID string) (string, bool) {
	if keyID == "" {
		return "", false
	}
	adminSet := map[string]bool{}
	for _, a := range tm.Admins {
		adminSet[a] = true
	}
	for _, id := range tm.Identities {
		if !adminSet[id.ID] || id.Status != registry.StatusActive {
			continue
		}
		for _, sk := range id.SigningKeys {
			if sk.Class != registry.SignClassAdmin || sk.Status != registry.StatusActive {
				continue
			}
			if sk.KeyID == keyID {
				return id.ID, true
			}
		}
	}
	return "", false
}

// --- OffboardStart ----------------------------------------------------------

// OffboardStartRequest, bir offboard kaydı açan kontrol-düzlemi işleminin girdisi.
type OffboardStartRequest struct {
	Principal              string
	Reason                 string // departure | compromise | device_loss | decommission
	Projects               []string
	Devices                []string
	EscrowShareHolder      bool
	LegacyPassphraseHolder bool
	OpenedBy               string // çalıştıran admin id — AYRILAN prensip OLAMAZ (§8.5)
	Signer                 cryptoid.SigningKey
	RecordID               string // opsiyonel; boşsa üretilir
}

// OffboardStart, imzalı bir offboard kaydı oluşturur ve RecordStore'a yazar (SPEC
// §8.5.1). Ayrılan prensip kaydı KENDİSİ açamaz (§8.5, ≥2 admin — hiçbir adım tek
// çalıştırıcısı ayrılan olamaz). Kayıt id'sini + kaydı döner.
func (e *Engine) OffboardStart(req OffboardStartRequest) (*OffboardRecord, error) {
	if req.Principal == "" {
		return nil, fmt.Errorf("lifecycle.OffboardStart: empty principal")
	}
	if req.OpenedBy == "" || req.Signer == nil {
		return nil, fmt.Errorf("lifecycle.OffboardStart: opening admin + signer required")
	}
	if req.OpenedBy == req.Principal {
		return nil, ErrDepartingRunner
	}
	recID := req.RecordID
	if recID == "" {
		recID = newRecordID()
	}
	rec := &OffboardRecord{
		Schema:    OffboardSchema,
		RecordID:  recID,
		Principal: req.Principal,
		Reason:    req.Reason,
		OpenedAt:  e.now(),
		OpenedBy:  req.OpenedBy,
		Status:    RecordOpen,
		Scope: OffboardScope{
			Projects:               append([]string(nil), req.Projects...),
			Devices:                append([]string(nil), req.Devices...),
			EscrowShareHolder:      req.EscrowShareHolder,
			LegacyPassphraseHolder: req.LegacyPassphraseHolder,
		},
		Steps: OffboardSteps{
			Kill:   StepState{Status: StepPending},
			Rewrap: StepState{Status: StepPending},
			Rotate: StepState{Status: StepPending},
			Escrow: StepState{Status: StepPending},
			Close:  StepState{Status: StepPending},
		},
	}
	if err := e.signAndStore(rec, req.Signer); err != nil {
		return nil, err
	}
	return rec, nil
}

// assertRunner, çalıştırıcıyı adım imzalama anahtarına KRİPTOGRAFİK olarak bağlar
// (§8.5, P3-a): imzalayan anahtarın SAHİBİ AKTİF bir admin olmalı, iddia edilen
// (caller-supplied) runnerID bu doğrulanmış kimlikle EŞLEŞMELİ ve ayrılan prensip
// OLAMAZ. Böylece hâlâ aktif olan ayrılan bir admin, spoofed bir runnerID ile
// adımları tek başına süremez. Doğrulanmış çalıştırıcı kimliğini (güvenilir audit
// "by") döner.
func assertRunner(head *trust.VerifiedEpoch, rec *OffboardRecord, claimedRunner string, signer cryptoid.SigningKey) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("lifecycle.offboard: nil runner signer")
	}
	runner, ok := adminIdentityForSigningKey(head.Manifest, signer.KeyID())
	if !ok {
		// İmzalama anahtarı aktif bir admin'e ait değil → çalıştırıcı yetkisiz.
		return "", fmt.Errorf("lifecycle.offboard: runner key not owned by an active admin: %w", ErrRunnerIdentityMismatch)
	}
	// ÖNCE ayrılan kontrolü (asıl güvenlik değişmezi, §8.5).
	if runner == rec.Principal {
		return "", ErrDepartingRunner
	}
	// İddia edilen runnerID, imza sahibiyle uyuşmalı (spoofed audit trail'i reddet).
	if claimedRunner != "" && claimedRunner != runner {
		return "", ErrRunnerIdentityMismatch
	}
	return runner, nil
}

// loadForStep, kaydı yükler, KAPALI olmadığını doğrular ve çalıştırıcıyı imzalama
// anahtarına kriptografik olarak bağlar (assertRunner). Adım fonksiyonlarının ortak
// giriş kapısı; doğrulanmış runner kimliğini (audit "by") döner.
func (e *Engine) loadForStep(recordID string, head *trust.VerifiedEpoch, claimedRunner string, signer cryptoid.SigningKey) (*OffboardRecord, string, error) {
	rec, err := e.LoadOffboard(recordID, head)
	if err != nil {
		return nil, "", err
	}
	if rec.Status == RecordClosed {
		return nil, "", ErrRecordClosed
	}
	runner, err := assertRunner(head, rec, claimedRunner, signer)
	if err != nil {
		return nil, "", err
	}
	return rec, runner, nil
}

// --- Step 1: KILL -----------------------------------------------------------

// OffboardStep1Kill, kill-switch adımıdır (SPEC §8.5.2): CF Access kaldırma +
// token revoke (TokenRevoker arayüzü; StubTokenRevoker net TODO taşır) + D1
// kill-flag. Tek bir admin tarafından UNILATERAL çalıştırılabilir, kriptografiye
// DOKUNMAZ. Kanıt kayda yazılır. İdempotent (done ise no-op).
func (e *Engine) OffboardStep1Kill(recordID string, head *trust.VerifiedEpoch, runnerID string, signer cryptoid.SigningKey) (*OffboardRecord, error) {
	rec, runner, err := e.loadForStep(recordID, head, runnerID, signer)
	if err != nil {
		return nil, err
	}
	if rec.Steps.Kill.Status == StepDone {
		return rec, nil // idempotent
	}
	ev, revErr := e.cfg.TokenRevoker.RevokeTokens(rec.Principal)
	// best-effort: revoke hatası adımı BLOKLAMAZ (§8.5.2); kanıta yazılır.
	evJSON, _ := json.Marshal(ev)
	rec.Steps.Kill = StepState{Status: StepDone, At: e.now(), By: runner, Evidence: evJSON}
	if revErr != nil {
		// Kanıt zaten stubbed/durum taşıyor; hata sadece not düşülür (değer sızmaz).
		note, _ := json.Marshal(map[string]any{"revoke_error": true})
		rec.Steps.Kill.Evidence = note
	}
	if err := e.signAndStore(rec, signer); err != nil {
		return nil, err
	}
	return rec, nil
}

// --- Step 2: REWRAP ---------------------------------------------------------

// Step2Input, offboard step 2 girdisidir (SPEC §8.5.3): trust/registry epoch'ları
// (grant revoke + identity retire) + kalan alıcılar için rewrap.
type Step2Input struct {
	// Head, current doğrulanmış trust head'i (revoke/retire ÖNCESİ; idempotent:
	// grant/identity zaten kaldırılmışsa o adım atlanır).
	Head *trust.VerifiedEpoch
	// RevokeSigners/RetireSigners, grant-removal (grant tier) + identity-retire
	// (registry tier) için admin imzalar.
	RevokeSigners []cryptoid.SigningKey
	RetireSigners []cryptoid.SigningKey
	// Reader, kalan bir okuyucu kimliği (DEK'leri açar); ASLA ayrılan olamaz.
	Reader            *cryptoid.X25519Identity
	ReaderFingerprint string
	// Writer, rewrap epoch'larını imzalayan yazar.
	Writer   cryptoid.SigningKey
	WriterID string
	// RunnerID, çalıştıran admin; RecordSigner kaydı yeniden imzalar.
	RunnerID     string
	RecordSigner cryptoid.SigningKey
}

// Step2Output, step 2 sonucudur.
type Step2Output struct {
	// NewHead, revoke+retire sonrası doğrulanmış head (rewrap bunun karşısında).
	NewHead *trust.VerifiedEpoch
	// RevokeEpoch/RetireEpoch, üretilen trust epoch'ları (caller trust store'a
	// persist eder). Zaten uygulanmışsa nil.
	RevokeEpoch *cryptoid.SignedObject
	RetireEpoch *cryptoid.SignedObject
	// Rewrap, per-proje rewrap sonuçları.
	Rewrap map[string]*RewrapResult
	// FullyRotated, TÜM projeler %100 rotate olduysa true.
	FullyRotated bool
	Record       *OffboardRecord
}

// OffboardStep2Rewrap, step 2'yi yürütür (SPEC §8.5.3): prensibi trust spine'dan +
// her wrap-set'ten kaldırır (§3 hard rule: removal ⇒ yeni DEK ⇒ re-encrypt). Grant
// zaten kaldırılmışsa revoke atlanır (idempotent/resume). Rewrap DEVAM-ETTİRİLEBİLİR
// (Rewrap motoru current'tan kalan işi türetir). Adım yalnızca TÜM projeler %100
// rotate olduğunda done olur; aksi halde in_progress ("alarming until 100%").
func (e *Engine) OffboardStep2Rewrap(recordID string, in Step2Input) (*Step2Output, error) {
	rec, runner, err := e.loadForStep(recordID, in.Head, in.RunnerID, in.RecordSigner)
	if err != nil {
		return nil, err
	}
	if rec.Steps.Kill.Status != StepDone {
		return nil, fmt.Errorf("lifecycle.offboard: step2 before step1: %w", ErrStepOutOfOrder)
	}
	// P3-b (§8.2): cihaz-kapsamlı offboard (tek cihazı kaldır, insan KALIR) bu
	// motorda UYGULANMADI — scope.Devices dolu iken departingFPs prensibin TÜM enc
	// anahtarlarını döner ve RetireIdentity kimliği TÜMÜYLE emekliye ayırır (insanın
	// tüm erişimini yok eder). Sessizce fazla-kaldırmak yerine açıkça reddet.
	if len(rec.Scope.Devices) > 0 {
		return nil, ErrDeviceOffboardUnsupported
	}

	// Ayrılan prensibin enc parmak izleri = Removed kümesi (device+backup).
	departingFPs := principalEncFingerprints(in.Head.Manifest, rec.Principal)

	out := &Step2Output{Rewrap: map[string]*RewrapResult{}}
	head := in.Head

	// (1) Grant revoke (idempotent: hâlâ grant varsa).
	if principalHasGrants(head.Manifest, rec.Principal) {
		obj, next, rerr := e.Revoke(RevokeRequest{Parent: head, Principal: rec.Principal, Signers: in.RevokeSigners})
		if rerr != nil {
			return nil, fmt.Errorf("lifecycle.offboard: revoke: %w", rerr)
		}
		out.RevokeEpoch = &obj
		head = next
	}
	// (2) Identity retire (idempotent: hâlâ active ise).
	if principalActive(head.Manifest, rec.Principal) {
		obj, next, rerr := e.RetireIdentity(RetireRequest{Parent: head, Principal: rec.Principal, Signers: in.RetireSigners})
		if rerr != nil {
			return nil, fmt.Errorf("lifecycle.offboard: retire: %w", rerr)
		}
		out.RetireEpoch = &obj
		head = next
	}
	out.NewHead = head

	// (3) Per-proje rewrap (REMOVE yolu — departingFPs artık gereken kümede değil).
	ledgerRef := "offboard/" + recordID + "/rewrap-ledger.jsonl"
	fullyRotated := true
	var attestations []json.RawMessage
	for _, project := range rec.Scope.Projects {
		rr, rerr := e.Rewrap(RewrapRequest{
			Project:           project,
			TrustHead:         head,
			Reader:            in.Reader,
			ReaderFingerprint: in.ReaderFingerprint,
			Writer:            in.Writer,
			WriterID:          in.WriterID,
			Removed:           departingFPs,
			LedgerKey:         ledgerRef,
			RecordID:          recordID,
		})
		if rerr != nil {
			// Kalıcılaştır (kısmi ilerleme) ve hatayı yay — resume kalanı tamamlar.
			rec.Steps.Rewrap = StepState{Status: StepInProgress, At: e.now(), By: runner, LedgerRef: ledgerRef}
			_ = e.signAndStore(rec, in.RecordSigner)
			out.Record = rec
			return out, fmt.Errorf("lifecycle.offboard: rewrap %q: %w", project, rerr)
		}
		out.Rewrap[project] = rr
		if !rr.FullyRotated {
			fullyRotated = false
		}
		if rr.Attestation != nil {
			if b, merr := json.Marshal(rr.Attestation); merr == nil {
				attestations = append(attestations, b)
			}
		}
	}
	out.FullyRotated = fullyRotated

	status := StepInProgress
	if fullyRotated {
		status = StepDone // yalnızca %100'de done (§8.5.3)
	}
	rec.Steps.Rewrap = StepState{
		Status:       status,
		At:           e.now(),
		By:           runner,
		LedgerRef:    ledgerRef,
		Attestations: attestations,
	}
	if err := e.signAndStore(rec, in.RecordSigner); err != nil {
		return nil, err
	}
	out.Record = rec
	return out, nil
}

// --- Step 3: ROTATE (worklist emit) -----------------------------------------

// Step3Output, step 3 sonucudur (üretilen worklist).
type Step3Output struct {
	Worklist *Worklist
	Record   *OffboardRecord
}

// OffboardStep3Rotate, step 3'ü yürütür (SPEC §8.5.5): ayrılan prensibin
// okuyabileceği HER projedeki HER anahtarın ZORUNLU değer-rotasyon worklist'ini
// ÜRETİR (en yüksek blast-radius önce). Bu VERİDİR — recipe'ler burada
// ÇALIŞTIRILMAZ (G11 tüketir). departure/compromise/device_loss için zorunludur.
func (e *Engine) OffboardStep3Rotate(recordID string, head *trust.VerifiedEpoch, runnerID string, signer cryptoid.SigningKey) (*Step3Output, error) {
	rec, runner, err := e.loadForStep(recordID, head, runnerID, signer)
	if err != nil {
		return nil, err
	}
	if rec.Steps.Rewrap.Status != StepDone {
		return nil, fmt.Errorf("lifecycle.offboard: step3 before step2 done: %w", ErrStepOutOfOrder)
	}
	runID := "wl_" + newRecordID()[3:]
	wl, werr := e.EmitWorklist(WorklistRequest{
		Principal: rec.Principal,
		Reason:    rec.Reason,
		Projects:  rec.Scope.Projects,
		RunID:     runID,
		RecordID:  recordID,
	})
	if werr != nil {
		return nil, werr
	}
	// P2-a: worklist EMİSYONU rotasyon YÜRÜTMESİ DEĞİLDİR. Rotate "done" OLMAZ —
	// yalnızca "rotation_pending" (G11 run'ı terminal bildirene kadar). Triyaj
	// gerektiren (metadata-eksik) giriş sayısı kanıta yazılır; close bunu bloklar.
	ev, _ := json.Marshal(rotationEmitEvidence(runID, wl))
	rec.Steps.Rotate = StepState{
		Status:       StepRotationPending,
		At:           e.now(),
		By:           runner,
		WorklistRuns: []string{runID},
		Evidence:     ev,
	}
	if err := e.signAndStore(rec, signer); err != nil {
		return nil, err
	}
	return &Step3Output{Worklist: wl, Record: rec}, nil
}

// rotationEmitEvidence, bir worklist emisyonunun (§8.5.5) kanıt gövdesini kurar:
// run id + toplam giriş + triyaj (metadata-eksik) giriş sayısı. Close bu
// needs_triage sayısını okuyarak (ledger'dan bağımsız) triyaj-bloğunu zorlar.
func rotationEmitEvidence(runID string, wl *Worklist) map[string]any {
	triage := 0
	for _, en := range wl.Entries {
		if en.NeedsTriage {
			triage++
		}
	}
	return map[string]any{
		"worklist_emitted": true,
		"run_id":           runID,
		"entries":          len(wl.Entries),
		"needs_triage":     triage,
	}
}

// --- Step 4: ESCROW re-key --------------------------------------------------

// Step4Output, step 4 sonucudur. Escrow re-key gerektiyse yeni escrow key + Shamir
// payları BİR KEZ döner.
type Step4Output struct {
	Rekey *EscrowRekeyResult // escrow_share_holder ise dolu; aksi halde nil
	// Worklist, escrow-share sahibi için üretilen TÜM-PROJELER değer-rotasyon
	// worklist'i (P2-b §8.5.4/§9.4.4); aksi halde nil. Run'ı close'dan ÖNCE zorunlu.
	Worklist *Worklist
	Record   *OffboardRecord
}

// OffboardStep4Escrow, step 4'ü yürütür (SPEC §8.5.4 / §3.8.5): ayrılan bir
// escrow-share sahibiyse yeni escrow keypair'i offline üretir + Shamir 2-of-3
// böler (payları BİR KEZ döner, asla persist etmez) ve escrow re-key gerektiğini
// işaretler; değilse adım no-op (not-applicable) done olur. Tam re-mint kampanyası
// (yeni escrow'u tüm projelerde Rewrap ile) caller'ın takibidir ve değer-rotasyon
// worklist'ini besler (§8.5.4 step 3: eski snapshot'lar "burned").
func (e *Engine) OffboardStep4Escrow(recordID string, head *trust.VerifiedEpoch, runnerID string, signer cryptoid.SigningKey) (*Step4Output, error) {
	rec, runner, err := e.loadForStep(recordID, head, runnerID, signer)
	if err != nil {
		return nil, err
	}
	// Rotate artık emisyonda "done" olmaz (P2-a) — step 4 için worklist'in
	// ÜRETİLMİŞ olması (rotation_pending veya done) yeterlidir.
	if rec.Steps.Rotate.Status != StepRotationPending && rec.Steps.Rotate.Status != StepDone {
		return nil, fmt.Errorf("lifecycle.offboard: step4 before step3 (worklist emitted): %w", ErrStepOutOfOrder)
	}
	out := &Step4Output{}
	if !rec.Scope.EscrowShareHolder {
		ev, _ := json.Marshal(map[string]any{"escrow_rekey": "not_applicable"})
		rec.Steps.Escrow = StepState{Status: StepDone, At: e.now(), By: runner, Evidence: ev}
		if err := e.signAndStore(rec, signer); err != nil {
			return nil, err
		}
		out.Record = rec
		return out, nil
	}
	rekey, rerr := e.EscrowRekey(nil)
	if rerr != nil {
		return nil, rerr
	}
	out.Rekey = rekey

	// P2-b (§8.5.4/§9.4.4): escrow alıcısı HER wrap-set'in ZORUNLU üyesidir; eski
	// escrow snapshot'larını "burn" etmek TÜM projelerdeki TÜM değerleri döndürmeyi
	// gerektirir. Step-3 worklist'i yalnızca scope.Projects'i kapsar → escrow için
	// AYRI, TÜM-PROJELER değer-rotasyon worklist'i üret; run'ı close'dan ÖNCE zorunlu.
	allProjects, lerr := e.cfg.Data.ListProjects()
	if lerr != nil {
		return nil, fmt.Errorf("lifecycle.offboard: escrow list projects: %w", lerr)
	}
	escrowRunID := "wl_" + newRecordID()[3:]
	escrowWL, werr := e.EmitWorklist(WorklistRequest{
		Principal: rec.Principal,
		Reason:    rec.Reason,
		Projects:  allProjects,
		RunID:     escrowRunID,
		RecordID:  recordID,
	})
	if werr != nil {
		return nil, fmt.Errorf("lifecycle.offboard: escrow worklist: %w", werr)
	}
	out.Worklist = escrowWL

	// Kanıt: yeni escrow parmak izi + pay üretimi + eski snapshot'lar burned +
	// TÜM-PROJELER remint worklist run id. ASLA pay/skalar değeri değil.
	emit := rotationEmitEvidence(escrowRunID, escrowWL)
	emit["escrow_rekey"] = "performed"
	emit["new_escrow_fingerprint"] = rekey.Fingerprint
	emit["shares_produced"] = rekey.Parts
	emit["threshold"] = rekey.Threshold
	emit["old_shares_burned"] = true
	emit["full_remint_required"] = true // §8.5.4: tüm projelerde yeni escrow'la re-mint
	emit["all_projects"] = len(allProjects)
	ev, _ := json.Marshal(emit)
	rec.Steps.Escrow = StepState{
		Status:       StepDone,
		At:           e.now(),
		By:           runner,
		Evidence:     ev,
		WorklistRuns: []string{escrowRunID},
	}
	if err := e.signAndStore(rec, signer); err != nil {
		return nil, err
	}
	out.Record = rec
	return out, nil
}

// --- Step 5: CLOSE ----------------------------------------------------------

// OffboardStep5Close, step 5'i yürütür (SPEC §8.5.7): adım 1-2 done + rewrap %100
// + escrow done VE değer-rotasyon worklist run'ları TERMİNAL (DONE/imzalı-SKIPPED,
// §8.5.5.4) olduğunda final attestation imzalar ve kaydı kapatır (immutable).
//
// P2-a: bu motor değer rotasyonunu YÜRÜTMEZ (G11 tüketir). Rotasyon run'ları
// ledger'da terminal olana kadar close, kaydı "awaiting rotation" (kill+rewrap+
// escrow done, rotation pending) durumunda bırakır ve ErrRotationPending döner —
// sahte "all_steps_verified" attestation'ı ASLA basılmaz. Metadata-eksik (triyaj)
// giriş varken (§8.5.5.1) ErrRotationTriageRequired; escrow gerekli ama yapılmadıysa
// ErrEscrowRekeyRequired; başka bir adım eksikse ErrStepOutOfOrder.
func (e *Engine) OffboardStep5Close(recordID string, head *trust.VerifiedEpoch, runnerID string, signer cryptoid.SigningKey) (*OffboardRecord, error) {
	rec, runner, err := e.loadForStep(recordID, head, runnerID, signer)
	if err != nil {
		return nil, err
	}
	if rec.Steps.Kill.Status != StepDone || rec.Steps.Rewrap.Status != StepDone {
		return nil, fmt.Errorf("lifecycle.offboard: close before steps 1-2 done: %w", ErrStepOutOfOrder)
	}
	// Step 3 worklist ÜRETİLMİŞ olmalı (rotation_pending veya done).
	if rec.Steps.Rotate.Status != StepRotationPending && rec.Steps.Rotate.Status != StepDone {
		return nil, fmt.Errorf("lifecycle.offboard: close before step3 (worklist emitted): %w", ErrStepOutOfOrder)
	}
	if rec.Scope.EscrowShareHolder && rec.Steps.Escrow.Status != StepDone {
		return nil, ErrEscrowRekeyRequired
	}
	if rec.Steps.Escrow.Status != StepDone {
		return nil, fmt.Errorf("lifecycle.offboard: close before step4 done: %w", ErrStepOutOfOrder)
	}
	// §8.5.5.1: emisyon anında bilinen metadata-eksik (triyaj) girişler close'u
	// bloklar — ledger'dan BAĞIMSIZ (optimistik/bozuk G11 bile bunu bypass edemez).
	if stepTriageCount(rec.Steps.Rotate)+stepTriageCount(rec.Steps.Escrow) > 0 {
		return nil, ErrRotationTriageRequired
	}
	// §8.5.5.4/§8.5.7: rotasyon (step-3 + escrow all-projects) run'ları TERMİNAL
	// olmadan close YASAK. G11 bağlı değilken StubRotationRunLedger her run'ı
	// pending bildirir → close ErrRotationPending döner (awaiting rotation).
	runIDs := append([]string(nil), rec.Steps.Rotate.WorklistRuns...)
	runIDs = append(runIDs, rec.Steps.Escrow.WorklistRuns...)
	for _, id := range runIDs {
		st, lerr := e.cfg.RotationRuns.RunState(id)
		if lerr != nil {
			return nil, fmt.Errorf("lifecycle.offboard: rotation run %q: %w", id, lerr)
		}
		if st.NeedsTriage {
			return nil, ErrRotationTriageRequired
		}
		if !st.Complete {
			return nil, ErrRotationPending
		}
	}
	// Tüm run'lar terminal → rotasyonu finalize et (done) + DÜRÜST final attestation.
	rec.Steps.Rotate.Status = StepDone
	final, _ := json.Marshal(map[string]any{
		"closed_by": runner, "closed_at": e.now(),
		"all_steps_verified": true, "rotation_runs": runIDs,
	})
	rec.Steps.Close = StepState{Status: StepDone, At: e.now(), By: runner, Evidence: final}
	rec.Status = RecordClosed
	if err := e.signAndStore(rec, signer); err != nil {
		return nil, err
	}
	return rec, nil
}

// stepTriageCount, bir adımın kanıtındaki needs_triage sayısını (yoksa 0) okur —
// ledger'dan bağımsız triyaj-bloğu (§8.5.5.1) için.
func stepTriageCount(s StepState) int {
	if len(s.Evidence) == 0 {
		return 0
	}
	var doc struct {
		NeedsTriage int `json:"needs_triage"`
	}
	_ = json.Unmarshal(s.Evidence, &doc)
	return doc.NeedsTriage
}

// --- registry yardımcıları --------------------------------------------------

// principalEncFingerprints, prensibin aktif enc anahtarlarının (device+backup)
// parmak izleri — rewrap Removed kümesi.
func principalEncFingerprints(tm *trust.TrustManifest, principal string) []string {
	var out []string
	for _, id := range tm.Identities {
		if id.ID != principal {
			continue
		}
		for _, ek := range id.EncKeys {
			fp := ek.KeyID
			if fp == "" {
				fp = ek.Fingerprint()
			}
			out = append(out, fp)
		}
	}
	return out
}

// principalHasGrants, prensibin trust manifest'inde hâlâ grant'ı var mı.
func principalHasGrants(tm *trust.TrustManifest, principal string) bool {
	for _, g := range tm.Grants {
		if g.Principal == principal {
			return true
		}
	}
	return false
}

// principalActive, prensibin kimliği hâlâ active mi.
func principalActive(tm *trust.TrustManifest, principal string) bool {
	id, ok := tm.Registry().IdentityByID(principal)
	return ok && id.Status == registry.StatusActive
}
