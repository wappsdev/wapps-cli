package rotation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
)

// Per-key rotasyon durum makinesi (SPEC §8.6.4):
//
//	PENDING → VALUE_MINTED → STORE_WRITTEN → CONSUMER_UPDATED → VERIFIED → DONE
//
// + terminal FAILED (retryable) ve SKIPPED (imzalı gerekçe). NEEDS_TRIAGE, rotasyon-
// metadata'sı eksik girdiler içindir (blocker). TERMİNAL = DONE veya SKIPPED.
const (
	StatePending         = "PENDING"
	StateValueMinted     = "VALUE_MINTED"
	StateStoreWritten    = "STORE_WRITTEN"
	StateConsumerUpdated = "CONSUMER_UPDATED"
	StateVerified        = "VERIFIED"
	StateDone            = "DONE"
	StateFailed          = "FAILED"       // retryable (terminal DEĞİL)
	StateSkipped         = "SKIPPED"      // imzalı gerekçe (terminal)
	StateNeedsTriage     = "NEEDS_TRIAGE" // metadata eksik (terminal DEĞİL, blocker)
	// StateMirrorOnly, origin:"tofu" bir anahtarın store-tarafı value-mint yolunu
	// REDDETTİĞİDİR (§8.6.5): değer origin'de (tofu/DB) döndürülüp `wapps secrets
	// sync` ile store'a akar — store-tarafı mint DEĞİL. Store-run'ı açısından bu bir
	// TERMİNAL-origin-notu durumudur (aşağıda isTerminal): tofu anahtarları origin'de
	// döner ve AYRI attest edilir; store-run'ının yapabileceği daha fazla iş yoktur.
	StateMirrorOnly = "MIRROR_ONLY_ORIGIN"
)

// isTerminal, bir durumun run-tamamlanma açısından terminal olup olmadığını döner
// (§8.5.5.4). DONE + admin-imzalı SKIPPED terminaldir. MIRROR_ONLY_ORIGIN de TERMİNAL
// sayılır (FIX #6): origin:tofu anahtarlar store'da rotate EDİLMEZ — değer origin'de
// döner ve ayrı attest edilir. Aksi halde tofu-origin (her vaulter offboard'ı için
// NORMAL) VEYA metadata-eksik bir anahtar içeren bir run, MIRROR_ONLY non-terminal
// kaldığından ASLA close'a ulaşamazdı.
func isTerminal(state string) bool {
	return state == StateDone || state == StateSkipped || state == StateMirrorOnly
}

// progressOrdinal, per-key ileri-akış durumunun sırasal değeridir (resume: bir
// anahtar NEREYE kadar ilerledi §8.6.4). YALNIZCA ileri-akış durumları sıralanır;
// FAILED/NEEDS_TRIAGE/MIRROR_ONLY/SKIPPED ilerleme DEĞİLDİR (−1) — bir FAILED satır
// ulaşılan ilerlemeyi GERİ ALMAZ (motor STORE_WRITTEN'a ulaşmış bir anahtarı
// resume'da re-mint/re-write etmez).
func progressOrdinal(state string) int {
	switch state {
	case StatePending:
		return 0
	case StateValueMinted:
		return 1
	case StateStoreWritten:
		return 2
	case StateConsumerUpdated:
		return 3
	case StateVerified:
		return 4
	case StateDone:
		return 5
	default:
		return -1
	}
}

// reachedState, 'have' ilerleme durumunun en az 'want' kadar ilerlediğini döner.
// Boş 'have' (hiç satır yok) hiçbir şeye ulaşmamış sayılır.
func reachedState(have, want string) bool {
	return progressOrdinal(have) >= progressOrdinal(want)
}

// planEntry, bir run planının tek bir girdisidir (worklist'ten türetilir). Plan,
// RunState'in "HER girdi terminal mi" sorusunu yanıtlayabilmesi için ZORUNLUdur:
// yalnızca ilerleme satırlarına bakmak, başlatılmamış bir run'ı yanlışlıkla
// "complete" gösterirdi.
type planEntry struct {
	Project     string `json:"project"`
	Key         string `json:"key"`
	Recipe      string `json:"recipe,omitempty"`
	BlastTier   string `json:"blast_tier,omitempty"`
	NeedsTriage bool   `json:"needs_triage"`
}

// runPlan, bir worklist run'ının kalıcı planıdır (RecordStore'da).
type runPlan struct {
	Schema    string      `json:"schema"`
	RunID     string      `json:"run_id"`
	CreatedAt time.Time   `json:"created_at"`
	Entries   []planEntry `json:"entries"`
}

// runPlanSchema, plan şeması.
const runPlanSchema = "wapps.rotation.run-plan/1"

// LedgerRow, per-key durum-geçiş satırıdır (§8.6.4 JSONL: {run_id, project, key,
// state, at, by, evidence}). Escrow-push'lu Worker üzerinden kalıcılaşır (üretim);
// burada RecordStore.AppendLedger. Evidence ASLA gizli değer taşımaz.
type LedgerRow struct {
	RunID    string          `json:"run_id"`
	Project  string          `json:"project"`
	Key      string          `json:"key"`
	State    string          `json:"state"`
	At       time.Time       `json:"at"`
	By       string          `json:"by"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

// RunLedger, G11 rotasyon-run ledger'ının GERÇEK, store-backed uygulamasıdır ve
// lifecycle.RotationRunLedger port'unu (offboard close §8.5.7'nin tükettiği)
// KARŞILAR. Plan (girdi kümesi) + append-only ilerleme satırları RecordStore'da
// yaşar → resumable, herhangi bir admin devralabilir (§8.5.1), ve close bir run'ın
// TERMİNAL olduğunu buradan DOĞRULAR — StubRotationRunLedger'ın aksine gerçek
// yürütmeye bağlı ("awaiting rotation" ancak gerçekten tamamlanınca ilerler).
type RunLedger struct {
	store lifecycle.RecordStore
	now   func() time.Time
}

// NewRunLedger, verilen RecordStore ile bir ledger kurar. now nil → time.Now.
func NewRunLedger(store lifecycle.RecordStore, now func() time.Time) *RunLedger {
	if now == nil {
		now = time.Now
	}
	return &RunLedger{store: store, now: now}
}

func planKey(runID string) string   { return "rotation-runs/" + runID + "/plan.json" }
func ledgerKey(runID string) string { return "rotation-runs/" + runID + "/ledger.jsonl" }

// EnsurePlan, run planını (idempotent) yazar: zaten varsa dokunmaz (resume). Plan,
// worklist'in TAM girdi kümesini dondurur — RunState terminal-sorgusunun temeli.
func (l *RunLedger) EnsurePlan(wl *lifecycle.Worklist) error {
	if wl == nil || wl.RunID == "" {
		return fmt.Errorf("rotation.EnsurePlan: nil/empty worklist")
	}
	if _, ok, err := l.plan(wl.RunID); err != nil {
		return err
	} else if ok {
		return nil // idempotent (resume)
	}
	plan := runPlan{Schema: runPlanSchema, RunID: wl.RunID, CreatedAt: l.now().UTC()}
	for _, en := range wl.Entries {
		plan.Entries = append(plan.Entries, planEntry{
			Project: en.Project, Key: en.Key, Recipe: en.Recipe,
			BlastTier: en.BlastTier, NeedsTriage: en.NeedsTriage,
		})
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("rotation.EnsurePlan: marshal: %w", err)
	}
	return l.store.PutRecord(planKey(wl.RunID), body)
}

// Record, bir durum-geçişini append-only ledger'a yazar (§8.6.4). Evidence gizli
// değer TAŞIMAZ (yalnızca recipe/probe/versiyon meta).
func (l *RunLedger) Record(runID, project, key, state, by string, evidence any) error {
	var ev json.RawMessage
	if evidence != nil {
		b, err := json.Marshal(evidence)
		if err != nil {
			return fmt.Errorf("rotation.Record: evidence: %w", err)
		}
		ev = b
	}
	row := LedgerRow{
		RunID: runID, Project: project, Key: key, State: state,
		At: l.now().UTC(), By: by, Evidence: ev,
	}
	line, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("rotation.Record: marshal: %w", err)
	}
	return l.store.AppendLedger(ledgerKey(runID), line)
}

// skipAttestationSchema, imzalı-SKIP attestation şeması.
const skipAttestationSchema = "wapps.rotation.skip/1"

// skipAttestation, imzalı bir SKIP geçişinin KANONİK gövdesidir (§8.5.5.4): hangi
// run/proje/anahtarın, hangi admin tarafından, hangi gerekçeyle SKIPPED işaretlendiği.
// ASLA gizli değer/anahtar materyali taşımaz.
type skipAttestation struct {
	Schema  string    `json:"schema"`
	RunID   string    `json:"run_id"`
	Project string    `json:"project"`
	Key     string    `json:"key"`
	Reason  string    `json:"reason"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// skipEvidence, StateSkipped ledger satırının evidence gövdesidir: imzalı attestation
// + imzalayan admin anahtarının parmak izi + base64 imza (audit — doğrulanabilir).
type skipEvidence struct {
	Attestation skipAttestation `json:"attestation"`
	KeyID       string          `json:"key_id"`
	Sig         string          `json:"sig"`
}

// SkipKey, bir NEEDS_TRIAGE (veya başka bir pending) anahtarı, ADMIN İMZASIYLA
// SKIPPED'e geçirir — RunState'in var saydığı imzalı-SKIP kaçış kapısı (§8.5.5.4).
// İmza kanonik skip-attestation baytları üzerinedir ve evidence'a gömülür. Bir
// StateSkipped ledger satırı yazar → RunState o anahtarı terminal sayar, triyaj
// çözülür ve offboard close ilerleyebilir. reason + admin signer ZORUNLUdur; hiçbiri
// gizli değer taşımaz. (`wapps rotate skip` verb'ünün motor tarafı.)
func (l *RunLedger) SkipKey(runID, project, key, reason, by string, signer cryptoid.SigningKey) error {
	if runID == "" || project == "" || key == "" {
		return fmt.Errorf("rotation.SkipKey: run_id/project/key required")
	}
	if reason == "" {
		return fmt.Errorf("rotation.SkipKey: a --reason is required for a signed skip")
	}
	if signer == nil {
		return fmt.Errorf("rotation.SkipKey: an admin signing key is required for a signed skip")
	}
	att := skipAttestation{
		Schema: skipAttestationSchema, RunID: runID, Project: project, Key: key,
		Reason: reason, By: by, At: l.now().UTC(),
	}
	body, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("rotation.SkipKey: marshal attestation: %w", err)
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return fmt.Errorf("rotation.SkipKey: sign: %w", err)
	}
	ev := skipEvidence{Attestation: att, KeyID: sig.KeyID, Sig: base64.StdEncoding.EncodeToString(sig.Sig)}
	return l.Record(runID, project, key, StateSkipped, by, ev)
}

// plan, run planını okur; ok=false → henüz planlanmamış.
func (l *RunLedger) plan(runID string) (*runPlan, bool, error) {
	raw, ok, err := l.store.GetRecord(planKey(runID))
	if err != nil {
		return nil, false, fmt.Errorf("rotation.plan: %w", err)
	}
	if !ok {
		return nil, false, nil
	}
	var p runPlan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false, fmt.Errorf("rotation.plan: unmarshal: %w", err)
	}
	return &p, true, nil
}

// latestStates, her (project,key) için EN SON durumu (yazım sırasına göre) döner.
func (l *RunLedger) latestStates(runID string) (map[string]string, error) {
	lines, err := l.store.ReadLedger(ledgerKey(runID))
	if err != nil {
		return nil, fmt.Errorf("rotation.latestStates: %w", err)
	}
	out := map[string]string{}
	for _, ln := range lines {
		var row LedgerRow
		if json.Unmarshal(ln, &row) != nil {
			continue
		}
		out[stateKey(row.Project, row.Key)] = row.State
	}
	return out, nil
}

// LatestStates, per-key en son durumu (resume için) dışa açar.
func (l *RunLedger) LatestStates(runID string) (map[string]string, error) {
	return l.latestStates(runID)
}

// FurthestProgress, her (project,key) için ULAŞILAN EN İLERİ ileri-akış durumunu
// (append-only ledger'daki en yüksek sırasal ilerleme satırı) döner. LatestStates'ten
// FARKI: FAILED gibi hata satırlarını ATLAR — bir başarısızlık ulaşılan ilerlemeyi
// geri almaz. Resume bunu kullanır: STORE_WRITTEN'a ulaşmış bir anahtar re-mint/
// re-write EDİLMEZ, CONSUMER_UPDATED'a ulaşmış bir anahtar için Apply ATLANIR (§8.6.4).
func (l *RunLedger) FurthestProgress(runID string) (map[string]string, error) {
	lines, err := l.store.ReadLedger(ledgerKey(runID))
	if err != nil {
		return nil, fmt.Errorf("rotation.FurthestProgress: %w", err)
	}
	ord := map[string]int{}
	out := map[string]string{}
	for _, ln := range lines {
		var row LedgerRow
		if json.Unmarshal(ln, &row) != nil {
			continue
		}
		o := progressOrdinal(row.State)
		if o < 0 {
			continue // FAILED/NEEDS_TRIAGE/MIRROR_ONLY — ilerleme değil
		}
		k := stateKey(row.Project, row.Key)
		if cur, ok := ord[k]; !ok || o > cur {
			ord[k] = o
			out[k] = row.State
		}
	}
	return out, nil
}

// stateKey, (project,key) ledger anahtarı.
func stateKey(project, key string) string { return project + "\x00" + key }

// RunState, lifecycle.RotationRunLedger — worklist run'ının yürütme durumunu
// GERÇEK ilerlemeden türetir (SPEC §8.5.5.4/§8.6.4). Plan yoksa run henüz
// başlatılmamıştır → Complete=false, Pending=-1 (stub güvenliğini korur: hiçbir
// yürütme = pending). Aksi halde HER plan girdisi terminal olmadıkça (ve triyaj
// yoksa) Complete=false — böylece offboard close ancak run gerçekten bitince ilerler.
func (l *RunLedger) RunState(runID string) (lifecycle.RotationRunState, error) {
	p, ok, err := l.plan(runID)
	if err != nil {
		return lifecycle.RotationRunState{}, err
	}
	if !ok {
		// Planlanmamış run: hiçbir girdi yürütülmedi → pending (close bloklu).
		return lifecycle.RotationRunState{RunID: runID, Complete: false, Pending: -1}, nil
	}
	states, err := l.latestStates(runID)
	if err != nil {
		return lifecycle.RotationRunState{}, err
	}
	pending := 0
	needsTriage := false
	mirrorOnly := 0
	for _, en := range p.Entries {
		st := states[stateKey(en.Project, en.Key)]
		// Metadata-eksik girdi: imzalı-SKIPPED ile çözülmedikçe triyaj bloklar
		// (§8.5.5.1) — terminal DEĞİL. (MIRROR_ONLY triyajı BYPASS ETMEZ.)
		if en.NeedsTriage && st != StateSkipped {
			needsTriage = true
			pending++
			continue
		}
		if st == StateMirrorOnly {
			mirrorOnly++ // terminal-origin-notu (aşağıda isTerminal ile de terminal)
		}
		if isTerminal(st) {
			continue
		}
		pending++
	}
	return lifecycle.RotationRunState{
		RunID:       runID,
		Complete:    pending == 0 && !needsTriage,
		NeedsTriage: needsTriage,
		Pending:     pending,
		MirrorOnly:  mirrorOnly,
	}, nil
}

// arayüz uyumluluğu: RunLedger, offboard close'un tükettiği port'u karşılar.
var _ lifecycle.RotationRunLedger = (*RunLedger)(nil)
