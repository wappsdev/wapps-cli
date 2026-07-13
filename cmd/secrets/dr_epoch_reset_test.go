package secrets

// dr_epoch_reset_test — plan P1.5 verb matrisi: agent-refusal, doğru 12-hex →
// tek pin-indiren Keys() çağrısı, yanlış 12-hex → hard abort (accepting store
// hiç kurulmaz), no-op (served >= pinned), format/normalizasyon kuralları.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// fakeEpochStore, epochResetStore'un scripted sahtesidir.
type fakeEpochStore struct {
	headSeq  uint64
	headHash string
	headErr  error
	keysRes  *store.KeysResult
	keysErr  error
	keysCall int
}

func (f *fakeEpochStore) AuditHead(context.Context) (uint64, string, error) {
	return f.headSeq, f.headHash, f.headErr
}

func (f *fakeEpochStore) Keys(_ context.Context, _ string) (*store.KeysResult, error) {
	f.keysCall++
	return f.keysRes, f.keysErr
}

// epochResetHarness, iki seam'i (opener + prompt) test süresince değiştirir:
// preview = default-false store, accepting = doğrulama sonrası store.
type epochResetHarness struct {
	preview     *fakeEpochStore
	accepting   *fakeEpochStore
	openCalls   []bool // opener'a geçirilen acceptReset değerleri, sıralı
	promptCalls int
	typed       string
	promptErr   error
}

func installEpochResetHarness(t *testing.T, h *epochResetHarness) {
	t.Helper()
	oldOpen, oldPrompt := openEpochResetStore, epochResetPrompt
	openEpochResetStore = func(acceptReset bool) (epochResetStore, error) {
		h.openCalls = append(h.openCalls, acceptReset)
		if acceptReset {
			return h.accepting, nil
		}
		return h.preview, nil
	}
	epochResetPrompt = func(string) (string, bool, error) {
		h.promptCalls++
		return h.typed, true, h.promptErr
	}
	t.Cleanup(func() { openEpochResetStore, epochResetPrompt = oldOpen, oldPrompt })
}

// downgradeErr, preview Keys'in EPOCH_DOWNGRADE senaryosunu üretir.
func downgradeErr() error {
	return clierr.Newf(clierr.EpochDowngrade, "served epoch %d < pinned %d for %q", 4, 9, "vaulter")
}

const liveHash = "ab12cd34ef56aa77bb88cc99dd00ee11"

func newDowngradeHarness(typed string) *epochResetHarness {
	return &epochResetHarness{
		preview:   &fakeEpochStore{headSeq: 4217, headHash: liveHash, keysErr: downgradeErr()},
		accepting: &fakeEpochStore{keysRes: &store.KeysResult{Project: "vaulter", Epoch: 4}},
		typed:     typed,
	}
}

// --- agent-refusal ---------------------------------------------------------------

// Ajan modunda verb, gate'e TEK istek ve TEK prompt bile atmadan reddedilir
// (kritik H4 — sosyal mühendislik kolu bir AI transcript'inden çekilemez).
func TestDrAcceptEpochReset_AgentRefusal(t *testing.T) {
	h := newDowngradeHarness(liveHash[:12])
	installEpochResetHarness(t, h)

	err := runDrAcceptEpochReset("vaulter", true /*isAgent*/, io.Discard, io.Discard)
	if !clierr.Is(err, clierr.AgentModeRefused) {
		t.Fatalf("want AGENT_MODE_REFUSED, got %v", err)
	}
	if len(h.openCalls) != 0 || h.promptCalls != 0 {
		t.Errorf("no store/prompt activity allowed in agent mode: opens=%v prompts=%d", h.openCalls, h.promptCalls)
	}
}

// --- doğru 12-hex → pin reset ------------------------------------------------------

// Kâğıttan yazılan İLK 12 hex canlı head'le eşleşince: accepting store TAM BİR
// kez, acceptReset=true ile kurulur ve tek Keys() çağrısı yapılır; çıktı yeni
// (indirilen) epoch'u ve zarf re-seal hatırlatmasını söyler.
func TestDrAcceptEpochReset_CorrectHexResetsPin(t *testing.T) {
	h := newDowngradeHarness(liveHash[:12])
	installEpochResetHarness(t, h)

	var out bytes.Buffer
	if err := runDrAcceptEpochReset("vaulter", false, &out, io.Discard); err != nil {
		t.Fatalf("ceremony should succeed: %v", err)
	}
	// Opener sırası: önce preview (false), sonra accepting (true) — başka yok.
	if len(h.openCalls) != 2 || h.openCalls[0] != false || h.openCalls[1] != true {
		t.Fatalf("opener calls: %v", h.openCalls)
	}
	if h.accepting.keysCall != 1 {
		t.Fatalf("accepting Keys must be called exactly once, got %d", h.accepting.keysCall)
	}
	got := out.String()
	for _, want := range []string{"reset to served epoch 4", "seq=4217", "re-seal"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q; got:\n%s", want, got)
		}
	}
}

// Büyük harf + çevre boşluğu normalize edilir (kâğıttan okuyan insan toleransı).
func TestDrAcceptEpochReset_NormalizesTypedHex(t *testing.T) {
	h := newDowngradeHarness("  " + strings.ToUpper(liveHash[:12]) + "\n")
	installEpochResetHarness(t, h)

	if err := runDrAcceptEpochReset("vaulter", false, io.Discard, io.Discard); err != nil {
		t.Fatalf("uppercase/whitespace input must normalize and match: %v", err)
	}
	if h.accepting.keysCall != 1 {
		t.Fatalf("accepting Keys calls: %d", h.accepting.keysCall)
	}
}

// --- yanlış 12-hex → hard abort ------------------------------------------------------

// Uyuşmazlıkta HARD ABORT: store substitution varsayılır, incident işaret edilir,
// accepting store HİÇ kurulmaz (pin'e dokunulmaz).
func TestDrAcceptEpochReset_WrongHexHardAborts(t *testing.T) {
	h := newDowngradeHarness("000000000000") // kâğıtla uyuşmayan değer
	installEpochResetHarness(t, h)

	err := runDrAcceptEpochReset("vaulter", false, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected hard abort on mismatch")
	}
	if !clierr.Is(err, clierr.EpochDowngrade) {
		t.Fatalf("want EPOCH_DOWNGRADE class abort, got %v", err)
	}
	if !strings.Contains(err.Error(), "substitution") || !strings.Contains(err.Error(), "incident") {
		t.Errorf("abort must assume store substitution + name the incident, got: %v", err)
	}
	for _, accept := range h.openCalls {
		if accept {
			t.Fatal("accepting store must NEVER be opened on mismatch")
		}
	}
	if h.accepting.keysCall != 0 {
		t.Fatalf("pin-lowering Keys must never fire on mismatch, got %d", h.accepting.keysCall)
	}
}

// 12 hex olmayan girdi (kısa / hex-dışı) da abort'tur — accepting store kurulmaz.
func TestDrAcceptEpochReset_MalformedInputAborts(t *testing.T) {
	for _, typed := range []string{"", "ab12", "zz12cd34ef56", liveHash} { // liveHash = 32 hex, 12 değil
		h := newDowngradeHarness(typed)
		installEpochResetHarness(t, h)
		if err := runDrAcceptEpochReset("vaulter", false, io.Discard, io.Discard); err == nil {
			t.Errorf("typed %q: expected abort", typed)
		}
		if h.accepting.keysCall != 0 {
			t.Errorf("typed %q: accepting Keys must not fire", typed)
		}
	}
}

// --- no-op + hata yolları ------------------------------------------------------------

// served >= pinned (preview Keys başarılı) → indirilecek pin yok; prompt HİÇ
// atılmaz, accepting store kurulmaz.
func TestDrAcceptEpochReset_NoResetNeeded(t *testing.T) {
	h := &epochResetHarness{
		preview:   &fakeEpochStore{headSeq: 1, headHash: liveHash, keysRes: &store.KeysResult{Project: "vaulter", Epoch: 9}},
		accepting: &fakeEpochStore{},
		typed:     liveHash[:12],
	}
	installEpochResetHarness(t, h)

	var out bytes.Buffer
	if err := runDrAcceptEpochReset("vaulter", false, &out, io.Discard); err != nil {
		t.Fatalf("no-op path must succeed: %v", err)
	}
	if h.promptCalls != 0 || h.accepting.keysCall != 0 {
		t.Errorf("no prompt/pin-lowering on no-op: prompts=%d keys=%d", h.promptCalls, h.accepting.keysCall)
	}
	if !strings.Contains(out.String(), "nothing to reset") {
		t.Errorf("output should say nothing to reset, got: %s", out.String())
	}
}

// AuditHead hatası (örn. AUDIT_UNAVAILABLE) seremoniyi prompt'suz keser —
// head'siz doğrulama olamaz (fail-closed).
func TestDrAcceptEpochReset_AuditHeadFailureStops(t *testing.T) {
	h := &epochResetHarness{
		preview:   &fakeEpochStore{headErr: clierr.New(clierr.AuditUnavailable, "audit ledger unavailable")},
		accepting: &fakeEpochStore{},
	}
	installEpochResetHarness(t, h)

	err := runDrAcceptEpochReset("vaulter", false, io.Discard, io.Discard)
	if !clierr.Is(err, clierr.AuditUnavailable) {
		t.Fatalf("want AUDIT_UNAVAILABLE, got %v", err)
	}
	if h.promptCalls != 0 || h.accepting.keysCall != 0 {
		t.Error("no prompt/pin-lowering without a live head")
	}
}

// Preview Keys'in EPOCH_DOWNGRADE dışı hatası (örn. SESSION_EXPIRED) aynen yayılır.
func TestDrAcceptEpochReset_OtherKeysErrorPropagates(t *testing.T) {
	h := &epochResetHarness{
		preview:   &fakeEpochStore{headSeq: 1, headHash: liveHash, keysErr: clierr.New(clierr.SessionExpired, "no session")},
		accepting: &fakeEpochStore{},
	}
	installEpochResetHarness(t, h)

	err := runDrAcceptEpochReset("vaulter", false, io.Discard, io.Discard)
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("want SESSION_EXPIRED, got %v", err)
	}
	if h.promptCalls != 0 || h.accepting.keysCall != 0 {
		t.Error("no prompt/pin-lowering on unrelated gate errors")
	}
}

// --project zorunlu; prompt hatası clierr ile sarılır (Unwrap zinciri korunur).
func TestDrAcceptEpochReset_GuardsAndPromptError(t *testing.T) {
	h := newDowngradeHarness(liveHash[:12])
	installEpochResetHarness(t, h)
	if err := runDrAcceptEpochReset("", false, io.Discard, io.Discard); err == nil {
		t.Fatal("expected error for missing --project")
	}

	sentinel := errors.New("tty closed")
	h2 := newDowngradeHarness("")
	h2.promptErr = sentinel
	installEpochResetHarness(t, h2)
	err := runDrAcceptEpochReset("vaulter", false, io.Discard, io.Discard)
	if !errors.Is(err, sentinel) {
		t.Fatalf("prompt error should stay in the Unwrap chain, got: %v", err)
	}
	if h2.accepting.keysCall != 0 {
		t.Error("pin-lowering must not fire after prompt failure")
	}
}
