package rotation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
)

// wl, test worklist'i kurar.
func wl(runID string, entries ...lifecycle.WorklistEntry) *lifecycle.Worklist {
	return &lifecycle.Worklist{Schema: lifecycle.WorklistSchema, RunID: runID, Entries: entries}
}

func staticEntry(project, key, recipe, tier string) lifecycle.WorklistEntry {
	return lifecycle.WorklistEntry{Project: project, Key: key, Recipe: recipe, Origin: OriginStatic, BlastTier: tier, State: StatePending}
}

// newTestEngine, mem-backed bir rotasyon motoru + ledger + değer-store kurar.
func newTestEngine() (*Engine, *RunLedger, *lifecycle.MemStore, *MemValueStore) {
	mem := lifecycle.NewMemStore()
	ledger := NewRunLedger(mem, fixedNow)
	vs := NewMemValueStore()
	e := NewEngine(Config{Ledger: ledger, Values: vs, Now: fixedNow})
	return e, ledger, mem, vs
}

// ledgerRows, bir run'ın ledger satırlarını yazım SIRASIYLA döner (ordering iddiaları).
func ledgerRows(t *testing.T, mem *lifecycle.MemStore, runID string) []LedgerRow {
	t.Helper()
	lines, err := mem.ReadLedger(ledgerKey(runID))
	require.NoError(t, err)
	out := make([]LedgerRow, 0, len(lines))
	for _, ln := range lines {
		var r LedgerRow
		require.NoError(t, json.Unmarshal(ln, &r))
		out = append(out, r)
	}
	return out
}

// TestRun_WalksWorklist, motorun worklist'i yürütüp her girdiyi DONE'a getirdiğini,
// store-first değer yazdığını ve ledger'ın terminal bildirdiğini kanıtlar (§8.6.4).
func TestRun_WalksWorklist(t *testing.T) {
	e, ledger, mem, vs := newTestEngine()
	w := wl(
		"wl_walk",
		staticEntry(testProject, "A", RecipeCoolifyStart, lifecycle.TierProdShared),
		staticEntry(testProject, "B", RecipeDBRolePhase1, lifecycle.TierProdShared),
	)
	rep, err := e.Run(context.Background(), w, NewMockExecutor(), "human:a", nil)
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Done)

	st, err := ledger.RunState("wl_walk")
	require.NoError(t, err)
	assert.True(t, st.Complete)
	assert.Equal(t, 0, st.Pending)

	// Store-first: her anahtar için değer yazıldı.
	assert.GreaterOrEqual(t, vs.WriteIndex(testProject, "A"), 0)
	assert.GreaterOrEqual(t, vs.WriteIndex(testProject, "B"), 0)

	// Durum makinesi sırası: STORE_WRITTEN, CONSUMER_UPDATED'ten ÖNCE (store-first).
	rows := ledgerRows(t, mem, "wl_walk")
	storeIdx, consumerIdx := -1, -1
	for i, r := range rows {
		if r.Key == "A" && r.State == StateStoreWritten && storeIdx == -1 {
			storeIdx = i
		}
		if r.Key == "A" && r.State == StateConsumerUpdated && consumerIdx == -1 {
			consumerIdx = i
		}
	}
	require.NotEqual(t, -1, storeIdx)
	require.NotEqual(t, -1, consumerIdx)
	assert.Less(t, storeIdx, consumerIdx, "value written to store BEFORE the consumer-side change (§8.6.1)")
}

// TestRun_ResumableAfterInterrupt, bir probe hatası bir girdide run'ı durdurduğunda
// (FAILED), Heal + yeniden Run'ın YALNIZCA kalan işi yaptığını (zaten-DONE atlanır)
// kanıtlar (§8.6.4 resumability).
func TestRun_ResumableAfterInterrupt(t *testing.T) {
	e, ledger, _, _ := newTestEngine()
	mock := NewMockExecutor()
	// Anahtarlar aynı tier + kısıtsız → anahtar adına göre sıra: A, B, C.
	w := wl(
		"wl_resume",
		staticEntry(testProject, "A", RecipeCoolifyStart, lifecycle.TierProdShared),
		staticEntry(testProject, "B", RecipeCoolifyStart, lifecycle.TierProdShared),
		staticEntry(testProject, "C", RecipeCoolifyStart, lifecycle.TierProdShared),
	)
	// B'nin probe'u başarısız → run B'de durur.
	mock.FailProbeFor[stateKey(testProject, "B")] = true

	_, err := e.Run(context.Background(), w, mock, "human:a", nil)
	require.Error(t, err, "run stops at the failing key")

	st, err := ledger.RunState("wl_resume")
	require.NoError(t, err)
	assert.False(t, st.Complete, "run not terminal after interrupt")

	aOpsBefore := len(mock.OpsFor(testProject, "A"))
	require.Equal(t, 4, aOpsBefore, "A fully processed once (mint,push-env,restart,probe)")

	// İyileş + resume.
	mock.Healed = true
	rep, err := e.Run(context.Background(), w, mock, "human:a", nil)
	require.NoError(t, err)

	// A yeniden ÇALIŞTIRILMADI (idempotent resume — DONE atlanır).
	assert.Equal(t, aOpsBefore, len(mock.OpsFor(testProject, "A")), "already-DONE key not re-executed on resume")
	assert.Equal(t, 3, rep.Done, "resume reports all three DONE")

	st, err = ledger.RunState("wl_resume")
	require.NoError(t, err)
	assert.True(t, st.Complete, "run terminal after resume completes remaining work")
}

// TestRun_NeedsTriageBlocks, metadata-eksik (NeedsTriage) bir girdinin rotate
// EDİLMEDİĞİNİ ve run'ı terminal olmaktan alıkoyduğunu kanıtlar (§8.5.5.1).
func TestRun_NeedsTriageBlocks(t *testing.T) {
	e, ledger, _, vs := newTestEngine()
	w := wl(
		"wl_triage",
		staticEntry(testProject, "OK", RecipeCoolifyStart, lifecycle.TierProdShared),
		lifecycle.WorklistEntry{Project: testProject, Key: "NO_META", NeedsTriage: true, BlastTier: lifecycle.TierUnknown, State: StatePending},
	)
	rep, err := e.Run(context.Background(), w, NewMockExecutor(), "human:a", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Done)
	assert.Equal(t, 1, rep.Triaged)
	assert.Equal(t, -1, vs.WriteIndex(testProject, "NO_META"), "triage entry is never value-minted")

	st, err := ledger.RunState("wl_triage")
	require.NoError(t, err)
	assert.True(t, st.NeedsTriage)
	assert.False(t, st.Complete, "triage blocks run terminal")
}

// TestRun_MirrorOnlyRefusesTofu, origin:"tofu" bir girdinin store-tarafı value-mint
// yolundan REDDEDİLDİĞİNİ (mirror-only §8.6.5) kanıtlar: değer store'a yazılmaz,
// recipe mint edilmez. FIX #6: MIRROR_ONLY_ORIGIN artık RunState'te TERMİNAL-origin-
// notu sayılır (tofu anahtarı origin'de döner + `wapps secrets sync` ile akar, AYRI
// attest edilir) → run Complete olur ama origin-tarafı takip işi st.MirrorOnly ile
// görünür kalır. Böylece tofu-origin anahtar içeren bir offboard ASLA deadlock olmaz.
func TestRun_MirrorOnlyRefusesTofu(t *testing.T) {
	e, ledger, _, vs := newTestEngine()
	tofu := lifecycle.WorklistEntry{Project: testProject, Key: "DATABASE_URL", Recipe: RecipeDBRolePhase1, Origin: OriginTofu, BlastTier: lifecycle.TierProdShared, State: StatePending}
	w := wl(
		"wl_tofu",
		staticEntry(testProject, "STATIC_KEY", RecipeCoolifyStart, lifecycle.TierProdShared),
		tofu,
	)
	rep, err := e.Run(context.Background(), w, NewMockExecutor(), "human:a", nil)
	require.NoError(t, err, "mirror-only is not a failure — it's rotated at origin + sync")
	assert.Equal(t, []string{testProject + "/DATABASE_URL"}, rep.MirrorOnly)
	assert.Equal(t, -1, vs.WriteIndex(testProject, "DATABASE_URL"), "TF-origin key NEVER enters the store-side value-mint path")

	st, err := ledger.RunState("wl_tofu")
	require.NoError(t, err)
	assert.True(t, st.Complete, "MIRROR_ONLY is terminal-with-origin-note; run must not deadlock (FIX #6)")
	assert.Equal(t, 0, st.Pending)
	assert.Equal(t, 1, st.MirrorOnly, "origin-side follow-up (tofu apply + sync) stays visible via MirrorOnly")
}

// TestRun_ManualPauses, manuel recipe (cf-manual) onay OLMADAN CONSUMER_UPDATED'te
// DURAKLADIĞINI (Paused) ve run'ı non-terminal bıraktığını kanıtlar (§8.6.4).
func TestRun_ManualPauses(t *testing.T) {
	e, ledger, mem, _ := newTestEngine()
	w := wl(
		"wl_manual",
		lifecycle.WorklistEntry{Project: testProject, Key: "CF_TOKEN", Recipe: RecipeCFManual, Origin: OriginStatic, BlastTier: lifecycle.TierPlatformAnchor, State: StatePending},
	)
	rep, err := e.Run(context.Background(), w, NewMockExecutor(), "human:a", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{testProject + "/CF_TOKEN"}, rep.Paused)
	assert.Equal(t, 0, rep.Done)

	// Ledger: VALUE_MINTED'da duraklı (CONSUMER_UPDATED yok) — non-terminal.
	rows := ledgerRows(t, mem, "wl_manual")
	last := rows[len(rows)-1].State
	assert.Equal(t, StateValueMinted, last, "manual entry pauses awaiting human attestation")
	st, err := ledger.RunState("wl_manual")
	require.NoError(t, err)
	assert.False(t, st.Complete)
}

// countOp, bir (project,key) için verilen Op'un kaç kez koştuğunu sayar.
func countOp(m *MockExecutor, project, key, op string) int {
	n := 0
	for _, o := range m.OpsFor(project, key) {
		if o == op {
			n++
		}
	}
	return n
}

// TestRun_ResumeDoesNotRemint, resume'un step-idempotent olduğunu kanıtlar (§8.6.4):
// STORE_WRITTEN/CONSUMER_UPDATED'a ulaşmış bir oto-recipe anahtarı FAILED'dan sonra
// YENİDEN mint/store-write/apply EDİLMEZ — yalnızca kalan Verify koşar. Aksi halde
// canlı executor'la ikinci bir kimlik-bilgisi basılır, ikinci ALTER ROLE + env-PATCH
// koşulur ve yeni bir store sürümü yazılırdı.
func TestRun_ResumeDoesNotRemint(t *testing.T) {
	e, ledger, _, vs := newTestEngine()
	mock := NewMockExecutor()
	w := wl(
		"wl_remint",
		staticEntry(testProject, "DB", RecipeDBRolePhase1, lifecycle.TierProdShared),
	)
	// Verify probe'u başarısız → DB, CONSUMER_UPDATED'a ULAŞMIŞ olarak FAILED olur.
	mock.FailProbeFor[stateKey(testProject, "DB")] = true

	_, err := e.Run(context.Background(), w, mock, "human:a", nil)
	require.Error(t, err, "run stops at the failing verify")

	// İlk geçiş: tam olarak bir mint, bir store-write (v1), bir ALTER ROLE.
	require.Equal(t, 1, countOp(mock, testProject, "DB", "mint"), "minted once")
	require.Equal(t, 1, countOp(mock, testProject, "DB", "alter-role"), "ALTER ROLE ran once")
	require.GreaterOrEqual(t, vs.WriteIndex(testProject, "DB"), 0, "value written to store once")
	require.Equal(t, uint64(1), vs.Version(testProject, "DB"))
	require.Len(t, vs.Writes, 1)

	st, err := ledger.RunState("wl_remint")
	require.NoError(t, err)
	assert.False(t, st.Complete, "run not terminal after the failed verify")

	// İyileş + resume.
	mock.Healed = true
	rep, err := e.Run(context.Background(), w, mock, "human:a", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Done)

	// RE-MINT YOK, RE-WRITE YOK, İKİNCİ ALTER ROLE YOK — yalnızca Verify tekrar koştu.
	assert.Equal(t, 1, countOp(mock, testProject, "DB", "mint"), "NOT re-minted on resume")
	assert.Equal(t, 1, countOp(mock, testProject, "DB", "alter-role"), "ALTER ROLE NOT doubled on resume")
	assert.Equal(t, 1, countOp(mock, testProject, "DB", "push-env"), "env-PATCH NOT doubled on resume")
	assert.Equal(t, uint64(1), vs.Version(testProject, "DB"), "store version unchanged (no re-write)")
	assert.Len(t, vs.Writes, 1, "exactly one store write across the failed run + resume")
	assert.Equal(t, 2, countOp(mock, testProject, "DB", "probe"), "only Verify re-ran on resume")

	st, err = ledger.RunState("wl_remint")
	require.NoError(t, err)
	assert.True(t, st.Complete, "run terminal once the remaining Verify passes")
}

// TestRun_ManualConfirmationCompletes, bir manuel recipe'e per-key onay token'ı
// verildiğinde girdinin DONE'a ilerlediğini ve run'ın Complete olduğunu kanıtlar
// (§8.6.4 tamamlanma tarafı — onaysız DURAKLAR, bkz. TestRun_ManualPauses).
func TestRun_ManualConfirmationCompletes(t *testing.T) {
	e, ledger, _, _ := newTestEngine()
	w := wl(
		"wl_manual_ok",
		lifecycle.WorklistEntry{Project: testProject, Key: "CF_TOKEN", Recipe: RecipeCFManual, Origin: OriginStatic, BlastTier: lifecycle.TierPlatformAnchor, State: StatePending},
	)
	confirms := &Confirmations{
		Tokens: map[string]string{stateKey(testProject, "CF_TOKEN"): "human-attested"},
	}
	rep, err := e.Run(context.Background(), w, NewMockExecutor(), "human:a", confirms)
	require.NoError(t, err)
	assert.Empty(t, rep.Paused, "confirmed manual entry does not pause")
	assert.Equal(t, 1, rep.Done)

	st, err := ledger.RunState("wl_manual_ok")
	require.NoError(t, err)
	assert.True(t, st.Complete, "run completes once the manual entry is human-confirmed")
}

// TestRun_ConfirmationRefusedInAgentMode, ajan/CI modunda onay token'ı verilirse
// Run'ın AGENT_MODE_REFUSED ile yapısal reddettiğini kanıtlar: insan-attestasyonu
// yalnızca gerçek bir TTY'den gelebilir (agent/CI onay ÜRETEMEZ).
func TestRun_ConfirmationRefusedInAgentMode(t *testing.T) {
	e, ledger, _, _ := newTestEngine()
	w := wl(
		"wl_manual_agent",
		lifecycle.WorklistEntry{Project: testProject, Key: "CF_TOKEN", Recipe: RecipeCFManual, Origin: OriginStatic, BlastTier: lifecycle.TierPlatformAnchor, State: StatePending},
	)
	confirms := &Confirmations{
		IsAgent: true,
		Tokens:  map[string]string{stateKey(testProject, "CF_TOKEN"): "human-attested"},
	}
	_, err := e.Run(context.Background(), w, NewMockExecutor(), "human:a", confirms)
	require.Error(t, err, "agent mode may not supply a human confirmation")
	assert.True(t, clierr.Is(err, clierr.AgentModeRefused), "confirmation in agent mode → AGENT_MODE_REFUSED")

	// Reddedilen run hiçbir plan/ilerleme yazmamalı (side-effect'ten önce reddedildi).
	st, err := ledger.RunState("wl_manual_agent")
	require.NoError(t, err)
	assert.False(t, st.Complete)
	assert.Equal(t, -1, st.Pending, "no plan written for the refused run")
}
