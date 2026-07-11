package rotation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/lifecycle"
)

// TestLedger_NotPlannedIsPending, planlanmamış bir run'ın PENDING bildirdiğini
// (Complete=false, Pending=-1) — StubRotationRunLedger'ın güvenli varsayılanını
// KORUDUĞUNU kanıtlar (§8.5.5.4: hiçbir yürütme = pending, close bloklu).
func TestLedger_NotPlannedIsPending(t *testing.T) {
	l := NewRunLedger(lifecycle.NewMemStore(), fixedNow)
	st, err := l.RunState("wl_unknown")
	require.NoError(t, err)
	assert.False(t, st.Complete)
	assert.Equal(t, -1, st.Pending)
	assert.False(t, st.NeedsTriage)
}

// TestLedger_TerminalWhenAllDone, plan girdilerinin HEPSİ DONE olduğunda run'ın
// terminal (Complete=true) bildirdiğini kanıtlar.
func TestLedger_TerminalWhenAllDone(t *testing.T) {
	l := NewRunLedger(lifecycle.NewMemStore(), fixedNow)
	w := wl(
		"wl_l1",
		staticEntry(testProject, "A", RecipeCoolifyStart, lifecycle.TierProdShared),
		staticEntry(testProject, "B", RecipeCoolifyStart, lifecycle.TierProdShared),
	)
	require.NoError(t, l.EnsurePlan(w))

	// Yalnızca biri DONE → hâlâ pending.
	require.NoError(t, l.Record("wl_l1", testProject, "A", StateDone, "human:a", nil))
	st, err := l.RunState("wl_l1")
	require.NoError(t, err)
	assert.False(t, st.Complete)
	assert.Equal(t, 1, st.Pending)

	// İkisi de terminal (biri DONE, biri imzalı-SKIPPED) → complete.
	require.NoError(t, l.Record("wl_l1", testProject, "B", StateSkipped, "human:a", map[string]any{"reason": "not-a-secret"}))
	st, err = l.RunState("wl_l1")
	require.NoError(t, err)
	assert.True(t, st.Complete, "DONE + signed-SKIPPED are both terminal")
	assert.Equal(t, 0, st.Pending)
}

// TestLedger_TriageSurfacedUntilSkipped, plan'daki metadata-eksik girdinin
// NeedsTriage bildirdiğini ve ancak imzalı-SKIPPED ile çözüldüğünü kanıtlar (§8.5.5.1).
func TestLedger_TriageSurfacedUntilSkipped(t *testing.T) {
	l := NewRunLedger(lifecycle.NewMemStore(), fixedNow)
	w := wl(
		"wl_l2",
		lifecycle.WorklistEntry{Project: testProject, Key: "NO_META", NeedsTriage: true, BlastTier: lifecycle.TierUnknown, State: StatePending},
	)
	require.NoError(t, l.EnsurePlan(w))

	st, err := l.RunState("wl_l2")
	require.NoError(t, err)
	assert.True(t, st.NeedsTriage)
	assert.False(t, st.Complete)

	// İmzalı-SKIPPED ile triyaj çözülür → complete.
	require.NoError(t, l.Record("wl_l2", testProject, "NO_META", StateSkipped, "human:a", map[string]any{"reason": "manually-triaged"}))
	st, err = l.RunState("wl_l2")
	require.NoError(t, err)
	assert.False(t, st.NeedsTriage, "signed-SKIPPED resolves triage")
	assert.True(t, st.Complete)
}

// TestLedger_EnsurePlanIdempotent, EnsurePlan'in idempotent olduğunu (resume: ikinci
// çağrı planı BOZMAZ) kanıtlar.
func TestLedger_EnsurePlanIdempotent(t *testing.T) {
	mem := lifecycle.NewMemStore()
	l := NewRunLedger(mem, fixedNow)
	w := wl("wl_l3", staticEntry(testProject, "A", RecipeCoolifyStart, lifecycle.TierProdShared))
	require.NoError(t, l.EnsurePlan(w))
	require.NoError(t, l.Record("wl_l3", testProject, "A", StateDone, "human:a", nil))
	// İkinci EnsurePlan (resume) planı yeniden yazmamalı.
	require.NoError(t, l.EnsurePlan(w))
	st, err := l.RunState("wl_l3")
	require.NoError(t, err)
	assert.True(t, st.Complete, "resume EnsurePlan is idempotent, ledger progress preserved")
}

// TestLedger_LatestStateWins, aynı anahtar için EN SON durumun (yazım sırasına göre)
// döndüğünü kanıtlar (resume için).
func TestLedger_LatestStateWins(t *testing.T) {
	l := NewRunLedger(lifecycle.NewMemStore(), fixedNow)
	w := wl("wl_l4", staticEntry(testProject, "A", RecipeCoolifyStart, lifecycle.TierProdShared))
	require.NoError(t, l.EnsurePlan(w))
	require.NoError(t, l.Record("wl_l4", testProject, "A", StateValueMinted, "human:a", nil))
	require.NoError(t, l.Record("wl_l4", testProject, "A", StateStoreWritten, "human:a", nil))
	require.NoError(t, l.Record("wl_l4", testProject, "A", StateFailed, "human:a", nil))
	states, err := l.LatestStates("wl_l4")
	require.NoError(t, err)
	assert.Equal(t, StateFailed, states[stateKey(testProject, "A")], "latest row wins")

	// FAILED terminal DEĞİL → pending.
	st, err := l.RunState("wl_l4")
	require.NoError(t, err)
	assert.False(t, st.Complete)
	assert.Equal(t, 1, st.Pending)
}
