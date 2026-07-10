package rotation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
)

// mirrorEntry, origin:"tofu" bir worklist girdisi kurar (store-tarafı mint reddi →
// MIRROR_ONLY_ORIGIN). Metadata mevcut (NeedsTriage=false).
func mirrorEntry(project, key string) lifecycle.WorklistEntry {
	return lifecycle.WorklistEntry{
		Project: project, Key: key, Recipe: "db-role/phase1", Origin: OriginTofu,
		BlastTier: lifecycle.TierProdShared, State: StatePending,
	}
}

// TestLedger_MirrorOnlyIsTerminal (FIX #6): origin:tofu bir anahtar, store'da rotate
// EDİLEMEZ ve MIRROR_ONLY_ORIGIN ledger satırı yazar — bu artık TERMİNAL sayılır, run
// Complete'e ulaşır. Aksi halde tofu-origin anahtar içeren HER vaulter offboard'ı
// ASLA kapanamazdı.
func TestLedger_MirrorOnlyIsTerminal(t *testing.T) {
	l := NewRunLedger(lifecycle.NewMemStore(), fixedNow)
	w := wl("wl_mirror",
		staticEntry(testProject, "APP_KEY", RecipeCoolifyStart, lifecycle.TierProdShared),
		mirrorEntry(testProject, "DATABASE_URL"),
	)
	require.NoError(t, l.EnsurePlan(w))

	// APP_KEY DONE, DATABASE_URL henüz hiç işlenmedi → pending.
	require.NoError(t, l.Record("wl_mirror", testProject, "APP_KEY", StateDone, "human:a", nil))
	st, err := l.RunState("wl_mirror")
	require.NoError(t, err)
	assert.False(t, st.Complete)
	assert.Equal(t, 1, st.Pending)

	// Rotasyon motoru tofu anahtarı için MIRROR_ONLY yazar → TERMİNAL → run complete.
	require.NoError(t, l.Record("wl_mirror", testProject, "DATABASE_URL", StateMirrorOnly, "rotation-engine", nil))
	st, err = l.RunState("wl_mirror")
	require.NoError(t, err)
	assert.True(t, st.Complete, "MIRROR_ONLY_ORIGIN must be terminal (tofu keys rotate at origin, attested separately)")
	assert.Equal(t, 0, st.Pending)
	assert.False(t, st.NeedsTriage)
}

// TestLedger_NeedsTriageBlocksUntilSignedSkip (FIX #6): metadata-eksik (NEEDS_TRIAGE)
// bir anahtar, run'ı bloklar; ancak ADMIN-İMZALI SkipKey ile SKIPPED'e geçince triyaj
// çözülür ve run Complete'e ulaşır — RunState'in var saydığı kaçış kapısı.
func TestLedger_NeedsTriageBlocksUntilSignedSkip(t *testing.T) {
	mem := lifecycle.NewMemStore()
	l := NewRunLedger(mem, fixedNow)
	w := wl("wl_triage",
		lifecycle.WorklistEntry{Project: testProject, Key: "NO_META", NeedsTriage: true, BlastTier: lifecycle.TierUnknown, State: StatePending},
	)
	require.NoError(t, l.EnsurePlan(w))

	// NEEDS_TRIAGE → bloklu.
	st, err := l.RunState("wl_triage")
	require.NoError(t, err)
	assert.True(t, st.NeedsTriage)
	assert.False(t, st.Complete)

	// İmzasız/gerekçesiz SkipKey reddedilir.
	admin, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	require.Error(t, l.SkipKey("wl_triage", testProject, "NO_META", "", "human:a", admin), "reason zorunlu")
	require.Error(t, l.SkipKey("wl_triage", testProject, "NO_META", "manually-triaged", "human:a", nil), "signer zorunlu")

	// Admin-imzalı SkipKey → StateSkipped satırı → triyaj çözülür, run complete.
	require.NoError(t, l.SkipKey("wl_triage", testProject, "NO_META", "value is a public constant; not a secret", "human:a", admin))
	st, err = l.RunState("wl_triage")
	require.NoError(t, err)
	assert.False(t, st.NeedsTriage, "signed-SKIP resolves triage")
	assert.True(t, st.Complete)

	// Yazılan satır GERÇEKTEN imzalı (evidence: attestation + key_id + sig).
	states, err := l.LatestStates("wl_triage")
	require.NoError(t, err)
	assert.Equal(t, StateSkipped, states[stateKey(testProject, "NO_META")])
	rows := ledgerRows(t, mem, "wl_triage")
	require.NotEmpty(t, rows)
	last := rows[len(rows)-1]
	require.Equal(t, StateSkipped, last.State)
	var ev skipEvidence
	require.NoError(t, json.Unmarshal(last.Evidence, &ev))
	assert.Equal(t, skipAttestationSchema, ev.Attestation.Schema)
	assert.NotEmpty(t, ev.KeyID, "signed skip must record the admin key fingerprint")
	assert.NotEmpty(t, ev.Sig, "signed skip must carry a signature")
	assert.Equal(t, "human:a", ev.Attestation.By)
}
