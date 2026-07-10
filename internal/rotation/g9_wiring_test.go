package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// TestG9_OffboardClosesOnlyWhenLedgerTerminal, G11'in ASIL bağlama kanıtıdır: bir
// GERÇEK offboard (G9), ancak-ve-ancak GERÇEK store-backed RunLedger (bu paket) tüm
// değer-rotasyon worklist run'larını TERMİNAL bildirdiğinde CLOSED'a ulaşır
// (§8.5.5.4/§8.5.7). StubRotationRunLedger her run'ı pending bildirir → close
// "awaiting rotation"da bloklu; RunLedger, rotation.Engine worklist'i gerçekten
// yürütüp her girdiyi VERIFIED/DONE yaptıktan SONRA terminal bildirir → close ilerler.
func TestG9_OffboardClosesOnlyWhenLedgerTerminal(t *testing.T) {
	mem := lifecycle.NewMemStore()

	// GERÇEK G11 ledger'ı + motoru (mem RecordStore-backed).
	ledger := NewRunLedger(mem, fixedNow)
	engine := NewEngine(Config{
		Ledger: ledger,
		Values: NewMemValueStore(),
		Now:    fixedNow,
	})

	// lifecycle motorunu GERÇEK ledger'a bağla (StubRotationRunLedger DEĞİL).
	life := lifecycle.New(lifecycle.Config{
		Data: mem, Records: mem, Classifier: prodClassifier, Now: fixedNow,
		RotationRuns: ledger,
	})

	a := newTHuman(t, "adnan@wapps.dev") // çalıştıran admin
	eve := newTHuman(t, "eve@wapps.dev") // ayrılan (read-grantee)
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, testProject), readOnlyGrant(eve.id, testProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})

	// STATIC-origin anahtarlar (recipe'ler DefaultRecipes'te; store-tarafı rotate
	// edilebilir) + rotasyon metadata (triyaj yok).
	seedDataMeta(t, mem, head, testProject, a.daily,
		map[string][]byte{"CF_TOKEN": []byte("cf-old"), "APP_SECRET": []byte("sec-old")},
		map[string]string{
			"CF_TOKEN":   `{"recipe":"coolify-env/start","origin":"static","blast_tier":"platform-anchor"}`,
			"APP_SECRET": `{"recipe":"coolify-env/start","origin":"static","blast_tier":"prod-single"}`,
		})

	// --- Offboard adım 1-4 (non-escrow-holder → tek step-3 run) ---
	_, err := life.OffboardStart(lifecycle.OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{testProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: "ob_g9",
	})
	require.NoError(t, err)
	_, err = life.OffboardStep1Kill("ob_g9", head, a.id, a.admin)
	require.NoError(t, err)
	out2, err := life.OffboardStep2Rewrap("ob_g9", lifecycle.Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin},
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	require.NoError(t, err)
	require.True(t, out2.FullyRotated)
	newHead := out2.NewHead

	out3, err := life.OffboardStep3Rotate("ob_g9", newHead, a.id, a.admin)
	require.NoError(t, err)
	require.Len(t, out3.Worklist.Entries, 2)
	runID := out3.Worklist.RunID
	require.NotEmpty(t, runID)

	_, err = life.OffboardStep4Escrow("ob_g9", newHead, a.id, a.admin)
	require.NoError(t, err)

	// --- BEFORE running the worklist: ledger reports the run PENDING → close BLOCKED ---
	st, err := ledger.RunState(runID)
	require.NoError(t, err)
	assert.False(t, st.Complete, "un-run worklist is not terminal")

	_, err = life.OffboardStep5Close("ob_g9", newHead, a.id, a.admin)
	require.ErrorIs(t, err, lifecycle.ErrRotationPending, "close must block while the ledger reports the run non-terminal")

	reloaded, err := life.LoadOffboard("ob_g9", newHead)
	require.NoError(t, err)
	assert.Equal(t, lifecycle.RecordOpen, reloaded.Status, "record stays OPEN (awaiting rotation)")

	// --- Run the value-rotation worklist through the REAL rotation engine ---
	rep, err := engine.Run(context.Background(), out3.Worklist, NewMockExecutor(), a.id, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Done, "both static keys rotated to DONE")

	// Ledger now reports the run TERMINAL.
	st, err = ledger.RunState(runID)
	require.NoError(t, err)
	assert.True(t, st.Complete, "ledger reports terminal once every entry is VERIFIED/DONE")
	assert.Equal(t, 0, st.Pending)
	assert.False(t, st.NeedsTriage)

	// --- NOW close succeeds — and the attestation is honest ---
	closed, err := life.OffboardStep5Close("ob_g9", newHead, a.id, a.admin)
	require.NoError(t, err, "close proceeds once the ledger reports the run terminal")
	assert.Equal(t, lifecycle.RecordClosed, closed.Status)
	assert.Equal(t, lifecycle.StepDone, closed.Steps.Close.Status)
	assert.Equal(t, lifecycle.StepDone, closed.Steps.Rotate.Status, "rotation finalized on verified completion")
}

// TestG9_LedgerBlocksCloseOnTriage, metadata-EKSİK bir girdi worklist'te olduğunda
// (ROTATION_METADATA_MISSING) run'ın TERMİNAL olamadığını ve offboard close'un
// bloklandığını kanıtlar (§8.5.5.1). rotation.Engine metadata-eksik girdiyi rotate
// ETMEZ (NEEDS_TRIAGE) → ledger NeedsTriage bildirir → close ErrRotationTriageRequired.
func TestG9_LedgerBlocksCloseOnTriage(t *testing.T) {
	mem := lifecycle.NewMemStore()
	ledger := NewRunLedger(mem, fixedNow)
	engine := NewEngine(Config{Ledger: ledger, Values: NewMemValueStore(), Now: fixedNow})
	life := lifecycle.New(lifecycle.Config{
		Data: mem, Records: mem, Classifier: prodClassifier, Now: fixedNow, RotationRuns: ledger,
	})

	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, testProject), readOnlyGrant(eve.id, testProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})
	// NO_META → NeedsTriage.
	seedDataMeta(t, mem, head, testProject, a.daily, map[string][]byte{"NO_META": []byte("x")}, nil)

	_, err := life.OffboardStart(lifecycle.OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{testProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: "ob_triage",
	})
	require.NoError(t, err)
	_, err = life.OffboardStep1Kill("ob_triage", head, a.id, a.admin)
	require.NoError(t, err)
	out2, err := life.OffboardStep2Rewrap("ob_triage", lifecycle.Step2Input{
		Head: head, RevokeSigners: []cryptoid.SigningKey{a.admin}, RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader: a.device, Writer: a.daily, WriterID: a.id, RunnerID: a.id, RecordSigner: a.admin,
	})
	require.NoError(t, err)
	newHead := out2.NewHead
	out3, err := life.OffboardStep3Rotate("ob_triage", newHead, a.id, a.admin)
	require.NoError(t, err)
	_, err = life.OffboardStep4Escrow("ob_triage", newHead, a.id, a.admin)
	require.NoError(t, err)

	// Even after "running" the worklist, the triage entry never becomes terminal.
	_, err = engine.Run(context.Background(), out3.Worklist, NewMockExecutor(), a.id, nil)
	require.NoError(t, err)
	st, err := ledger.RunState(out3.Worklist.RunID)
	require.NoError(t, err)
	assert.True(t, st.NeedsTriage, "ledger surfaces the metadata-missing entry")
	assert.False(t, st.Complete)

	_, err = life.OffboardStep5Close("ob_triage", newHead, a.id, a.admin)
	require.ErrorIs(t, err, lifecycle.ErrRotationTriageRequired, "close refused while an entry needs triage")
}
