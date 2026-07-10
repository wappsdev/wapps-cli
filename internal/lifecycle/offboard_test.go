package lifecycle

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// completeRuns, TÜM worklist run'larını TERMİNAL (yürütülmüş, triyaj yok) bildiren
// sahte G11 rotasyon ledger'ıdır — gerçek G11 bağlandığında offboard close'unun
// "awaiting rotation"dan ilerleyip kapandığını (§8.5.5.4/§8.5.7) kanıtlamak için.
type completeRuns struct{}

func (completeRuns) RunState(runID string) (RotationRunState, error) {
	return RotationRunState{RunID: runID, Complete: true, Pending: 0}, nil
}

// offboardSoloWorld, tek admin A + granted-read EVE + escrow olan bir dünya kurar
// (E2E offboard). meta ile worklist blast-tier'ları sınanabilir.
func offboardSoloWorld(t *testing.T) (*Engine, *MemStore, tHuman, tHuman, tEscrow, *trust.VerifiedEpoch) {
	t.Helper()
	mem := NewMemStore()
	e := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})
	seedDataMeta(t, mem, head, rwProject, a.daily, map[string][]byte{
		"CF_TOKEN": []byte("cf"), "DB_URL": []byte("db"),
	}, map[string]string{
		"CF_TOKEN": `{"recipe":"cf-manual","origin":"static","blast_tier":"platform-anchor"}`,
		"DB_URL":   `{"recipe":"db-role/phase1","origin":"tofu","blast_tier":"prod-shared"}`,
	})
	return e, mem, a, eve, esc, head
}

// driveToEscrow, offboard'ı adım 1-4'ten geçirir (kill → rewrap → rotate → escrow)
// ve step2/step3/step4 çıktılarını + rewrap sonrası head'i döner. E2E + close
// testlerinin ORTAK gövdesi (P2-a/P2-b: close'a kadar).
func driveToEscrow(t *testing.T, e *Engine, a, eve tHuman, head *trust.VerifiedEpoch, recID string, escrowHolder bool) (*trust.VerifiedEpoch, *Step3Output, *Step4Output) {
	t.Helper()
	_, err := e.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		EscrowShareHolder: escrowHolder, OpenedBy: a.id, Signer: a.admin, RecordID: recID,
	})
	require.NoError(t, err)

	_, err = e.OffboardStep1Kill(recID, head, a.id, a.admin)
	require.NoError(t, err)

	out2, err := e.OffboardStep2Rewrap(recID, Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin},
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	require.NoError(t, err)
	require.True(t, out2.FullyRotated, "rewrap must reach 100%")
	newHead := out2.NewHead

	out3, err := e.OffboardStep3Rotate(recID, newHead, a.id, a.admin)
	require.NoError(t, err)
	out4, err := e.OffboardStep4Escrow(recID, newHead, a.id, a.admin)
	require.NoError(t, err)
	return newHead, out3, out4
}

// TestOffboard_EndToEnd, offboard durum makinesini uçtan uca kanıtlar: kill →
// rewrap(%100 + attestation) → worklist(en yüksek blast önce, ROTATION_PENDING) →
// escrow re-key (paylar bir kez + TÜM-PROJELER worklist) → close BLOKLU. P2-a: G11
// rotasyonu YÜRÜTMEDEN close olmaz — kayıt "awaiting rotation"da kalır, ASLA
// closed olmaz + sahte attestation basılmaz.
func TestOffboard_EndToEnd(t *testing.T) {
	e, mem, a, eve, _, head := offboardSoloWorld(t)

	// --- OPEN ---
	rec, err := e.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		EscrowShareHolder: true, OpenedBy: a.id, Signer: a.admin, RecordID: "ob_e2e",
	})
	require.NoError(t, err)
	require.Equal(t, RecordOpen, rec.Status)

	// --- STEP 1: KILL (stub token-revoke kanıtı) ---
	r1, err := e.OffboardStep1Kill("ob_e2e", head, a.id, a.admin)
	require.NoError(t, err)
	assert.Equal(t, StepDone, r1.Steps.Kill.Status)
	var ev RevokeEvidence
	require.NoError(t, json.Unmarshal(r1.Steps.Kill.Evidence, &ev))
	assert.True(t, ev.Stubbed, "token revoke is a stubbed interface (G-account wiring pending)")

	// --- STEP 2: REWRAP (revoke+retire+re-mint) ---
	out2, err := e.OffboardStep2Rewrap("ob_e2e", Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin}, // solo → 1 admin
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	require.NoError(t, err)
	assert.True(t, out2.FullyRotated, "rewrap must reach 100%")
	assert.Equal(t, StepDone, out2.Record.Steps.Rewrap.Status)
	require.NotEmpty(t, out2.Record.Steps.Rewrap.Attestations, "fully-rotated attestation attached")
	newHead := out2.NewHead

	// EVE artık hiçbir anahtarı çözemez.
	for _, k := range []string{"CF_TOKEN", "DB_URL"} {
		_, derr := decryptAs(t, mem, rwProject, k, eve.device)
		require.Error(t, derr, "EVE must not decrypt %q post-offboard", k)
	}

	// --- STEP 3: ROTATE (worklist) — P2-a: emisyon ≠ yürütme → ROTATION_PENDING ---
	out3, err := e.OffboardStep3Rotate("ob_e2e", newHead, a.id, a.admin)
	require.NoError(t, err)
	assert.Equal(t, StepRotationPending, out3.Record.Steps.Rotate.Status, "worklist emitted, NOT executed")
	require.Len(t, out3.Worklist.Entries, 2)
	// En yüksek blast önce: CF_TOKEN (platform-anchor) < DB_URL (prod-shared).
	assert.Equal(t, "CF_TOKEN", out3.Worklist.Entries[0].Key)
	assert.Equal(t, TierPlatformAnchor, out3.Worklist.Entries[0].BlastTier)
	assert.Equal(t, "DB_URL", out3.Worklist.Entries[1].Key)

	// --- STEP 4: ESCROW re-key + P2-b TÜM-PROJELER worklist ---
	out4, err := e.OffboardStep4Escrow("ob_e2e", newHead, a.id, a.admin)
	require.NoError(t, err)
	require.NotNil(t, out4.Rekey, "escrow-share holder → re-key performed")
	require.NotNil(t, out4.Worklist, "escrow-share holder → ALL-projects value-rotation worklist emitted")
	assert.Equal(t, StepDone, out4.Record.Steps.Escrow.Status)
	require.NotEmpty(t, out4.Record.Steps.Escrow.WorklistRuns, "escrow worklist run required before close")

	// Paylar BİR KEZ + 2-of-3 birleşimi yeni escrow anahtarını verir (§3.9).
	shares := out4.Rekey.SharesOnce()
	require.Len(t, shares, 3)
	assert.Nil(t, out4.Rekey.SharesOnce(), "shares retrievable only once")
	scalar, cerr := cryptoid.ShamirCombine([][]byte{shares[0], shares[2]})
	require.NoError(t, cerr)
	recombined, cerr := cryptoid.NewX25519IdentityFromScalar(scalar)
	require.NoError(t, cerr)
	assert.Equal(t, out4.Rekey.Fingerprint, recombined.Recipient().Fingerprint(), "2-of-3 shares reconstruct the new escrow key")

	// --- STEP 5: CLOSE — P2-a: G11 rotasyonu YÜRÜTMEDEN close BLOKLU ---
	_, err = e.OffboardStep5Close("ob_e2e", newHead, a.id, a.admin)
	require.ErrorIs(t, err, ErrRotationPending, "close blocked until worklist runs are executed (G11 out of scope)")

	// Kayıt "awaiting rotation"da: kill+rewrap+escrow done, rotation pending, close
	// pending, status OPEN — ASLA closed değil, sahte attestation yok.
	reloaded, err := e.LoadOffboard("ob_e2e", newHead)
	require.NoError(t, err)
	assert.Equal(t, RecordOpen, reloaded.Status, "must NOT reach closed on emission")
	assert.Equal(t, StepRotationPending, reloaded.Steps.Rotate.Status)
	assert.NotEqual(t, StepDone, reloaded.Steps.Close.Status, "no final all_steps_verified attestation")
}

// TestOffboard_ClosesWhenRotationComplete, gerçek G11 ledger'ı (completeRuns) TÜM
// worklist run'larını (step-3 + escrow all-projects) terminal bildirince offboard'ın
// kapandığını + DÜRÜST all_steps_verified attestation'ı bastığını kanıtlar (P2-a/P2-b
// forward-compat: close artık gerçek rotasyon yürütmesine bağlı).
func TestOffboard_ClosesWhenRotationComplete(t *testing.T) {
	_, mem, a, eve, _, head := offboardSoloWorld(t)
	// Aynı mem üzerinde ama TAMAMLANMA bildiren ledger'lı bir motor.
	e := New(Config{Data: mem, Records: mem, Classifier: prodClassifier, Now: fixedNow, RotationRuns: completeRuns{}})

	newHead, _, out4 := driveToEscrow(t, e, a, eve, head, "ob_done", true)
	require.NotNil(t, out4.Worklist)

	closed, err := e.OffboardStep5Close("ob_done", newHead, a.id, a.admin)
	require.NoError(t, err, "close succeeds once rotation runs are terminal")
	assert.Equal(t, RecordClosed, closed.Status)
	assert.Equal(t, StepDone, closed.Steps.Close.Status)
	assert.Equal(t, StepDone, closed.Steps.Rotate.Status, "rotation finalized on verified completion")
	var final map[string]any
	require.NoError(t, json.Unmarshal(closed.Steps.Close.Evidence, &final))
	assert.Equal(t, true, final["all_steps_verified"], "attestation is honest — runs actually verified")
}

// TestOffboard_CloseBlockedByTriage, rotasyon-metadata'sı EKSİK (ROTATION_METADATA_
// MISSING) bir giriş varken offboard'ın KAPATILAMADIĞINI kanıtlar (P2-a/§8.5.5.1:
// close bu girdileri swallow ETMEZ). completeRuns ledger'ı bile bunu bypass edemez —
// triyaj bloğu emisyon-anı bilgisinden ledger'dan BAĞIMSIZ zorlanır.
func TestOffboard_CloseBlockedByTriage(t *testing.T) {
	mem := NewMemStore()
	// TAMAMLANMA bildiren ledger'la bile: triyaj close'u yine de bloklamalı.
	e := New(Config{Data: mem, Records: mem, Classifier: prodClassifier, Now: fixedNow, RotationRuns: completeRuns{}})
	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, a.id, a.id},
		m:          2, solo: true,
	})
	// NO_META anahtarı → NeedsTriage.
	seedData(t, mem, head, rwProject, a.daily, map[string][]byte{"NO_META": []byte("x")})

	newHead, out3, _ := driveToEscrow(t, e, a, eve, head, "ob_triage", false)
	require.Len(t, out3.Worklist.Entries, 1)
	require.True(t, out3.Worklist.Entries[0].NeedsTriage, "metadata-missing key flagged for triage")

	_, err := e.OffboardStep5Close("ob_triage", newHead, a.id, a.admin)
	require.ErrorIs(t, err, ErrRotationTriageRequired, "close must refuse while any entry needs triage")
}

// TestOffboard_EscrowRotatesAllProjects, escrow-share sahibi offboard'ında değer-
// rotasyon worklist'inin TÜM projeleri (yalnızca scope.Projects DEĞİL) kapsadığını
// kanıtlar (P2-b/§8.5.4/§9.4.4: escrow her wrap-set'in üyesi → eski snapshot'ları
// burn etmek her projedeki her değeri döndürmeyi gerektirir). scope.Projects yalnızca
// rwProject; escrow worklist'i ayrıca EVE'nin grant'lı OLMADIĞI otherProject'i de
// kapsamalı.
func TestOffboard_EscrowRotatesAllProjects(t *testing.T) {
	const otherProject = "vaulter-other"
	mem := NewMemStore()
	e := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id},
		grants: []registry.Grant{
			readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject),
			readWriteGrant(a.id, otherProject), // EVE otherProject'te grant'sız
		},
		roots:   []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders: []string{a.id, a.id, a.id},
		m:       2, solo: true,
	})
	seedDataMeta(t, mem, head, rwProject, a.daily, map[string][]byte{"CF_TOKEN": []byte("cf")},
		map[string]string{"CF_TOKEN": `{"recipe":"cf-manual","origin":"static","blast_tier":"platform-anchor"}`})
	seedDataMeta(t, mem, head, otherProject, a.daily, map[string][]byte{"OTHER_KEY": []byte("o")},
		map[string]string{"OTHER_KEY": `{"recipe":"db-role/phase1","origin":"tofu","blast_tier":"prod-shared"}`})

	newHead, out3, out4 := driveToEscrow(t, e, a, eve, head, "ob_allproj", true)

	// Step-3 worklist'i YALNIZCA scope.Projects (rwProject) kapsar.
	require.Len(t, out3.Worklist.Entries, 1)
	assert.Equal(t, rwProject, out3.Worklist.Entries[0].Project)

	// Escrow (step-4) worklist'i TÜM projeleri kapsar — otherProject DAHİL.
	require.NotNil(t, out4.Worklist)
	projects := map[string]bool{}
	for _, en := range out4.Worklist.Entries {
		projects[en.Project] = true
	}
	assert.True(t, projects[rwProject], "escrow worklist covers rwProject")
	assert.True(t, projects[otherProject], "escrow worklist MUST cover a project EVE was never granted (escrow burn)")

	// Bu run close'dan önce zorunlu → default stub'la close pending.
	require.NotEmpty(t, out4.Record.Steps.Escrow.WorklistRuns)
	_, err := e.OffboardStep5Close("ob_allproj", newHead, a.id, a.admin)
	require.ErrorIs(t, err, ErrRotationPending)
}

// TestOffboard_CannotBeRunByDeparting, offboard'ın AYRILAN prensip tarafından
// AÇILAMAYACAĞINI kanıtlar (§8.5, ≥2 admin — hiçbir adım tek çalıştırıcısı ayrılan
// olamaz).
func TestOffboard_CannotBeRunByDeparting(t *testing.T) {
	e, _, _, eve, _, _ := offboardSoloWorld(t)
	_, err := e.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		OpenedBy: eve.id, Signer: eve.admin,
	})
	require.ErrorIs(t, err, ErrDepartingRunner)
}

// TestOffboard_NonAdminCannotRunStep, offboard adımlarının aktif bir admin OLMAYAN
// bir imzalayan tarafından çalıştırılamayacağını kanıtlar (P3-a: çalıştırıcı imzalama
// anahtarına kriptografik olarak bağlanır). EVE bir read-grantee, admin değil →
// eve.admin ile adım imzalamak reddedilir.
func TestOffboard_NonAdminCannotRunStep(t *testing.T) {
	e, _, a, eve, _, head := offboardSoloWorld(t)
	_, err := e.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: "ob_guard",
	})
	require.NoError(t, err)
	// EVE aktif admin değil → adımı kendi anahtarıyla imzalamak reddedilir.
	_, err = e.OffboardStep1Kill("ob_guard", head, eve.id, eve.admin)
	require.ErrorIs(t, err, ErrRunnerIdentityMismatch)
}

// TestOffboard_DepartingAdminCannotRunStep, AYRILAN prensibin hâlâ AKTİF bir admin
// olduğu (step-2 retire ÖNCESİ) durumda bile bir adımı KENDİ anahtarıyla — başka bir
// runnerID spoof'layarak — çalıştıramayacağını kanıtlar (P3-a asıl açık): guard
// caller'ın verdiği stringe değil, imzayı ÜRETEN anahtarın sahibi kimliğe bağlanır.
func TestOffboard_DepartingAdminCannotRunStep(t *testing.T) {
	mem := NewMemStore()
	e := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev") // ayrılan AMA hâlâ aktif admin
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id, eve.id}, // EVE de admin
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, eve.id, "human:carol@wapps.dev"},
		m:          2, solo: false,
	})
	seedData(t, mem, head, rwProject, a.daily, map[string][]byte{"K": []byte("v")})

	_, err := e.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "compromise", Projects: []string{rwProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: "ob_dep_admin",
	})
	require.NoError(t, err)

	// EVE spoof'lar: runnerID=a.id iddia eder ama KENDİ anahtarıyla (eve.admin) imzalar.
	// Guard imza sahibini (eve) çözer → ayrılan prensip → reddedilir.
	_, err = e.OffboardStep1Kill("ob_dep_admin", head, a.id, eve.admin)
	require.ErrorIs(t, err, ErrDepartingRunner, "departing admin cannot drive a step with their own key")

	// Ters spoof: A imzalar ama runnerID=eve.id iddia eder → imza/iddia uyuşmazlığı.
	_, err = e.OffboardStep1Kill("ob_dep_admin", head, eve.id, a.admin)
	require.ErrorIs(t, err, ErrRunnerIdentityMismatch, "claimed runnerID must match the signing key owner")

	// Meşru: A hem imzalar hem doğru runnerID iddia eder → geçer.
	_, err = e.OffboardStep1Kill("ob_dep_admin", head, a.id, a.admin)
	require.NoError(t, err)
}

// TestOffboard_DeviceScopedRejected, cihaz-kapsamlı offboard'ın (scope.Devices dolu)
// sessizce TÜM kimliği kaldırmak yerine açıkça REDDEDİLDİĞİNİ kanıtlar (P3-b/§8.2:
// gerçek cihaz-kapsamı desteği = izlenen takip işi).
func TestOffboard_DeviceScopedRejected(t *testing.T) {
	e, _, a, eve, _, head := offboardSoloWorld(t)
	_, err := e.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "device_loss", Projects: []string{rwProject},
		Devices:  []string{"dev:eve-laptop"}, // tek cihaz kapsamı
		OpenedBy: a.id, Signer: a.admin, RecordID: "ob_dev",
	})
	require.NoError(t, err)
	// Kill (kripto-dokunmaz) geçebilir; rewrap fazla-kaldırmadan ÖNCE reddetmeli.
	_, err = e.OffboardStep1Kill("ob_dev", head, a.id, a.admin)
	require.NoError(t, err)
	_, err = e.OffboardStep2Rewrap("ob_dev", Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin},
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	require.ErrorIs(t, err, ErrDeviceOffboardUnsupported, "device-scoped offboard must reject, not over-remove the whole identity")
}

// TestOffboard_ResumeByAnotherAdmin, kaydın laptop kaybından sağ çıktığını ve BAŞKA
// bir admin'in --resume edip kapatabildiğini kanıtlar (§8.5.1): de-solo (A,B) dünyada
// A start+kill+rewrap(2-admin co-sign) yapar; TAZE bir motorla (farklı laptop +
// tamamlanma bildiren G11 ledger'ı) B step 3-5'i devralır ve kapatır.
func TestOffboard_ResumeByAnotherAdmin(t *testing.T) {
	mem := NewMemStore()
	engA := newEngine(mem)
	a := newTHuman(t, "adnan@wapps.dev")
	b := newTHuman(t, "bob@wapps.dev")
	eve := newTHuman(t, "eve@wapps.dev")
	esc := newTEscrow(t)
	r0, r1, r2 := edFromSeed(t, 1), edFromSeed(t, 2), edFromSeed(t, 3)
	head, _ := buildGenesis(t, genesisSpec{
		identities: []registry.Identity{a.identity(), b.identity(), eve.identity(), esc.id},
		adminIDs:   []string{a.id, b.id},
		grants:     []registry.Grant{readWriteGrant(a.id, rwProject), readOnlyGrant(eve.id, rwProject)},
		roots:      []*cryptoid.Ed25519SigningKey{r0, r1, r2},
		holders:    []string{a.id, b.id, "human:carol@wapps.dev"},
		m:          2, solo: false,
	})
	// Metadata'lı seed → worklist'te triyaj yok (close ilerleyebilir).
	seedDataMeta(t, mem, head, rwProject, a.daily, map[string][]byte{"A": []byte("val-A"), "B": []byte("val-B")},
		map[string]string{
			"A": `{"recipe":"cf-manual","origin":"static","blast_tier":"platform-anchor"}`,
			"B": `{"recipe":"db-role/phase1","origin":"tofu","blast_tier":"prod-shared"}`,
		})

	// A açar + kill + rewrap (revoke 2-admin co-sign — prod tier, N_h=2).
	_, err := engA.OffboardStart(OffboardStartRequest{
		Principal: eve.id, Reason: "departure", Projects: []string{rwProject},
		OpenedBy: a.id, Signer: a.admin, RecordID: "ob_resume",
	})
	require.NoError(t, err)
	_, err = engA.OffboardStep1Kill("ob_resume", head, a.id, a.admin)
	require.NoError(t, err)
	out2, err := engA.OffboardStep2Rewrap("ob_resume", Step2Input{
		Head:          head,
		RevokeSigners: []cryptoid.SigningKey{a.admin, b.admin}, // ≥2 admin rewrap
		RetireSigners: []cryptoid.SigningKey{a.admin},
		Reader:        a.device, Writer: a.daily, WriterID: a.id,
		RunnerID: a.id, RecordSigner: a.admin,
	})
	require.NoError(t, err)
	require.True(t, out2.FullyRotated)
	newHead := out2.NewHead

	// --- BAŞKA admin (B), TAZE motor (farklı laptop) + G11 ledger ile resume eder ---
	engB := New(Config{Data: mem, Records: mem, Classifier: prodClassifier, Now: fixedNow, RotationRuns: completeRuns{}})

	// B kaydı store'dan yükleyebilmeli (laptop kaybından sağ çıktı).
	loaded, err := engB.LoadOffboard("ob_resume", newHead)
	require.NoError(t, err)
	assert.Equal(t, StepDone, loaded.Steps.Rewrap.Status, "resumed record carries A's completed rewrap")

	out3, err := engB.OffboardStep3Rotate("ob_resume", newHead, b.id, b.admin)
	require.NoError(t, err)
	assert.Equal(t, StepRotationPending, out3.Record.Steps.Rotate.Status)

	out4, err := engB.OffboardStep4Escrow("ob_resume", newHead, b.id, b.admin)
	require.NoError(t, err)
	assert.Nil(t, out4.Rekey, "not an escrow-share holder → no re-key")
	assert.Nil(t, out4.Worklist, "no escrow → no all-projects worklist")

	closed, err := engB.OffboardStep5Close("ob_resume", newHead, b.id, b.admin)
	require.NoError(t, err)
	assert.Equal(t, RecordClosed, closed.Status, "another admin closed the resumed offboard")
	_ = esc
}
