package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/intent"
	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// --- Witness head publish ---------------------------------------------------

func TestPublishHeads(t *testing.T) {
	f := newFixture(t)
	res, err := Verify(context.Background(), f.store, cfgOf(f))
	require.NoError(t, err)

	w := NewMemStore()
	require.NoError(t, PublishHeads(context.Background(), w, res, "ci.meapps.dev"))

	// Per-proje head yayınlandı + otoritatif alanlar doğru.
	raw, ok := w.Objects["witness/"+fixProject+".json"]
	require.True(t, ok)
	var head WitnessHead
	require.NoError(t, json.Unmarshal(raw, &head))
	require.Equal(t, SchemaWitnessHead, head.Schema)
	require.EqualValues(t, 2, head.Epoch)
	require.Equal(t, f.headHash, head.ManifestSha256)

	// Trust head + verification raporu da yayınlandı.
	require.Contains(t, w.Objects, "witness/trust.json")
	rep, ok := w.Objects["verification/latest.json"]
	require.True(t, ok)
	var vr verificationReport
	require.NoError(t, json.Unmarshal(rep, &vr))
	require.True(t, vr.OK)
}

// --- intent.Witness (HTTPWitness) drives deploy fresh-or-fail ---------------

// witnessServer, /witness/<project>.json'u serve eden bir non-CF origin taklidir.
func witnessServer(t *testing.T, head WitnessHead) *httptest.Server {
	t.Helper()
	body, _ := json.Marshal(head)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/witness/"+head.Project+".json" {
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPWitness_HeadEpoch_OK(t *testing.T) {
	now := time.Now()
	srv := witnessServer(t, WitnessHead{Schema: SchemaWitnessHead, Project: "vaulter", Epoch: 7, ManifestSha256: "abc", VerifiedAt: now.UTC().Format(time.RFC3339)})
	w := &HTTPWitness{Origin: srv.URL, Project: "vaulter", Client: srv.Client(), Now: func() time.Time { return now }, FailOnStale: true}
	got, err := w.HeadEpoch()
	require.NoError(t, err)
	require.EqualValues(t, 7, got)
}

// Deploy fresh-or-fail: witness epoch > fetched → WITNESS_CONTRADICTION (hard fail).
func TestCheckWitness_Contradiction(t *testing.T) {
	now := time.Now()
	srv := witnessServer(t, WitnessHead{Schema: SchemaWitnessHead, Project: "vaulter", Epoch: 9, VerifiedAt: now.UTC().Format(time.RFC3339)})
	w := &HTTPWitness{Origin: srv.URL, Project: "vaulter", Client: srv.Client(), Now: func() time.Time { return now }, FailOnStale: true}
	// Cloudflare bize epoch 5 sundu ama tanık epoch 9 gördü → freeze/rollback.
	err := intent.CheckWitness(w, 5)
	require.Error(t, err)
	require.True(t, clierr.Is(err, clierr.WitnessContradiction), "want WITNESS_CONTRADICTION, got %v", err)
}

// Witness unreachable under deploy → WITNESS_UNREACHABLE (fail-closed, F6).
func TestCheckWitness_Unreachable(t *testing.T) {
	// Kapalı bir origin (bağlantı reddi) → HeadEpoch hata → CheckWitness fail-closed.
	w := &HTTPWitness{Origin: "http://127.0.0.1:1", Project: "vaulter", Client: &http.Client{Timeout: 500 * time.Millisecond}, FailOnStale: true}
	err := intent.CheckWitness(w, 5)
	require.Error(t, err)
	require.True(t, clierr.Is(err, clierr.WitnessUnreachable), "want WITNESS_UNREACHABLE, got %v", err)
}

// Stale witness head (>2h) → HeadEpoch hata → CheckWitness fail-closed (F6).
func TestHTTPWitness_StaleFailsClosed(t *testing.T) {
	now := time.Now()
	srv := witnessServer(t, WitnessHead{Schema: SchemaWitnessHead, Project: "vaulter", Epoch: 3, VerifiedAt: now.Add(-3 * time.Hour).UTC().Format(time.RFC3339)})
	w := &HTTPWitness{Origin: srv.URL, Project: "vaulter", Client: srv.Client(), Now: func() time.Time { return now }, FailOnStale: true}
	_, err := w.HeadEpoch()
	require.Error(t, err)
	// deploy tüketiminde bu WITNESS_UNREACHABLE'a çevrilir.
	require.True(t, clierr.Is(intent.CheckWitness(w, 3), clierr.WitnessUnreachable))
}

// --- DR restore roundtrip ---------------------------------------------------

func TestRestore_Roundtrip(t *testing.T) {
	f := newFixture(t)
	res, err := Verify(context.Background(), f.store, cfgOf(f))
	require.NoError(t, err)

	restored, err := Restore(context.Background(), f.store, res, fixProject, f.escrow, RestorePathA, fixTime)
	require.NoError(t, err)

	// Reconstructed current pointer head epoch/hash ile tutarlı.
	require.EqualValues(t, 2, restored.Current.Epoch)
	require.Equal(t, f.headHash, restored.Current.ManifestSha256)

	// Escrow wrap'lerinden açılan değerler head epoch'un doğru plaintext'i.
	require.Equal(t, []byte("postgres://secret-2"), restored.Values["DATABASE_URL"])
	require.Equal(t, []byte("canary-plaintext-v1"), restored.Values[CANARY_KEY])

	// Epoch-reset kaydı üretildi (§9.5.4).
	require.Equal(t, SchemaDataEpochReset, restored.EpochReset.Schema)
	require.Equal(t, string(RestorePathA), restored.EpochReset.Reason)
	require.EqualValues(t, 2, restored.EpochReset.ResetFromEpoch)
}

// --- Escrow keygen + Shamir split/recombine ---------------------------------

func TestEscrowKeygen_ShamirRoundtrip(t *testing.T) {
	// Deterministik rng ile keygen.
	seed := bytes.Repeat([]byte{0x42}, 4096)
	kp, err := GenerateEscrowKeypair(bytes.NewReader(seed))
	require.NoError(t, err)
	require.Len(t, kp.Shares, 3)
	require.NotEmpty(t, kp.Recipient)

	// Herhangi 2 pay recipient'ı tam olarak geri üretir.
	pairs := [][][]byte{
		{kp.Shares[0], kp.Shares[1]},
		{kp.Shares[0], kp.Shares[2]},
		{kp.Shares[1], kp.Shares[2]},
	}
	for _, pair := range pairs {
		id, err := ReconstructEscrowKey(pair)
		require.NoError(t, err)
		require.Equal(t, kp.Recipient, id.Recipient().String(), "2-of-3 reconstruct must match")
		require.Equal(t, kp.Fingerprint, id.Fingerprint())
	}

	// Tek pay YETMEZ (ShamirCombine ≥2 ister).
	_, err = ReconstructEscrowKey([][]byte{kp.Shares[0]})
	require.Error(t, err)
}

// --- Escrow canary decrypt (§9.7a) ------------------------------------------

func TestVerifyCanary_LiveAndForged(t *testing.T) {
	// Yayınlanmış (non-secret) canary DEK + plaintext.
	dek, err := cryptoid.NewDEK()
	require.NoError(t, err)
	plain := []byte("published-canary-plaintext")
	escrow, err := cryptoid.GenerateX25519Identity()
	require.NoError(t, err)
	rec := escrow.Recipient()
	slot := cryptoid.Slot{Project: "vaulter", KeyName: CANARY_KEY, KeyVersion: 1}
	wrap, err := cryptoid.SealDEK(dek, rec, slot)
	require.NoError(t, err)
	blob, err := cryptoid.SealBlob(plain, dek, slot)
	require.NoError(t, err)

	// LIVE: wrap doğru → geçer (decrypt + re-derive byte-compare + blob open).
	require.NoError(t, VerifyCanary(CanaryCheck{
		Project: "vaulter", KeyVersion: 1,
		EscrowIdentity: escrow, EscrowRecipient: rec,
		PublishedDEK: dek, PublishedPlain: plain,
		StoredWrap: wrap, StoredBlob: blob,
	}))

	// FORGED: stored wrap başka bir DEK'e sarılmış → re-derive byte-compare fail.
	otherDEK, _ := cryptoid.NewDEK()
	forgedWrap, _ := cryptoid.SealDEK(otherDEK, rec, slot)
	err = VerifyCanary(CanaryCheck{
		Project: "vaulter", KeyVersion: 1,
		EscrowIdentity: escrow, EscrowRecipient: rec,
		PublishedDEK: dek, PublishedPlain: plain,
		StoredWrap: forgedWrap, StoredBlob: blob,
	})
	require.Error(t, err)
}

// --- RunOnce (VM cron çekirdeği) --------------------------------------------

func TestRunOnce_PublishesOnSuccess_AlertsOnFailure(t *testing.T) {
	f := newFixture(t)
	w := NewMemStore()
	var alerts []string
	al := alertFunc(func(rule, summary string) { alerts = append(alerts, rule) })

	// Başarı → publish, alert YOK.
	res, err := RunOnce(context.Background(), f.store, w, cfgOf(f), "ci.meapps.dev", al, fixTime.Add(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Contains(t, w.Objects, "witness/"+fixProject+".json")
	require.Empty(t, alerts)

	// Başarısızlık (audit chain bozuk) → A5 alert + hata.
	bad := f.store.clone()
	var seg auditSegment
	_ = json.Unmarshal(bad.Objects[keyAuditSegment(2)], &seg)
	seg.Hash = "00000000" + seg.Hash[8:]
	b, _ := json.Marshal(seg)
	bad.Objects[keyAuditSegment(2)] = b
	_, err = RunOnce(context.Background(), bad, NewMemStore(), cfgOf(f), "ci.meapps.dev", al, fixTime.Add(time.Hour))
	require.Error(t, err)
	require.Contains(t, alerts, "A5")
}

// alertFunc, Alerter arayüzünü bir closure'a bağlar (test).
type alertFunc func(rule, summary string)

func (a alertFunc) Alert(_ context.Context, rule, summary string, _ map[string]any) { a(rule, summary) }

// derinlik: manifest paketinin test-dışı yüzeyine dokunmadığımızdan emin ol.
var _ = manifest.SchemaDataManifest
