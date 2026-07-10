package intent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

func mkReceipt(t *testing.T, k *cryptoid.ECDSAP256SigningKey, manifestSha string, epoch uint64, iat int64) Receipt {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"schema": ReceiptSchema, "manifestSha256": manifestSha, "epoch": epoch, "iat": iat,
	})
	require.NoError(t, err)
	sig, err := k.Sign(payload)
	require.NoError(t, err)
	return Receipt{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Kid:     "att-1",
		Sig:     base64.StdEncoding.EncodeToString(sig.Sig),
	}
}

func jwkOf(t *testing.T, k *cryptoid.ECDSAP256SigningKey) json.RawMessage {
	t.Helper()
	pub := k.PublicKeyBytes()
	x := base64.RawURLEncoding.EncodeToString(pub[1:33])
	y := base64.RawURLEncoding.EncodeToString(pub[33:65])
	return json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, x, y))
}

func TestVerifyReceipt_OK(t *testing.T) {
	k, err := cryptoid.GenerateECDSAP256()
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)
	rec := mkReceipt(t, k, "manifest-hash", 5, now.Unix())

	p, err := VerifyReceipt(rec, jwkOf(t, k), "manifest-hash", 5, now)
	require.NoError(t, err)
	require.EqualValues(t, 5, p.Epoch)
}

func TestVerifyReceipt_StaleIAT(t *testing.T) {
	k, _ := cryptoid.GenerateECDSAP256()
	now := time.Unix(1_800_000_000, 0)
	rec := mkReceipt(t, k, "m", 1, now.Add(-20*time.Minute).Unix())
	_, err := VerifyReceipt(rec, jwkOf(t, k), "m", 1, now)
	require.True(t, clierr.Is(err, clierr.StaleReceipt), "stale iat: %v", err)
}

func TestVerifyReceipt_WrongManifest(t *testing.T) {
	k, _ := cryptoid.GenerateECDSAP256()
	now := time.Unix(1_800_000_000, 0)
	rec := mkReceipt(t, k, "other-manifest", 1, now.Unix())
	_, err := VerifyReceipt(rec, jwkOf(t, k), "expected-manifest", 1, now)
	require.True(t, clierr.Is(err, clierr.StaleReceipt), "manifest bind mismatch: %v", err)
}

func TestVerifyReceipt_EpochBelowPin(t *testing.T) {
	k, _ := cryptoid.GenerateECDSAP256()
	now := time.Unix(1_800_000_000, 0)
	rec := mkReceipt(t, k, "m", 3, now.Unix())
	_, err := VerifyReceipt(rec, jwkOf(t, k), "m", 9, now)
	require.True(t, clierr.Is(err, clierr.EpochDowngrade), "epoch below pin: %v", err)
}

func TestVerifyReceipt_BadSignature(t *testing.T) {
	k, _ := cryptoid.GenerateECDSAP256()
	other, _ := cryptoid.GenerateECDSAP256()
	now := time.Unix(1_800_000_000, 0)
	rec := mkReceipt(t, k, "m", 1, now.Unix())
	// Başka bir anahtarın JWK'ı ile doğrula → imza geçmez.
	_, err := VerifyReceipt(rec, jwkOf(t, other), "m", 1, now)
	require.True(t, clierr.Is(err, clierr.SigInvalid), "wrong pubkey must reject: %v", err)
}

func TestEvaluateOfflineRead(t *testing.T) {
	fetched := time.Now().Add(-3 * time.Hour)

	// dev ≤ 24h → uyarı, hata yok; değer İÇERMEZ.
	warn, err := EvaluateOfflineRead(Dev, 3*time.Hour, 7, fetched)
	require.NoError(t, err)
	require.Contains(t, warn, "7 keys")
	require.Contains(t, warn, "3h old")

	// dev > 24h → CACHE_STALE.
	_, err = EvaluateOfflineRead(Dev, 30*time.Hour, 7, fetched)
	require.True(t, clierr.Is(err, clierr.CacheStale))

	// deploy çevrimdışı → STALE_RECEIPT (fresh-or-fail).
	_, err = EvaluateOfflineRead(Deploy, 1*time.Minute, 7, fetched)
	require.True(t, clierr.Is(err, clierr.StaleReceipt))
}

func TestBlockOfflineWrite(t *testing.T) {
	require.True(t, clierr.Is(BlockOfflineWrite(), clierr.OfflineWriteBlocked))
}

func TestCheckWitness_Stub(t *testing.T) {
	// nil tanık → NO-OP (G10 stub).
	require.NoError(t, CheckWitness(nil, 5))
	// NoWitness → çelişki üretmez.
	require.NoError(t, CheckWitness(NoWitness{}, 5))
}

func TestParseIntent(t *testing.T) {
	got, err := Parse("")
	require.NoError(t, err)
	require.Equal(t, Dev, got)
	got, err = Parse("deploy")
	require.NoError(t, err)
	require.Equal(t, Deploy, got)
	_, err = Parse("bogus")
	require.Error(t, err)
}
