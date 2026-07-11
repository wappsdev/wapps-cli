package store

// v2 istemci testleri: httptest fake-worker'a karşı Read/Keys/Set/Import/Delete +
// epoch-pin tripwire (§7.4) + hata eşlemesi (§7.5) + auth enjeksiyonu (§7.2).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/intent"
)

// newTestStore, verilen handler'la bir fake gate + istemci kurar.
func newTestStore(t *testing.T, handler http.Handler) (*WorkerStore, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	st := New(Config{
		BaseURL:      srv.URL,
		EpochPinPath: filepath.Join(t.TempDir(), "epochs.json"),
		Auth: func(req *http.Request) error {
			req.Header.Set("cf-access-token", "test-session")
			return nil
		},
	})
	return st, srv
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// TestRead_PlaintextBulk, POST /read'in plaintext değerler döndürdüğünü, auth
// header'ının taşındığını ve epoch pin'inin İLERLEDİĞİNİ doğrular.
func TestRead_PlaintextBulk(t *testing.T) {
	var gotAuth string
	var gotBody struct {
		Keys []string `json:"keys"`
	}
	st, _ := newTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/vaulter/read" {
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("cf-access-token")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSON(w, 200, map[string]any{"epoch": 7, "values": map[string]string{"DB_URL": "postgres://x"}})
	}))

	res, err := st.Read(context.Background(), "vaulter", []string{"DB_URL"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Epoch != 7 || res.Values["DB_URL"] != "postgres://x" {
		t.Fatalf("read result: %+v", res)
	}
	if gotAuth != "test-session" {
		t.Errorf("auth header not injected")
	}
	if len(gotBody.Keys) != 1 || gotBody.Keys[0] != "DB_URL" {
		t.Errorf("request keys: %v", gotBody.Keys)
	}
	// Pin ilerledi mi?
	pin, err := st.pinnedEpoch("vaulter")
	if err != nil || pin != 7 {
		t.Fatalf("epoch pin should advance to 7, got %d (%v)", pin, err)
	}
}

// TestRead_EmptyKeysResolvesViaKeys, keys boşken önce GET /keys ile okunabilir
// küme çözülür (Worker boş keys gövdesini reddeder).
func TestRead_EmptyKeysResolvesViaKeys(t *testing.T) {
	st, _ := newTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects/vaulter/keys":
			writeJSON(w, 200, map[string]any{"project": "vaulter", "epoch": 3,
				"keys": []map[string]any{{"keyName": "A", "keyVersion": 1}, {"keyName": "B", "keyVersion": 2}}})
		case "/v1/projects/vaulter/read":
			var body struct {
				Keys []string `json:"keys"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Keys) != 2 {
				t.Errorf("expected both readable keys, got %v", body.Keys)
			}
			writeJSON(w, 200, map[string]any{"epoch": 3, "values": map[string]string{"A": "1", "B": "2"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	res, err := st.Read(context.Background(), "vaulter", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Values) != 2 {
		t.Fatalf("values: %v", res.Values)
	}
}

// TestRead_EpochDowngradeTripwire, served epoch < pinned → EPOCH_DOWNGRADE (§7.4).
func TestRead_EpochDowngradeTripwire(t *testing.T) {
	epoch := uint64(9)
	st, _ := newTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"epoch": epoch, "values": map[string]string{"A": "1"}})
	}))
	if _, err := st.Read(context.Background(), "vaulter", []string{"A"}); err != nil {
		t.Fatal(err)
	}
	epoch = 4 // rollback!
	_, err := st.Read(context.Background(), "vaulter", []string{"A"})
	if !clierr.Is(err, clierr.EpochDowngrade) {
		t.Fatalf("want EPOCH_DOWNGRADE, got %v", err)
	}
}

// TestWriteHeaders_RotationAndSync, §6.4 bilgilendirici etiketleri: rotation
// header'ı + sync intent'i Worker'a taşınır.
func TestWriteHeaders_RotationAndSync(t *testing.T) {
	var rotHeader, intentHeader string
	st, _ := newTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rotHeader = r.Header.Get(intent.HeaderRotation)
		intentHeader = r.Header.Get(intent.HeaderIntent)
		writeJSON(w, 200, map[string]any{"ok": true, "epoch": 1})
	}))

	if err := st.Set(context.Background(), "vaulter", "KEY_A", "v", WriteOpts{RotationID: "db-role/phase1"}); err != nil {
		t.Fatal(err)
	}
	if rotHeader != "db-role/phase1" {
		t.Errorf("rotation header: %q", rotHeader)
	}

	if err := st.Import(context.Background(), "vaulter", map[string]string{"K": "v"}, WriteOpts{Sync: true}); err != nil {
		t.Fatal(err)
	}
	if intentHeader != intent.IntentSync {
		t.Errorf("sync intent header: %q", intentHeader)
	}
}

// TestErrorMapping, Worker hata gövdelerinin clierr sözleşmesine eşlenmesi (§7.5).
func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		body   map[string]any
		want   clierr.Code
	}{
		{401, map[string]any{"error": "AUTH_INVALID"}, clierr.SessionExpired},
		{403, map[string]any{"error": "GRANT_DENIED", "key": "DB_URL", "dimension": "key_denied"}, clierr.GrantDenied},
		{404, map[string]any{"error": "NOT_FOUND", "key": "MISSING"}, clierr.NotFound},
		{412, map[string]any{"error": "EPOCH_CONFLICT"}, clierr.CASConflict},
		{412, map[string]any{"error": "POLICY_CONFLICT", "current_version": 4}, clierr.PolicyConflict},
		{422, map[string]any{"error": "POLICY_INVALID", "rule_index": 2}, clierr.PolicyInvalid},
		{429, map[string]any{"error": "RATE_LIMITED", "retry_after": 30}, clierr.RateLimited},
		{503, map[string]any{"error": "AUDIT_UNAVAILABLE"}, clierr.AuditUnavailable},
		{503, map[string]any{"error": "IDENTITY_UNAVAILABLE"}, clierr.IdentityUnavailable},
		{503, map[string]any{"error": "SERVICE_MISCONFIGURED"}, clierr.ServiceMisconfig},
	}
	for _, tc := range cases {
		st, _ := newTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, tc.status, tc.body)
		}))
		_, err := st.Read(context.Background(), "vaulter", []string{"A"})
		if !clierr.Is(err, tc.want) {
			t.Errorf("status %d %v: want %s, got %v", tc.status, tc.body["error"], tc.want, err)
		}
	}
}

// TestTransportError_NetworkRequired, taşıma hatası → NETWORK_REQUIRED (çevrimdışı
// mod YOK, §1.5).
func TestTransportError_NetworkRequired(t *testing.T) {
	st := New(Config{
		BaseURL:      "http://127.0.0.1:1", // kapalı port
		EpochPinPath: filepath.Join(t.TempDir(), "epochs.json"),
	})
	_, err := st.Read(context.Background(), "vaulter", []string{"A"})
	if !clierr.Is(err, clierr.NetworkRequired) {
		t.Fatalf("want NETWORK_REQUIRED, got %v", err)
	}
}

// TestAuthError_PreemptsNetwork, Auth hatası isteği ağ'a ÇIKMADAN keser.
func TestAuthError_PreemptsNetwork(t *testing.T) {
	st := New(Config{
		BaseURL:      "http://127.0.0.1:1",
		EpochPinPath: filepath.Join(t.TempDir(), "epochs.json"),
		Auth: func(*http.Request) error {
			return clierr.New(clierr.SessionExpired, "no session")
		},
	})
	_, err := st.Read(context.Background(), "vaulter", []string{"A"})
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("want SESSION_EXPIRED before any dial, got %v", err)
	}
}

// TestPolicyAndRotatePlanAndWhoami, kontrol-düzlemi istemci çağrılarının rota +
// gövde şekillerini doğrular.
func TestPolicyAndRotatePlanAndWhoami(t *testing.T) {
	st, _ := newTestStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/whoami":
			writeJSON(w, 200, map[string]any{"principal": "human:a@wapps.co", "kind": "human",
				"groups": []string{"developers@wapps.co"}, "policy_version": 3})
		case r.URL.Path == "/v1/policy" && r.Method == http.MethodGet:
			writeJSON(w, 200, map[string]any{"version": 3, "sha256": "abc",
				"policy": map[string]any{"schema": "wapps-secrets/policy/v1", "version": 3, "rules": []any{}}})
		case r.URL.Path == "/v1/policy" && r.Method == http.MethodPut:
			var doc PolicyDoc
			_ = json.NewDecoder(r.Body).Decode(&doc)
			if doc.Version != 4 {
				t.Errorf("PUT version = %d, want 4 (CAS current+1)", doc.Version)
			}
			writeJSON(w, 200, map[string]any{"version": 4, "sha256": "def"})
		case r.URL.Path == "/v1/admin/rotate-plan":
			if r.URL.Query().Get("identity") != "human:x@wapps.co" || r.URL.Query().Get("assume_policy") != "1" {
				t.Errorf("rotate-plan query: %s", r.URL.RawQuery)
			}
			writeJSON(w, 200, map[string]any{"identity": "human:x@wapps.co", "generated_at": "t",
				"items": []map[string]any{{"project": "vaulter", "key": "DB_URL", "last_read": "t", "reads": 5}}})
		default:
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))

	who, err := st.Whoami(context.Background())
	if err != nil || who.Principal != "human:a@wapps.co" {
		t.Fatalf("whoami: %+v %v", who, err)
	}
	pol, err := st.PolicyGet(context.Background())
	if err != nil || pol.Version != 3 {
		t.Fatalf("policy get: %+v %v", pol, err)
	}
	v, sha, err := st.PolicyPut(context.Background(), PolicyDoc{Schema: "wapps-secrets/policy/v1", Version: 4})
	if err != nil || v != 4 || sha != "def" {
		t.Fatalf("policy put: %d %s %v", v, sha, err)
	}
	plan, err := st.RotatePlan(context.Background(), "human:x@wapps.co", "", true)
	if err != nil || len(plan.Items) != 1 || plan.Items[0].Key != "DB_URL" {
		t.Fatalf("rotate-plan: %+v %v", plan, err)
	}
}
