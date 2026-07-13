package secrets

// policy show/set/lint + rotate-plan verb testleri (SPEC §7.3/§6.3): httptest
// fake gate (openAdminStore seam'i) + ajan-modu control-plane reddi (gateKey).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// installFakeGate, openAdminStore seam'ini httptest gate'ine yönlendirir.
func installFakeGate(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	prev := openAdminStore
	openAdminStore = func() (*store.WorkerStore, error) {
		return store.New(store.Config{
			BaseURL:      srv.URL,
			EpochPinPath: filepath.Join(t.TempDir(), "epochs.json"),
			Auth:         func(*http.Request) error { return nil },
		}), nil
	}
	t.Cleanup(func() { openAdminStore = prev })
	return srv
}

func gateJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func policyGateDoc() map[string]any {
	return map[string]any{
		"version": 3, "sha256": "abc123",
		"policy": map[string]any{
			"schema": "wapps-secrets/policy/v1", "version": 3,
			"rules": []map[string]any{
				{"group": "developers@wapps.co", "projects": []string{"*"}, "keys": []string{"*", "!*_PROD_*"}, "verbs": []string{"read"}},
			},
		},
	}
}

// TestPolicyShow, GET /v1/policy'nin çözülüp basıldığını doğrular.
func TestPolicyShow(t *testing.T) {
	installFakeGate(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy" || r.Method != http.MethodGet {
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		gateJSON(w, 200, policyGateDoc())
	}))
	out := new(bytes.Buffer)
	policyShowCmd.SetOut(out)
	if err := policyShowCmd.RunE(policyShowCmd, nil); err != nil {
		t.Fatalf("policy show: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "version: 3") || !strings.Contains(got, "developers@wapps.co") {
		t.Errorf("show output: %q", got)
	}
}

// TestPolicySet_CASVersionAndConfirm, set akışı: dosya lint edilir, current
// version çekilir, PUT current+1 ile gider; onaysız iptal edilir.
func TestPolicySet_CASVersionAndConfirm(t *testing.T) {
	var putDoc *store.PolicyDoc
	installFakeGate(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			gateJSON(w, 200, policyGateDoc())
		case http.MethodPut:
			var doc store.PolicyDoc
			_ = json.NewDecoder(r.Body).Decode(&doc)
			putDoc = &doc
			gateJSON(w, 200, map[string]any{"version": doc.Version, "sha256": "def456"})
		}
	}))

	file := filepath.Join(t.TempDir(), "policy.json")
	doc := `{"schema":"wapps-secrets/policy/v1","version":1,"rules":[
		{"group":"developers@wapps.co","projects":["*"],"keys":["*","!*_PROD_*"],"verbs":["read","write"]}]}`
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	// Onaysız (stdin "no") → iptal, PUT gitmez.
	cmd := policySetCmd
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetIn(strings.NewReader("no\n"))
	policySetYes = false
	err := runPolicySet(cmd, file)
	if !clierr.Is(err, clierr.NotAvailable) {
		t.Fatalf("unconfirmed set must abort, got %v", err)
	}
	if putDoc != nil {
		t.Fatal("PUT must not fire without confirm")
	}

	// Onaylı ("yes") → PUT version = current+1 = 4.
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("yes\n"))
	if err := runPolicySet(cmd, file); err != nil {
		t.Fatalf("policy set: %v", err)
	}
	if putDoc == nil || putDoc.Version != 4 {
		t.Fatalf("PUT version: %+v", putDoc)
	}
	if !strings.Contains(out.String(), "rule diff:") {
		t.Errorf("set must print the rule diff; got %q", out.String())
	}
}

// TestPolicyLint_FileValidation, lint verb'i: geçersiz şema hata; uyarılar basılır.
func TestPolicyLint_FileValidation(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"schema":"nope","version":1,"rules":[]}`), 0o600)
	if err := policyLintCmd.RunE(policyLintCmd, []string{bad}); !clierr.Is(err, clierr.PolicyInvalid) {
		t.Fatalf("bad schema must fail lint with POLICY_INVALID, got %v", err)
	}

	warny := filepath.Join(dir, "warny.json")
	doc := `{"schema":"wapps-secrets/policy/v1","version":1,"rules":[
		{"service":"svc-x","projects":["*"],"keys":["*"],"verbs":["*"]}]}`
	_ = os.WriteFile(warny, []byte(doc), 0o600)
	out := new(bytes.Buffer)
	policyLintCmd.SetOut(out)
	if err := policyLintCmd.RunE(policyLintCmd, []string{warny}); err != nil {
		t.Fatalf("lint with warnings must still succeed: %v", err)
	}
	if !strings.Contains(out.String(), "lint(d)") {
		t.Errorf("expected lint(d) warning for service [\"*\"]; got %q", out.String())
	}
}

// TestRotatePlan_TableAndFlags, rotate-plan çıktısı + --identity zorunluluğu.
func TestRotatePlan_TableAndFlags(t *testing.T) {
	installFakeGate(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/admin/rotate-plan" {
			t.Errorf("unexpected route %s", r.URL.Path)
		}
		if r.URL.Query().Get("identity") != "human:leaver@wapps.co" {
			t.Errorf("identity query: %s", r.URL.RawQuery)
		}
		gateJSON(w, 200, map[string]any{
			"identity": "human:leaver@wapps.co", "generated_at": "2026-07-11T00:00:00Z",
			"items": []map[string]any{
				{"project": "vaulter", "key": "DATABASE_URL", "last_read": "2026-07-10T00:00:00Z", "reads": 12},
			},
		})
	}))

	rotatePlanIdentity = ""
	if err := rotatePlanCmd.RunE(rotatePlanCmd, nil); err == nil {
		t.Fatal("rotate-plan without --identity must error")
	}

	rotatePlanIdentity = "human:leaver@wapps.co"
	rotatePlanSince, rotatePlanAssumePolicy, rotatePlanJSON = "", false, false
	t.Cleanup(func() { rotatePlanIdentity = "" })
	out := new(bytes.Buffer)
	rotatePlanCmd.SetOut(out)
	if err := rotatePlanCmd.RunE(rotatePlanCmd, nil); err != nil {
		t.Fatalf("rotate-plan: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "DATABASE_URL") || !strings.Contains(got, "vaulter") {
		t.Errorf("rotate-plan table output: %q", got)
	}
}

// TestAgentGate_PolicyFamilyIsControlPlane, gateKey'in policy alt-komutlarını
// AİLE adıyla ("policy" → control) gate'lediğini kanıtlar: "policy set" yaprağı,
// data-plane "set"in PolicyAllow iznini MİRAS ALAMAZ.
func TestAgentGate_PolicyFamilyIsControlPlane(t *testing.T) {
	t.Setenv("CLAUDECODE", "1") // ajan modu
	if !agentmode.IsAgent() {
		t.Skip("agent-mode detection unavailable in this environment")
	}
	if key := gateKey(policySetCmd); key != "policy" {
		t.Fatalf("gateKey(policy set) = %q, want policy", key)
	}
	err := secretsPreRunE(policySetCmd, nil)
	if !clierr.Is(err, clierr.ControlPlaneRequired) {
		t.Fatalf("policy set under agent mode: want CONTROL_PLANE_REQUIRED, got %v", err)
	}
	err = secretsPreRunE(rotatePlanCmd, nil)
	if !clierr.Is(err, clierr.ControlPlaneRequired) {
		t.Fatalf("rotate-plan under agent mode: want CONTROL_PLANE_REQUIRED, got %v", err)
	}
}

// TestLoginSessionFeedsAdminStore, üretim kurulumunda admin store'un session.Auth
// ile kurulduğunu (SESSION_EXPIRED yüzeyi) doğrular — fake seam devre dışı.
func TestLoginSessionFeedsAdminStore(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("CF_ACCESS_CLIENT_ID", "")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "")
	t.Setenv("WAPPS_SECRETS_GATE", "http://127.0.0.1:1")
	_ = session.GateHost() // env okunuyor

	st, serr := openAdminStore()
	if serr != nil {
		t.Fatalf("openAdminStore: %v", serr)
	}
	_, err := st.PolicyGet(t.Context())
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("no session: want SESSION_EXPIRED before any dial, got %v", err)
	}
}
