package deploy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/cmd/secrets"
	deploypkg "github.com/wappsdev/wapps-cli/internal/deploy"
)

func clearDeployEnv(t *testing.T) {
	t.Helper()
	for _, e := range []string{
		"DEPLOY_PROXY_TOKEN_VAULTER", "DEPLOY_PROXY_TOKEN", "PROXY_TOKEN",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_ID",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "CF_ACCESS_CLIENT_SECRET",
		"DEPLOY_PROXY_EP", "WAPPS_SECRETS_GATE", "WAPPS_SESSION_TOKEN",
	} {
		os.Unsetenv(e)
	}
	secrets.SetConfigPath("")
	t.Cleanup(func() { secrets.SetConfigPath("") })
}

func opts(service string) deployOptions {
	return deployOptions{service: service, repo: "vaulter"}
}

// U4: unknown repo → exit 1, no network.
func TestRunDeploy_UnknownRepo_Exit1(t *testing.T) {
	clearDeployEnv(t)
	o := opts("auth")
	o.repo = "nope"
	o.ep = "http://127.0.0.1:1" // would fail if a network call happened
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitUsage {
		t.Fatalf("want exit 1, got %d", code)
	}
	if !strings.Contains(errW.String(), "unknown repo") {
		t.Errorf("message: %q", errW.String())
	}
}

// U5: bad service name → exit 1, no network.
func TestRunDeploy_BadServiceName_Exit1(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "t")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "i")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "s")
	o := opts("BAD_Name")
	o.ep = "http://127.0.0.1:1"
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitUsage {
		t.Fatalf("want exit 1, got %d", code)
	}
}

// U3: creds unresolved → exit 2, names the missing key, no value.
func TestRunDeploy_MissingCreds_Exit2(t *testing.T) {
	clearDeployEnv(t)
	var out, errW bytes.Buffer
	if code := runDeploy(opts("auth"), &out, &errW); code != deploypkg.ExitCreds {
		t.Fatalf("want exit 2, got %d", code)
	}
	if !strings.Contains(errW.String(), "DEPLOY_PROXY_TOKEN_VAULTER") {
		t.Errorf("should name the missing token key: %q", errW.String())
	}
}

// setupStoreGate, sahte bir secrets-gate + backend:store .wapps.yaml kurar
// (P1.7: deploy'ın credential fallback'i artık store'dur). Gate'in aldığı
// bulk-read gövdelerini döner; oturum out-of-band env token'ıyla sağlanır.
func setupStoreGate(t *testing.T, keys []string, values map[string]string) *[]string {
	t.Helper()
	keysJSON := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		keysJSON = append(keysJSON, map[string]any{"keyName": k, "keyVersion": 1})
	}
	readBodies := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/vaulter/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"project": "vaulter", "epoch": 1, "keys": keysJSON})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/vaulter/read":
			b, _ := io.ReadAll(r.Body)
			*readBodies = append(*readBodies, string(b))
			_ = json.NewEncoder(w).Encode(map[string]any{"epoch": 1, "values": values})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"NOT_FOUND"}`))
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv("WAPPS_SECRETS_GATE", srv.URL)
	t.Setenv("WAPPS_SESSION_TOKEN", "fake-session-token")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // epoch-pin + oturum dosyaları izole

	projDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projDir, ".wapps.yaml"),
		[]byte("version: 2\nbackend: store\nproject: vaulter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir()) // cwd ≠ proje: --project/-c çözümlemesi kanıtlanır
	secrets.SetConfigPath(filepath.Join(projDir, ".wapps.yaml"))
	return readBodies
}

// U1 (P1.7): cred precedence — env wins over the store; keys the env does not
// supply resolve from the store. The bulk read must only request keys the
// name-plane says exist (all-or-nothing NOT_FOUND trap).
func TestResolveCreds_EnvBeatsStore(t *testing.T) {
	clearDeployEnv(t)
	present := []string{
		"DEPLOY_PROXY_TOKEN_VAULTER",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_ID",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET",
	}
	readBodies := setupStoreGate(t, present, map[string]string{
		"DEPLOY_PROXY_TOKEN_VAULTER":           "tok-STORE",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_ID":     "id-store",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET": "cf-sec",
	})
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "tok-ENV")

	creds, missing, storeErr := resolveCreds("vaulter", "")
	if missing != "" || storeErr != nil {
		t.Fatalf("unexpected missing=%s storeErr=%v", missing, storeErr)
	}
	if creds.Token != "tok-ENV" {
		t.Errorf("env should beat store for token, got %q", creds.Token)
	}
	// CF creds only in the store → resolved from the store.
	if creds.CFAccessID != "id-store" || creds.CFAccessSecret != "cf-sec" {
		t.Errorf("CF creds should come from the store: %+v", creds)
	}
	// Bulk read yalnızca store'da VAR olan adayları istemeli.
	if len(*readBodies) != 1 {
		t.Fatalf("expected exactly 1 bulk read, got %d", len(*readBodies))
	}
	var req struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal([]byte((*readBodies)[0]), &req); err != nil {
		t.Fatalf("read body not JSON: %v", err)
	}
	sort.Strings(req.Keys)
	wantKeys := append([]string{}, present...)
	sort.Strings(wantKeys)
	if len(req.Keys) != len(wantKeys) {
		t.Fatalf("read keys: got %v, want %v", req.Keys, wantKeys)
	}
	for i := range wantKeys {
		if req.Keys[i] != wantKeys[i] {
			t.Fatalf("read keys: got %v, want %v", req.Keys, wantKeys)
		}
	}
}

// P1.7: store yapılandırılmış ama aranan anahtarlar yok → NOT_FOUND hatası değil,
// normal exit-2 "missing" raporu; boş kesişimde value.read HİÇ yapılmaz.
func TestResolveCreds_StoreWithoutKeys_ReportsMissing(t *testing.T) {
	clearDeployEnv(t)
	readBodies := setupStoreGate(t, nil, nil)

	creds, missing, storeErr := resolveCreds("vaulter", "")
	if storeErr != nil {
		t.Fatalf("empty store must not be an error, got %v", storeErr)
	}
	if missing != "DEPLOY_PROXY_TOKEN_VAULTER" {
		t.Errorf("missing: got %q", missing)
	}
	if creds.Token != "" {
		t.Errorf("token must stay empty, got %q", creds.Token)
	}
	if len(*readBodies) != 0 {
		t.Errorf("no value.read must happen on empty intersection, got %d", len(*readBodies))
	}
}

// Legacy env fallbacks (current ci.yml names) still resolve.
func TestResolveCreds_LegacyEnvFallback(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("PROXY_TOKEN", "tok")
	t.Setenv("CF_ACCESS_CLIENT_ID", "id")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "sec")
	creds, missing, _ := resolveCreds("vaulter", "")
	if missing != "" || creds.Token != "tok" || creds.CFAccessID != "id" {
		t.Errorf("legacy fallback failed: %+v missing=%s", creds, missing)
	}
}

// I1 / U6: valid deploy, no wait → exit 0, prints triggered, exactly one POST.
func TestRunDeploy_TriggerNoWait_Exit0(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "tok")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "id")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "sec")

	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		_, _ = w.Write([]byte(`{"deployment_uuid":"mq12riea3yg6169dg0gs5xxo"}`))
	}))
	defer srv.Close()

	o := opts("auth")
	o.ep = srv.URL
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitOK {
		t.Fatalf("want exit 0, got %d (err=%q)", code, errW.String())
	}
	if posts != 1 {
		t.Errorf("expected exactly 1 POST, got %d", posts)
	}
	if !strings.Contains(out.String(), "triggered") {
		t.Errorf("output: %q", out.String())
	}
}

// I11 / U10: --json contract + AI-safe (no secret substrings anywhere).
func TestRunDeploy_JSONAndAISafe(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "supersecret-token")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "secret-cf-id")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "secret-cf-secret")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"deployment_uuid":"mq12riea3yg6169dg0gs5xxo"}`))
	}))
	defer srv.Close()

	o := opts("migrator")
	o.ep = srv.URL
	o.asJSON = true
	var out, errW bytes.Buffer
	code := runDeploy(o, &out, &errW)
	if code != deploypkg.ExitOK {
		t.Fatalf("want exit 0, got %d", code)
	}
	// Single JSON line, parses, right fields.
	var jr jsonResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &jr); err != nil {
		t.Fatalf("--json output not valid JSON: %v\n%s", err, out.String())
	}
	if jr.Service != "migrator" || jr.Outcome != "triggered" || jr.ExitCode != 0 || jr.DeploymentUUID == "" {
		t.Errorf("json fields wrong: %+v", jr)
	}
	// AI-safe: no secret substring in stdout OR stderr.
	combined := out.String() + errW.String()
	for _, secret := range []string{"supersecret-token", "secret-cf-id", "secret-cf-secret"} {
		if strings.Contains(combined, secret) {
			t.Errorf("credential %q leaked into output", secret)
		}
	}
}

// I2: out-of-scope name → exit 3, no status poll.
func TestRunDeploy_OutOfScope_Exit3(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "t")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "i")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "s")
	var statusPolls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/deployments/") {
			statusPolls++
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"service not allowlisted for this token"}`))
	}))
	defer srv.Close()
	o := opts("royco-api")
	o.ep = srv.URL
	o.wait = true
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitAuthScope {
		t.Fatalf("want exit 3, got %d", code)
	}
	if statusPolls != 0 {
		t.Errorf("must not poll status after a trigger 403, got %d polls", statusPolls)
	}
}

// I10: the gaps-doc scenario — migrator --wait finishes → exit 0.
func TestRunDeploy_MigratorWaitFinished_Exit0(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "t")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "i")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "s")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/deploy/") {
			_, _ = w.Write([]byte(`{"deployment_uuid":"mq12riea3yg6169dg0gs5xxo"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"finished"}`))
	}))
	defer srv.Close()
	o := opts("migrator")
	o.ep = srv.URL
	o.wait = true
	o.interval = 0
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitOK {
		t.Fatalf("want exit 0, got %d (%q)", code, errW.String())
	}
	if !strings.Contains(out.String(), "finished") {
		t.Errorf("output: %q", out.String())
	}
}

// --wait + --json: stdout must stay a single parseable JSON object (the poll
// status lines go to io.Discard, not stdout).
func TestRunDeploy_WaitJSON_StdoutSingleObject(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "t")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "i")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "s")
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/deploy/") {
			_, _ = w.Write([]byte(`{"deployment_uuid":"mq12riea3yg6169dg0gs5xxo"}`))
			return
		}
		n++
		st := "in_progress"
		if n >= 2 {
			st = "finished"
		}
		_, _ = w.Write([]byte(`{"status":"` + st + `"}`))
	}))
	defer srv.Close()
	o := opts("auth")
	o.ep = srv.URL
	o.wait = true
	o.interval = 0
	o.asJSON = true
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitOK {
		t.Fatalf("want exit 0, got %d", code)
	}
	// Whole stdout must parse as ONE JSON object — no leading poll lines.
	var jr jsonResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &jr); err != nil {
		t.Fatalf("stdout not a single JSON object: %v\n%q", err, out.String())
	}
	if jr.Outcome != "success" || jr.Status != "finished" {
		t.Errorf("json fields wrong: %+v", jr)
	}
}

// --wait failure: the terminal status line appears exactly once (Wait no longer
// prints it to stdout AND finish to stderr).
func TestRunDeploy_WaitFailed_SingleLine_Exit8(t *testing.T) {
	clearDeployEnv(t)
	t.Setenv("DEPLOY_PROXY_TOKEN_VAULTER", "t")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "i")
	t.Setenv("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "s")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/deploy/") {
			_, _ = w.Write([]byte(`{"deployment_uuid":"mq12riea3yg6169dg0gs5xxo"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"failed"}`))
	}))
	defer srv.Close()
	o := opts("migrator")
	o.ep = srv.URL
	o.wait = true
	o.interval = 0
	var out, errW bytes.Buffer
	if code := runDeploy(o, &out, &errW); code != deploypkg.ExitFailed {
		t.Fatalf("want exit 8, got %d", code)
	}
	if got := strings.Count(out.String()+errW.String(), "migrator: failed"); got != 1 {
		t.Errorf("terminal status line should appear exactly once, got %d:\nstdout=%q\nstderr=%q", got, out.String(), errW.String())
	}
}
