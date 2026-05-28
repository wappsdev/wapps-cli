package coolify

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HTTPError is unwrappable via errors.As. This is the contract SetBuildArgs
// relies on for typed status-code checks; if it breaks, the 409 fallback
// in SetBuildArgs silently regresses (POST errors are returned to caller
// instead of falling through to PATCH).
func TestHTTPError_UnwrapsViaErrorsAs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"conflict"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	_, err := c.doBytes("POST", "/anything", map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error from 409 response")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPError via errors.As, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusConflict {
		t.Errorf("expected StatusCode=409, got %d", httpErr.StatusCode)
	}
	if httpErr.Method != "POST" {
		t.Errorf("expected Method=POST, got %s", httpErr.Method)
	}
}

func TestCreateDockerComposeApp_POST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/applications/dockercompose" {
			t.Errorf("Expected /applications/dockercompose, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("User-Agent") != "curl/8" {
			t.Errorf("Expected User-Agent: curl/8, got %s", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			t.Errorf("Expected Bearer fake-token, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"uuid": "abc-uuid-123"})
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	uuid, err := c.CreateDockerComposeApp(CreateAppRequest{
		ProjectUUID: "proj-1",
		ServerUUID:  "srv-1",
		Name:        "test-app",
		ComposeYAML: "services:\n  app:\n    image: nginx",
	})
	if err != nil {
		t.Fatalf("CreateDockerComposeApp failed: %v", err)
	}
	if uuid != "abc-uuid-123" {
		t.Errorf("Want abc-uuid-123, got %q", uuid)
	}
}

func TestSetCustomLabels_Base64PATCH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("Expected PATCH, got %s", r.Method)
		}
		if r.URL.Path != "/applications/app-uuid-xyz" {
			t.Errorf("Expected /applications/app-uuid-xyz, got %s", r.URL.Path)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if labels, ok := body["custom_labels"].(string); !ok || labels == "" {
			t.Errorf("Expected non-empty custom_labels (base64), got %v", body["custom_labels"])
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	err := c.SetCustomLabels("app-uuid-xyz", []string{
		"traefik.enable=true",
		"traefik.http.routers.x.rule=Host(`example.com`)",
	})
	if err != nil {
		t.Fatalf("SetCustomLabels failed: %v", err)
	}
}

func TestListApplications_TopLevelArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/applications" {
			t.Errorf("Expected /applications, got %s", r.URL.Path)
		}
		// Coolify v4 returns a top-level JSON array, not {"data": [...]}.
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"uuid": "a-1", "name": "first"},
			{"uuid": "a-2", "name": "second"},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	apps, err := c.ListApplications()
	if err != nil {
		t.Fatalf("ListApplications failed: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("Expected 2 apps from top-level array, got %d", len(apps))
	}
	if apps[0]["uuid"] != "a-1" {
		t.Errorf("Expected uuid a-1, got %v", apps[0]["uuid"])
	}
}

func TestListApplications_DataEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Some Coolify endpoints / future versions may use {"data": [...]} envelope.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"uuid": "b-1", "name": "wrapped"},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	apps, err := c.ListApplications()
	if err != nil {
		t.Fatalf("ListApplications failed: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("Expected 1 app from envelope shape, got %d", len(apps))
	}
}

func TestCreatePrivateGitHubAppApp_POST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/applications/private-github-app" {
			t.Errorf("expected /applications/private-github-app, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["github_app_uuid"] != "gh-uuid" {
			t.Errorf("expected github_app_uuid=gh-uuid, got %v", body["github_app_uuid"])
		}
		if body["git_repository"] != "wappsdev/test-repo" {
			t.Errorf("git_repository mismatch: %v", body["git_repository"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"uuid": "app-new-uuid"})
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	uuid, err := c.CreatePrivateGitHubAppApp(CreateGitHubAppAppRequest{
		ProjectUUID:        "proj-1",
		ServerUUID:         "srv-1",
		GithubAppUUID:      "gh-uuid",
		Name:               "test-app",
		GitRepository:      "wappsdev/test-repo",
		GitBranch:          "main",
		BuildPack:          "dockerfile",
		DockerfileLocation: "/Dockerfile",
		Ports:              "8080",
		InstantDeploy:      true,
	})
	if err != nil {
		t.Fatalf("CreatePrivateGitHubAppApp: %v", err)
	}
	if uuid != "app-new-uuid" {
		t.Errorf("want app-new-uuid, got %q", uuid)
	}
}

// SetBuildArgs uses POST-then-PATCH idempotent upsert: POST /envs first
// (create), on 409 fall back to PATCH /envs (update). Happy path = only POST.
func TestSetBuildArgs_PostsEnvsPerKey(t *testing.T) {
	var calls []struct {
		method string
		body   map[string]interface{}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/envs") {
			t.Errorf("expected /envs endpoint, got %s", r.URL.Path)
		}
		if strings.HasSuffix(r.URL.Path, "/envs/bulk") {
			t.Errorf("should not hit /envs/bulk (it doesn't upsert)")
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		calls = append(calls, struct {
			method string
			body   map[string]interface{}
		}{r.Method, body})
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"uuid":"x"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	if err := c.SetBuildArgs("app-uuid-xyz", []string{
		"SERVICE_NAME=gateway",
		"VERSION=dev",
		"=bogus",        // should be skipped (empty key)
		"NO_EQUAL_SIGN", // should be skipped
	}); err != nil {
		t.Fatalf("SetBuildArgs: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 calls (malformed skipped), got %d", len(calls))
	}
	for i, call := range calls {
		if call.method != "POST" {
			t.Errorf("call %d: expected POST (happy path), got %s", i, call.method)
		}
	}
	if calls[0].body["key"] != "SERVICE_NAME" || calls[0].body["value"] != "gateway" {
		t.Errorf("first call body mismatch: %v", calls[0].body)
	}
	// Coolify v4 requires is_buildtime (NOT is_build_time) on POST/PATCH /envs.
	if calls[0].body["is_buildtime"] != true {
		t.Errorf("expected is_buildtime=true (Coolify v4 field name), got %v", calls[0].body["is_buildtime"])
	}
}

// When the env key already exists, Coolify returns 409 on POST. SetBuildArgs
// must fall back to PATCH /envs (update) to remain idempotent across re-runs.
func TestSetBuildArgs_FallsBackToPatchOn409(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		if r.Method == "POST" {
			// Simulate key already exists.
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"key already exists"}`))
			return
		}
		if r.Method == "PATCH" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"updated":true}`))
			return
		}
		t.Errorf("unexpected method %s", r.Method)
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	if err := c.SetBuildArgs("app-uuid-xyz", []string{"SERVICE_NAME=gateway"}); err != nil {
		t.Fatalf("SetBuildArgs (expected 409 fallback to succeed): %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected POST then PATCH (2 calls), got %d", len(calls))
	}
	if calls[0] != "POST" || calls[1] != "PATCH" {
		t.Errorf("expected POST→PATCH sequence, got %v", calls)
	}
}

// Non-409 errors on POST propagate without attempting PATCH fallback.
func TestSetBuildArgs_NonConflictPostErrorPropagates(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server exploded"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	err := c.SetBuildArgs("app-uuid-xyz", []string{"KEY=value"})
	if err == nil {
		t.Fatal("expected error from non-409 POST failure, got nil")
	}
	if !strings.Contains(err.Error(), "POST") {
		t.Errorf("expected error to mention POST stage, got: %v", err)
	}
	if len(calls) != 1 || calls[0] != "POST" {
		t.Errorf("expected exactly one POST call (no PATCH fallback on non-409), got %v", calls)
	}
}

// When POST returns 409 and the PATCH fallback also fails, the error from
// PATCH propagates (with "PATCH after 409" context) instead of being silently
// swallowed.
func TestSetBuildArgs_PatchAfter409FailurePropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"exists"}`))
			return
		}
		if r.Method == "PATCH" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad request"}`))
			return
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	err := c.SetBuildArgs("app-uuid-xyz", []string{"KEY=value"})
	if err == nil {
		t.Fatal("expected error from PATCH-after-409 failure, got nil")
	}
	if !strings.Contains(err.Error(), "PATCH after 409") {
		t.Errorf("expected error to mention 'PATCH after 409' context, got: %v", err)
	}
}

func TestSetBuildArgs_EmptySkipsAPICall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	if err := c.SetBuildArgs("app-uuid", []string{}); err != nil {
		t.Fatalf("SetBuildArgs: %v", err)
	}
	if called {
		t.Errorf("expected no API call for empty build args, but server was hit")
	}
}

func TestTriggerDeploy_GETsDeployEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.Contains(r.URL.RawQuery, "uuid=app-1") {
			t.Errorf("expected uuid=app-1 in query, got %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"deployments":[]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	if err := c.TriggerDeploy("app-1"); err != nil {
		t.Fatalf("TriggerDeploy: %v", err)
	}
}

func TestStartApp_POST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/applications/app-1/start" {
			t.Errorf("Expected /applications/app-1/start, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"started":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	if err := c.StartApp("app-1"); err != nil {
		t.Fatalf("StartApp failed: %v", err)
	}
}

// TestValidateUUID_RejectsPathTraversal closes the URL-injection vector where
// an appUUID like "../servers" or "../../admin" would normalize past the
// /applications/ prefix and hit a different Coolify endpoint. Operator
// .wapps.yaml is a trusted source today, but the validation is cheap defense
// in depth against a misconfigured config or future agent-driven UUID input.
func TestValidateUUID_RejectsPathTraversal(t *testing.T) {
	for _, bad := range []string{
		"../servers",
		"../../admin",
		"app/../etc",
		"app%2F..",
		"a/b",
		"app uuid",
		"",
	} {
		t.Run(bad, func(t *testing.T) {
			if err := validateUUID("test", bad); err == nil {
				t.Errorf("validateUUID accepted %q — path-traversal vector", bad)
			}
		})
	}
}

func TestValidateUUID_AcceptsCanonicalAndLaxShapes(t *testing.T) {
	for _, good := range []string{
		"12345678-1234-1234-1234-123456789abc", // canonical UUID
		"app-1",                                 // lax test fixture
		"abc123",                                // lax alnum
		"my-app-prod",                           // lax slug
	} {
		t.Run(good, func(t *testing.T) {
			if err := validateUUID("test", good); err != nil {
				t.Errorf("validateUUID rejected legitimate %q: %v", good, err)
			}
		})
	}
}

func TestListAppEnvs_RefusesBadUUID(t *testing.T) {
	c := New("http://unused", "tok")
	if _, err := c.ListAppEnvs("../servers"); err == nil {
		t.Fatal("ListAppEnvs accepted path-traversal appUUID")
	}
}

func TestDeleteAppEnv_RefusesBadEnvUUID(t *testing.T) {
	c := New("http://unused", "tok")
	if err := c.DeleteAppEnv("12345678-1234-1234-1234-123456789abc", "../other-env"); err == nil {
		t.Fatal("DeleteAppEnv accepted path-traversal envUUID")
	}
}

func TestHTTPError_Error_TruncatesLongBody(t *testing.T) {
	// Bodies long enough to potentially carry echoed request headers or
	// other sensitive context must be cut at maxErrorBodyBytes so they
	// don't drag credentials into operator transcripts / CI logs.
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	e := &HTTPError{Method: "POST", Path: "/x", StatusCode: 500, Body: long}
	msg := e.Error()
	if len(msg) > 400 {
		t.Errorf("Error() should truncate long body, got %d chars", len(msg))
	}
	if !strings.Contains(msg, "…") {
		t.Errorf("Error() should mark truncation with ellipsis, got: %q", msg)
	}
}

func TestNew_HTTPClient_StripsAuthorizationOnRedirect(t *testing.T) {
	// Same-host redirect: Go's default would forward the Bearer token.
	// Our CheckRedirect strips Authorization on every hop so a misconfigured
	// reverse proxy redirect can't exfiltrate the operator's API token.
	var secondReqAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.Redirect(w, r, "/second", http.StatusFound)
			return
		}
		secondReqAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "secret-token")
	_, _ = c.doBytes("GET", "/first", nil)
	if secondReqAuth != "" {
		t.Errorf("Authorization leaked across redirect: %q", secondReqAuth)
	}
}
