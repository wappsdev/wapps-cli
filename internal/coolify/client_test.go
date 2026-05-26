package coolify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

func TestSetBuildArgs_PATCHesEnvsBulkAsBuildTime(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/envs/bulk") {
			t.Errorf("expected /envs/bulk endpoint, got %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	if err := c.SetBuildArgs("app-uuid-xyz", []string{
		"SERVICE_NAME=gateway",
		"VERSION=dev",
		"=bogus",       // should be skipped (empty key)
		"NO_EQUAL_SIGN", // should be skipped
	}); err != nil {
		t.Fatalf("SetBuildArgs: %v", err)
	}

	data, ok := gotBody["data"].([]interface{})
	if !ok {
		t.Fatalf("expected data array in body, got %v", gotBody)
	}
	if len(data) != 2 {
		t.Fatalf("expected 2 build args (malformed skipped), got %d: %v", len(data), data)
	}
	first := data[0].(map[string]interface{})
	if first["key"] != "SERVICE_NAME" || first["value"] != "gateway" {
		t.Errorf("first entry mismatch: %v", first)
	}
	if first["is_build_time"] != true {
		t.Errorf("expected is_build_time=true, got %v", first["is_build_time"])
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
