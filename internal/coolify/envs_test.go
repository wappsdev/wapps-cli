package coolify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListAppEnvs_TopLevelArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/applications/app-1/envs" {
			t.Errorf("path mismatch: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"uuid": "env-uuid-1", "key": "DB_PASSWORD", "value": "secret", "is_buildtime": false},
			{"uuid": "env-uuid-2", "key": "BUILD_TAG", "value": "v1.0", "is_buildtime": true},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "fake-token")
	envs, err := c.ListAppEnvs("app-1")
	if err != nil {
		t.Fatalf("ListAppEnvs: %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 envs, got %d", len(envs))
	}
	if envs[0].Key != "DB_PASSWORD" || envs[0].Value != "secret" || envs[0].IsBuildtime {
		t.Errorf("entry 0 mismatch: %+v", envs[0])
	}
	if envs[1].IsBuildtime != true {
		t.Errorf("expected is_buildtime=true for BUILD_TAG, got %+v", envs[1])
	}
}

func TestListAppEnvs_ParsesIsCoolify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"uuid": "e1", "key": "SERVICE_URL_API", "value": "https://x", "is_coolify": true},
			{"uuid": "e2", "key": "DB_URL", "value": "pg", "is_coolify": false},
			{"uuid": "e3", "key": "NO_FLAG", "value": "v"}, // absent → false
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	envs, err := c.ListAppEnvs("app-1")
	if err != nil {
		t.Fatalf("ListAppEnvs: %v", err)
	}
	byKey := map[string]EnvEntry{}
	for _, e := range envs {
		byKey[e.Key] = e
	}
	if !byKey["SERVICE_URL_API"].IsCoolify {
		t.Error("SERVICE_URL_API should be is_coolify=true")
	}
	if byKey["DB_URL"].IsCoolify {
		t.Error("DB_URL should be is_coolify=false")
	}
	if byKey["NO_FLAG"].IsCoolify {
		t.Error("absent is_coolify should default to false")
	}
}

func TestListAppEnvs_DataEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"uuid": "env-1", "key": "FOO", "value": "bar"},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	envs, err := c.ListAppEnvs("app-1")
	if err != nil {
		t.Fatalf("ListAppEnvs: %v", err)
	}
	if len(envs) != 1 || envs[0].Key != "FOO" {
		t.Errorf("envelope shape parse failed: %+v", envs)
	}
}

func TestListAppEnvs_EmptyArchive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	envs, err := c.ListAppEnvs("app-1")
	if err != nil {
		t.Fatalf("ListAppEnvs: %v", err)
	}
	if len(envs) != 0 {
		t.Errorf("expected empty slice, got %+v", envs)
	}
}

func TestUpsertAppEnv_POST_HappyPath(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	if err := c.UpsertAppEnv("app-1", "FOO", "bar", false); err != nil {
		t.Fatalf("UpsertAppEnv: %v", err)
	}
	if len(calls) != 1 || calls[0] != "POST" {
		t.Errorf("expected single POST, got %v", calls)
	}
}

func TestUpsertAppEnv_FallsBackToPATCHOn409(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		if r.Method == "POST" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if r.Method == "PATCH" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	if err := c.UpsertAppEnv("app-1", "FOO", "new-value", true); err != nil {
		t.Fatalf("UpsertAppEnv: %v", err)
	}
	if len(calls) != 2 || calls[0] != "POST" || calls[1] != "PATCH" {
		t.Errorf("expected POST→PATCH, got %v", calls)
	}
}

func TestUpsertAppEnv_NonConflictPOSTErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	err := c.UpsertAppEnv("app-1", "FOO", "v", false)
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "POST") {
		t.Errorf("error should label POST stage: %v", err)
	}
}

func TestUpsertAppEnv_IsBuildtimeFalse(t *testing.T) {
	// Confirms runtime env (not build arg) path: is_buildtime=false in body.
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	if err := c.UpsertAppEnv("app-1", "RUNTIME_VAR", "value", false); err != nil {
		t.Fatalf("UpsertAppEnv: %v", err)
	}
	if gotBody["is_buildtime"] != false {
		t.Errorf("is_buildtime should be false, got %v", gotBody["is_buildtime"])
	}
}

func TestUpsertAppEnv_IsBuildtimeTrue(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	if err := c.UpsertAppEnv("app-1", "BUILD_TAG", "v1", true); err != nil {
		t.Fatalf("UpsertAppEnv: %v", err)
	}
	if gotBody["is_buildtime"] != true {
		t.Errorf("is_buildtime should be true, got %v", gotBody["is_buildtime"])
	}
}

func TestDeleteAppEnv_HappyPath(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	if err := c.DeleteAppEnv("app-1", "env-uuid-xyz"); err != nil {
		t.Fatalf("DeleteAppEnv: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("expected DELETE, got %s", gotMethod)
	}
	if gotPath != "/applications/app-1/envs/env-uuid-xyz" {
		t.Errorf("path mismatch: %s", gotPath)
	}
}

func TestDeleteAppEnv_RejectsEmptyUUID(t *testing.T) {
	c := New("http://unused", "tok")
	err := c.DeleteAppEnv("app-1", "")
	if err == nil {
		t.Fatal("expected error on empty envUUID")
	}
}

func TestDeleteAppEnv_PropagatesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	err := c.DeleteAppEnv("app-1", "env-x")
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !strings.Contains(err.Error(), "DeleteAppEnv") {
		t.Errorf("error should label call site: %v", err)
	}
}
