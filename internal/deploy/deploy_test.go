package deploy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testCreds(ep string) Creds {
	return Creds{Endpoint: ep, Token: "tok", CFAccessID: "cfid", CFAccessSecret: "cfsec"}
}

func TestTrigger_HappyPath_ReturnsUUID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/deploy/migrator" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" ||
			r.Header.Get("CF-Access-Client-Id") != "cfid" ||
			r.Header.Get("CF-Access-Client-Secret") != "cfsec" {
			t.Errorf("missing/wrong proxy headers: %v", r.Header)
		}
		_, _ = w.Write([]byte(`{"deployment_uuid":"mq12riea3yg6169dg0gs5xxo"}`))
	}))
	defer srv.Close()

	c := New(testCreds(srv.URL), "vaulter")
	uuid, err := c.Trigger(context.Background(), "migrator")
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if uuid != "mq12riea3yg6169dg0gs5xxo" {
		t.Errorf("uuid = %q", uuid)
	}
}

// U7: empty deployment_uuid → exit 6.
func TestTrigger_EmptyUUID_Exit6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"deployment_uuid":""}`))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "x")
	if err == nil || err.Code != ExitProxy {
		t.Fatalf("want ExitProxy, got %v", err)
	}
}

func TestTrigger_InvalidUUIDShape_Exit6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"deployment_uuid":"UPPER-and-short"}`))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "x")
	if err == nil || err.Code != ExitProxy {
		t.Fatalf("want ExitProxy for invalid uuid shape, got %v", err)
	}
}

// U11 / I2 / I4: 403 with proxy JSON → exit 3; 403 HTML (CF edge) → exit 4.
func TestTrigger_403_ProxyVsCFEdge(t *testing.T) {
	t.Run("proxy 403 → exit 3", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"service not allowlisted for this token"}`))
		}))
		defer srv.Close()
		_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "royco-api")
		if err == nil || err.Code != ExitAuthScope {
			t.Fatalf("want ExitAuthScope (3), got %v", err)
		}
		if !strings.Contains(err.Error(), "scope") {
			t.Errorf("message should mention scope: %v", err)
		}
	})
	t.Run("CF edge 403 HTML → exit 4", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body>Cloudflare Access</body></html>`))
		}))
		defer srv.Close()
		_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "auth")
		if err == nil || err.Code != ExitCFAccess {
			t.Fatalf("want ExitCFAccess (4), got %v", err)
		}
		if !strings.Contains(err.Error(), "Cloudflare Access") {
			t.Errorf("message should point at CF Access: %v", err)
		}
	})
}

// CheckRedirect: a CF-edge 302 is surfaced as exit 4 and NOT followed, so the
// CF Access headers are never replayed to the redirect target.
func TestTrigger_302_NotFollowed_Exit4(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
	}))
	defer target.Close()
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/login", http.StatusFound) // 302, no proxy JSON
	}))
	defer edge.Close()

	_, err := New(testCreds(edge.URL), "vaulter").Trigger(context.Background(), "auth")
	if err == nil || err.Code != ExitCFAccess {
		t.Fatalf("want ExitCFAccess (4) for a 302, got %v", err)
	}
	if atomic.LoadInt32(&targetHits) != 0 {
		t.Errorf("redirect must NOT be followed (CF Access headers would leak); target hit %d times", targetHits)
	}
}

func TestTrigger_401_Exit3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "auth")
	if err == nil || err.Code != ExitAuthScope {
		t.Fatalf("want ExitAuthScope (3), got %v", err)
	}
}

// I9: upstream 502 → exit 6.
func TestTrigger_502_Exit6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"unexpected upstream response"}`))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "auth")
	if err == nil || err.Code != ExitProxy {
		t.Fatalf("want ExitProxy (6), got %v", err)
	}
}

// I8: network unreachable → exit 5.
func TestTrigger_Network_Exit5(t *testing.T) {
	c := New(Creds{Endpoint: "http://127.0.0.1:1", Token: "t", CFAccessID: "i", CFAccessSecret: "s"}, "vaulter")
	c.HTTP.Timeout = 200 * time.Millisecond
	_, err := c.Trigger(context.Background(), "auth")
	if err == nil || err.Code != ExitNetwork {
		t.Fatalf("want ExitNetwork (5), got %v", err)
	}
}

func TestTrigger_NeverLeaksCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Trigger(context.Background(), "gateway")
	for _, secret := range []string{"tok", "cfid", "cfsec"} {
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("credential %q leaked into error: %v", secret, err)
		}
	}
}

// U8: status classification table.
func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		status       string
		wantTerminal bool
		wantSuccess  bool
	}{
		{"finished", true, true},
		{"failed", true, false},
		{"error", true, false},
		{"cancelled", true, false},
		{"cancelled-by-force", true, false},
		{"in_progress", false, false},
		{"queued", false, false},
		{"unknown", false, false},
	}
	for _, c := range cases {
		term, ok := classifyStatus(c.status)
		if term != c.wantTerminal || ok != c.wantSuccess {
			t.Errorf("classifyStatus(%q) = (%v,%v), want (%v,%v)", c.status, term, ok, c.wantTerminal, c.wantSuccess)
		}
	}
}

// I5: --wait success after polling.
func TestWait_PollsUntilFinished(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := "in_progress"
		if atomic.AddInt32(&n, 1) >= 3 {
			st = "finished"
		}
		_, _ = w.Write([]byte(`{"status":"` + st + `"}`))
	}))
	defer srv.Close()
	var buf bytes.Buffer
	status, err := New(testCreds(srv.URL), "vaulter").Wait(context.Background(), "dep1", "auth", time.Millisecond, time.Second, &buf)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// Wait writes only NON-terminal progress lines; the terminal "finished" is
	// the caller's summary, so the buffer carries the in_progress polls only.
	if status != "finished" {
		t.Errorf("status=%q, want finished", status)
	}
	if !strings.Contains(buf.String(), "in_progress") || strings.Contains(buf.String(), "finished") {
		t.Errorf("buffer should hold progress lines only, got %q", buf.String())
	}
}

// I6: --wait failed → exit 8.
func TestWait_Failed_Exit8(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"failed"}`))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Wait(context.Background(), "d", "auth", time.Millisecond, time.Second, &bytes.Buffer{})
	if err == nil || err.Code != ExitFailed {
		t.Fatalf("want ExitFailed (8), got %v", err)
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("error message should carry the status: %v", err)
	}
}

// I7: --wait timeout → exit 7.
func TestWait_Timeout_Exit7(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"in_progress"}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := New(testCreds(srv.URL), "vaulter").Wait(ctx, "d", "auth", 5*time.Millisecond, 7*time.Second, &bytes.Buffer{})
	if err == nil || err.Code != ExitTimeout {
		t.Fatalf("want ExitTimeout (7), got %v", err)
	}
	// Spec §5 / I7: message carries the configured timeout seconds.
	if !strings.Contains(err.Error(), "TIMEOUT (7s)") {
		t.Errorf("timeout message should include seconds, got %q", err.Error())
	}
}

// status 404 mid-poll (owner TTL) → exit 6.
func TestWait_404MidPoll_Exit6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"unknown deployment for this token"}`))
	}))
	defer srv.Close()
	_, err := New(testCreds(srv.URL), "vaulter").Wait(context.Background(), "d", "auth", time.Millisecond, time.Second, &bytes.Buffer{})
	if err == nil || err.Code != ExitProxy {
		t.Fatalf("want ExitProxy (6), got %v", err)
	}
}

// U5: local service-name validation.
func TestValidateServiceName(t *testing.T) {
	bad := []string{"", "a", "BAD_Name", "Auth", "-x", "x_y", strings.Repeat("a", 60)}
	for _, s := range bad {
		if err := ValidateServiceName(s); err == nil {
			t.Errorf("ValidateServiceName(%q) should fail", s)
		}
	}
	for _, s := range []string{"auth", "migrator", "vaulter-db", "ai", "labellens-api"} {
		if err := ValidateServiceName(s); err != nil {
			t.Errorf("ValidateServiceName(%q) should pass: %v", s, err)
		}
	}
}

func TestNew_DefaultEndpoint(t *testing.T) {
	if New(Creds{Token: "t"}, "vaulter").Creds.Endpoint != DefaultEndpoint {
		t.Error("endpoint should default")
	}
}
