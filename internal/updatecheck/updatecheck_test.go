package updatecheck

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in        string
		wantOK    bool
		maj, min, pat int
	}{
		{"v0.12.0", true, 0, 12, 0},
		{"0.12.0", true, 0, 12, 0},
		{"v1.2.3", true, 1, 2, 3},
		{"v0.12.0-rc1", true, 0, 12, 0}, // pre-release suffix dropped
		{"v0.12.0+build5", true, 0, 12, 0},
		{"dev", false, 0, 0, 0},
		{"main-2978d52", false, 0, 0, 0},
		{"", false, 0, 0, 0},
		{"v1.2", false, 0, 0, 0},      // not a triple
		{"v1.2.3.4", false, 0, 0, 0},  // too many parts
		{"vX.Y.Z", false, 0, 0, 0},    // non-numeric
		{"v1.-2.3", false, 0, 0, 0},   // negative
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, ok := ParseSemver(c.in)
			if ok != c.wantOK {
				t.Fatalf("ParseSemver(%q) ok=%v, want %v", c.in, ok, c.wantOK)
			}
			if ok && (got.major != c.maj || got.minor != c.min || got.patch != c.pat) {
				t.Errorf("ParseSemver(%q) = %+v, want %d.%d.%d", c.in, got, c.maj, c.min, c.pat)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	mk := func(s string) semver { v, _ := ParseSemver(s); return v }
	cases := []struct {
		a, b string
		want int // sign only
	}{
		{"v1.0.0", "v0.9.9", +1},
		{"v0.12.0", "v0.11.1", +1}, // minor bump
		{"v0.12.1", "v0.12.0", +1}, // patch bump
		{"v0.11.1", "v0.12.0", -1},
		{"v0.12.0", "v0.12.0", 0},
		{"v2.0.0", "v1.99.99", +1}, // major dominates
	}
	for _, c := range cases {
		got := Compare(mk(c.a), mk(c.b))
		sign := 0
		if got > 0 {
			sign = 1
		} else if got < 0 {
			sign = -1
		}
		if sign != c.want {
			t.Errorf("Compare(%s, %s) sign = %d, want %d", c.a, c.b, sign, c.want)
		}
	}
}

// newServer returns an httptest server that serves the given tag and counts
// how many times it was hit (to assert cache behavior).
func newServer(t *testing.T, tag string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name":"` + tag + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func baseOpts(t *testing.T, current, apiURL string) Options {
	t.Helper()
	return Options{
		CurrentVersion: current,
		APIURL:         apiURL,
		CacheDir:       t.TempDir(),
		TTL:            24 * time.Hour,
		Now:            func() time.Time { return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC) },
		HTTPClient:     &http.Client{Timeout: 2 * time.Second},
	}
}

func TestMaybeNotify_NewerAvailable_PrintsNotice(t *testing.T) {
	srv, _ := newServer(t, "v0.13.0")
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))

	out := buf.String()
	if !strings.Contains(out, "v0.13.0") {
		t.Errorf("notice should mention new version, got: %q", out)
	}
	if !strings.Contains(out, "brew upgrade wapps") {
		t.Errorf("notice should include upgrade command, got: %q", out)
	}
}

func TestMaybeNotify_SameVersion_NoNotice(t *testing.T) {
	srv, _ := newServer(t, "v0.12.0")
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))
	if buf.Len() != 0 {
		t.Errorf("no notice expected when up-to-date, got: %q", buf.String())
	}
}

func TestMaybeNotify_OlderLatest_NoNotice(t *testing.T) {
	// Defensive: if GitHub somehow reports an older tag, never tell the user
	// to "upgrade" to something behind them.
	srv, _ := newServer(t, "v0.11.0")
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))
	if buf.Len() != 0 {
		t.Errorf("no notice expected when latest is older, got: %q", buf.String())
	}
}

func TestMaybeNotify_DevBuild_SkipsEntirely(t *testing.T) {
	srv, hits := newServer(t, "v9.9.9")
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "dev", srv.URL))
	if buf.Len() != 0 {
		t.Errorf("dev build must not print a notice, got: %q", buf.String())
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Errorf("dev build must not hit the network, hits=%d", *hits)
	}
}

func TestMaybeNotify_LocalMainBuild_SkipsEntirely(t *testing.T) {
	srv, hits := newServer(t, "v9.9.9")
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "main-2978d52", srv.URL))
	if buf.Len() != 0 || atomic.LoadInt32(hits) != 0 {
		t.Errorf("local main-<sha> build must skip; out=%q hits=%d", buf.String(), *hits)
	}
}

func TestMaybeNotify_FreshCache_NoSecondHTTP(t *testing.T) {
	srv, hits := newServer(t, "v0.13.0")
	opts := baseOpts(t, "v0.12.0", srv.URL)

	MaybeNotify(&bytes.Buffer{}, opts) // first call: fetches + caches
	MaybeNotify(&bytes.Buffer{}, opts) // second call: cache still fresh

	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("expected exactly 1 network hit with fresh cache, got %d", got)
	}
}

func TestMaybeNotify_StaleCache_Refetches(t *testing.T) {
	srv, hits := newServer(t, "v0.13.0")
	opts := baseOpts(t, "v0.12.0", srv.URL)

	// First call at T.
	MaybeNotify(&bytes.Buffer{}, opts)

	// Second call 25h later — cache stale, must refetch.
	opts.Now = func() time.Time { return time.Date(2026, 5, 29, 13, 0, 0, 0, time.UTC) }
	MaybeNotify(&bytes.Buffer{}, opts)

	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("expected 2 network hits across stale cache, got %d", got)
	}
}

func TestMaybeNotify_WritesCacheFile(t *testing.T) {
	srv, _ := newServer(t, "v0.13.0")
	opts := baseOpts(t, "v0.12.0", srv.URL)
	MaybeNotify(&bytes.Buffer{}, opts)

	path := filepath.Join(opts.CacheDir, "wapps", "version-check.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cache file should exist after check: %v", err)
	}
	if !strings.Contains(string(data), "v0.13.0") {
		t.Errorf("cache should record latest version, got: %s", data)
	}
}

func TestMaybeNotify_HTTPError_NoNoticeNoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	// Must not panic, must not print.
	MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))
	if buf.Len() != 0 {
		t.Errorf("server error should produce no notice, got: %q", buf.String())
	}
}

func TestMaybeNotify_UnreachableHost_Swallowed(t *testing.T) {
	opts := baseOpts(t, "v0.12.0", "http://127.0.0.1:1/nope") // closed port
	opts.HTTPClient = &http.Client{Timeout: 200 * time.Millisecond}
	var buf bytes.Buffer
	MaybeNotify(&buf, opts) // should return quickly, no panic, no output
	if buf.Len() != 0 {
		t.Errorf("unreachable host should produce no notice, got: %q", buf.String())
	}
}

func TestMaybeNotify_GarbageTagFromServer_NoNotice(t *testing.T) {
	srv, _ := newServer(t, "not-a-version")
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))
	if buf.Len() != 0 {
		t.Errorf("unparseable server tag should produce no notice, got: %q", buf.String())
	}
}

// TestMaybeNotify_NoTerminalEscapeInjection is the security regression: a
// compromised release whose tag_name smuggles ANSI escape sequences must
// never reach the terminal. The notice is reconstructed from parsed integers,
// so an escape-bearing tag either fails ParseSemver (no notice) or — if it
// somehow parses — is rendered as clean digits. Either way no ESC byte leaks.
func TestMaybeNotify_NoTerminalEscapeInjection(t *testing.T) {
	malicious := []string{
		"v9.9.9\x1b[2J\x1b[H",            // clear screen + home
		"v9.9.9\x1b]0;pwned\x07",         // set window title
		"v9.9.9\r\nFAKE: type your pp",   // CRLF spoof line
		"v\x1b[31m9.9.9",                 // color injection mid-version
	}
	for _, tag := range malicious {
		t.Run(tag, func(t *testing.T) {
			srv, _ := newServer(t, tag)
			var buf bytes.Buffer
			MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))
			out := buf.String()
			if strings.ContainsAny(out, "\x1b\x07\r") {
				t.Errorf("control characters leaked to terminal: %q", out)
			}
		})
	}
}

// TestMaybeNotify_NoticeUsesReconstructedVersion proves the displayed version
// is built from parsed integers, not echoed from the server. A tag with
// leading zeros / odd-but-valid formatting normalizes to canonical vX.Y.Z.
func TestMaybeNotify_NoticeUsesReconstructedVersion(t *testing.T) {
	srv, _ := newServer(t, "v00.013.00") // valid ints, non-canonical text
	var buf bytes.Buffer
	MaybeNotify(&buf, baseOpts(t, "v0.12.0", srv.URL))
	out := buf.String()
	if !strings.Contains(out, "v0.13.0") {
		t.Errorf("notice should show canonical reconstructed version, got: %q", out)
	}
	if strings.Contains(out, "00.013.00") {
		t.Errorf("notice must not echo raw server tag, got: %q", out)
	}
}
