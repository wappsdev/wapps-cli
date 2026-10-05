// ucoracle is the live Go oracle of tests/updatecheck.rs: it runs the REAL
// internal/updatecheck code (and Go's time package) on vectors read from
// stdin, one JSON object per line, and answers one JSON object per line.
//
// It lives under a `testdata` directory so `go build ./...`, `go vet` and
// `go test ./...` skip it; the Rust test runs it with `go run`. Being inside
// the module is what lets it import the internal package.
//
// Kinds:
//
//	semver  {"s": b64}                         -> {"ok", "v"}
//	compare {"a", "b"}                         -> {"sign"}
//	format  {"t": [sec, nsec]}                 -> {"json"}   json.Marshal(time.Unix(sec, nsec)), Local = $TZ
//	parse   {"s": b64}                         -> {"ok", "t": [sec, nsec]}  Time.UnmarshalJSON(s)
//	notify  {"current", "now": [sec, nsec], "cache": b64|null,
//	         "status", "body": b64, "delay_ms"} -> {"out", "hits", "cache": b64|null}
//
// For notify, a local server answers the release request with status and
// body, but only when the request carries GitHub's Accept header and the
// User-Agent wapps-cli (else 400), the same rule as the Rust test's server.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/wappsdev/wapps-cli/internal/updatecheck"
)

type vector struct {
	Kind    string   `json:"kind"`
	S       string   `json:"s"`
	A       string   `json:"a"`
	B       string   `json:"b"`
	T       [2]int64 `json:"t"`
	Current string   `json:"current"`
	Now     [2]int64 `json:"now"`
	Cache   *string  `json:"cache"`
	Status  int      `json:"status"`
	Body    string   `json:"body"`
	DelayMs int      `json:"delay_ms"`
}

func b64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	enc := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var v vector
		if err := json.Unmarshal(in.Bytes(), &v); err != nil {
			panic(err)
		}
		switch v.Kind {
		case "semver":
			s, ok := updatecheck.ParseSemver(string(b64(v.S)))
			out := map[string]any{"ok": ok}
			if ok {
				out["v"] = s.String()
			}
			_ = enc.Encode(out)
		case "compare":
			a, _ := updatecheck.ParseSemver(v.A)
			b, _ := updatecheck.ParseSemver(v.B)
			c := updatecheck.Compare(a, b)
			sign := 0
			if c > 0 {
				sign = 1
			} else if c < 0 {
				sign = -1
			}
			_ = enc.Encode(map[string]any{"sign": sign})
		case "format":
			b, err := json.Marshal(time.Unix(v.T[0], v.T[1]))
			if err != nil {
				_ = enc.Encode(map[string]any{"json": nil})
				continue
			}
			_ = enc.Encode(map[string]any{"json": string(b)})
		case "parse":
			var t time.Time
			err := t.UnmarshalJSON(b64(v.S))
			out := map[string]any{"ok": err == nil}
			if err == nil {
				out["t"] = [2]int64{t.Unix(), int64(t.Nanosecond())}
			}
			_ = enc.Encode(out)
		case "notify":
			_ = enc.Encode(notify(v))
		default:
			panic("unknown kind " + v.Kind)
		}
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}

func notify(v vector) map[string]any {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("Accept") != "application/vnd.github+json" ||
			r.Header.Get("User-Agent") != "wapps-cli" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if v.DelayMs > 0 {
			time.Sleep(time.Duration(v.DelayMs) * time.Millisecond)
		}
		w.WriteHeader(v.Status)
		_, _ = w.Write(b64(v.Body))
	}))
	defer srv.Close()

	dir, err := os.MkdirTemp("", "ucoracle")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "wapps", "version-check.json")
	if v.Cache != nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, b64(*v.Cache), 0o644); err != nil {
			panic(err)
		}
	}

	var buf bytes.Buffer
	now := time.Unix(v.Now[0], v.Now[1])
	updatecheck.MaybeNotify(&buf, updatecheck.Options{
		CurrentVersion: v.Current,
		APIURL:         srv.URL,
		CacheDir:       dir,
		Now:            func() time.Time { return now },
	})

	out := map[string]any{"out": buf.String(), "hits": atomic.LoadInt32(&hits), "cache": nil}
	if b, err := os.ReadFile(path); err == nil {
		out["cache"] = base64.StdEncoding.EncodeToString(b)
	}
	return out
}
