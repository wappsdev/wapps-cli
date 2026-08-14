package secrets

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// seedGet, store fake'ini iki anahtarla doldurur ve proje dizinini kurar.
func seedGet(t *testing.T) *fakeStore {
	t.Helper()
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["jwt_key"] = "abc-123"
	f.values["db_password"] = "pgpass"
	return f
}

func TestGetReturnsSingleValue(t *testing.T) {
	seedGet(t)
	var buf bytes.Buffer
	if err := runGet("jwt_key", &buf); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "abc-123" {
		t.Errorf("want abc-123, got %q", buf.String())
	}
}

// Olmayan anahtar SESSİZ boş değil, adı konmuş NOT_FOUND.
func TestGetMissingKeyError(t *testing.T) {
	seedGet(t)
	var buf bytes.Buffer
	err := runGet("nope", &buf)
	if err == nil {
		t.Fatal("missing key must error")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error must name the key, got %v", err)
	}
}

func TestListReturnsAllNames(t *testing.T) {
	seedGet(t)
	var buf bytes.Buffer
	if err := runList(&buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{"jwt_key", "db_password"} {
		if !strings.Contains(got, want) {
			t.Errorf("name %q missing:\n%s", want, got)
		}
	}
	// list ADLARI basar, DEĞERLERİ asla.
	for _, secret := range []string{"abc-123", "pgpass"} {
		if strings.Contains(got, secret) {
			t.Errorf("list leaked a value: %q", got)
		}
	}
}

func TestRawValueToString_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"hello"`, "hello"},
		{"null", `null`, ""},
		{"absent (empty raw)", ``, ""},
		{"array", `["a","b"]`, `["a","b"]`},
		{"number", `42`, "42"},
		{"bool", `true`, "true"},
		{"object", `{"k":"v"}`, `{"k":"v"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rawValueToString(json.RawMessage(c.raw)); got != c.want {
				t.Errorf("rawValueToString(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func containsEnv(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}
