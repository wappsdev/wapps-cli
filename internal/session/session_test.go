package session

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSaveLoadRoundtrip, oturumun 0600/0700 izinlerle host-başına dosyada
// saklandığını ve geri yüklendiğini doğrular (SPEC §7.2 adım 3).
func TestSaveLoadRoundtrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")

	exp := time.Now().Add(time.Hour).Unix()
	if err := Save("gw.meapps.dev", State{Token: "jwt-bytes", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	path, err := Path("gw.meapps.dev")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("session file mode = %o, want 0600", fi.Mode().Perm())
	}
	dfi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dfi.Mode().Perm() != 0o700 {
		t.Errorf("session dir mode = %o, want 0700", dfi.Mode().Perm())
	}

	s, ok := Load("gw.meapps.dev")
	if !ok || s.Token != "jwt-bytes" || s.ExpiresAt != exp {
		t.Fatalf("Load = %+v ok=%v", s, ok)
	}
	if s.Expired(time.Now()) {
		t.Error("session should not be expired")
	}
	if s.Expired(time.Unix(exp+1, 0)) == false {
		t.Error("session should be expired after exp")
	}
}

// TestLoad_EnvOverridesFile, WAPPS_SESSION_TOKEN out-of-band token'ının dosyadan
// önce geldiğini doğrular (CI/test yolu).
func TestLoad_EnvOverridesFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "env-token")
	t.Setenv("WAPPS_SESSION_EXPIRES", "")

	s, ok := Load("whatever.host")
	if !ok || s.Token != "env-token" {
		t.Fatalf("env token must win: %+v ok=%v", s, ok)
	}
	if s.ExpiresAt != 0 || s.Expired(time.Now()) {
		t.Error("env token without expiry must never expire client-side")
	}
}

// TestLoad_MissingOrTokenless, oturum yokluğu/boş token → ok=false.
func TestLoad_MissingOrTokenless(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	if _, ok := Load("none.host"); ok {
		t.Fatal("no session file must load as ok=false")
	}
	if err := Save("tokenless.host", State{Token: "", ExpiresAt: 1}); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load("tokenless.host"); ok {
		t.Fatal("a tokenless session file must load as ok=false")
	}
}

// TestParseClaims, JWT payload'ının imza doğrulamadan (yalnızca görüntüleme)
// çözüldüğünü doğrular.
func TestParseClaims(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"a@wapps.co","exp":1700000000}`))
	token := "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"
	c, err := ParseClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "a@wapps.co" || c.Exp != 1700000000 {
		t.Fatalf("claims = %+v", c)
	}
	if _, err := ParseClaims("not-a-jwt"); err == nil {
		t.Fatal("non-JWT must error")
	}
}

// TestGateURLAndHost, WAPPS_SECRETS_GATE env'i + OD-4 varsayılanı.
func TestGateURLAndHost(t *testing.T) {
	t.Setenv("WAPPS_SECRETS_GATE", "")
	if GateURL() != DefaultGateURL || GateHost() != "gw.meapps.dev" {
		t.Fatalf("defaults: url=%s host=%s", GateURL(), GateHost())
	}
	t.Setenv("WAPPS_SECRETS_GATE", "https://gate.example.com/")
	if GateURL() != "https://gate.example.com" || GateHost() != "gate.example.com" {
		t.Fatalf("env override: url=%s host=%s", GateURL(), GateHost())
	}
}
