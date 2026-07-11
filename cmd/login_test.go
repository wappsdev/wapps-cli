package cmd

// login token-cache testleri (SPEC §7.2): cloudflared seam → 0600 önbellek +
// --check çıktısı token baytları basmaz.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/session"
)

// fakeJWT, verilen email+exp ile imzasız-shape bir JWT üretir (yalnızca payload
// çözümü test edilir; imza kenarda doğrulanır).
func fakeJWT(email string, exp int64) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"email":%q,"exp":%d}`, email, exp)))
	return "eyJhbGciOiJSUzI1NiJ9." + payload + ".c2ln"
}

// TestRunLogin_CachesToken0600, login akışını sürer: cloudflaredLogin seam'i bir
// JWT döner → token session/<host>.json'a 0600 + exp ile yazılır; stdout token
// baytları içermez.
func TestRunLogin_CachesToken0600(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("WAPPS_SECRETS_GATE", "https://gate.test.example")

	exp := time.Now().Add(45 * time.Minute).Unix()
	tok := fakeJWT("a@wapps.co", exp)

	prev := cloudflaredLogin
	cloudflaredLogin = func(cmd *cobra.Command, gate string) (string, error) {
		if gate != "https://gate.test.example" {
			t.Errorf("cloudflaredLogin gate = %q, want the configured gate", gate)
		}
		return tok, nil
	}
	t.Cleanup(func() { cloudflaredLogin = prev })

	cmd := loginCmd
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	if err := runLogin(cmd); err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	if strings.Contains(out.String(), tok) {
		t.Error("login output must never contain token bytes")
	}

	s, ok := session.Load("gate.test.example")
	if !ok || s.Token != tok || s.ExpiresAt != exp {
		t.Fatalf("cached session mismatch: %+v ok=%v", s, ok)
	}
	path, _ := session.Path("gate.test.example")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("session cache mode = %o, want 0600", fi.Mode().Perm())
	}
}

// TestRunLogin_RejectsNonJWT, seam JWT-olmayan bir şey dönerse INTERNAL + cache YOK.
func TestRunLogin_RejectsNonJWT(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("WAPPS_SECRETS_GATE", "https://gate.test.example")

	prev := cloudflaredLogin
	cloudflaredLogin = func(cmd *cobra.Command, gate string) (string, error) {
		return "not-a-jwt", nil
	}
	t.Cleanup(func() { cloudflaredLogin = prev })

	cmd := loginCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runLogin(cmd); !clierr.Is(err, clierr.Internal) {
		t.Fatalf("want INTERNAL on non-JWT token, got %v", err)
	}
	if _, ok := session.Load("gate.test.example"); ok {
		t.Error("no session must be cached when the token is unusable")
	}
}

// TestCloudflaredLogin_QuietNoLeak, GERÇEK cloudflaredLogin'i sahte bir cloudflared
// ile sürer. Sahte binary, `access login` --quiet YOKSA JWT basar (gerçek cloudflared
// davranışı). Kod --quiet geçtiği için kullanıcıya YÖNLENDİRİLEN çıktı token İÇERMEMELİ;
// dönen token yine de JWT olmalı (regresyon kilidi — codex P1 token-leak).
func TestCloudflaredLogin_QuietNoLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cloudflared is a POSIX shell script")
	}
	exp := time.Now().Add(30 * time.Minute).Unix()
	tok := fakeJWT("a@wapps.co", exp)

	dir := t.TempDir()
	script := "#!/bin/sh\nJWT='" + tok + "'\n" + `if [ "$1" = access ] && [ "$2" = login ]; then
  echo 'A browser window should have opened at the following URL:'
  echo 'https://gate.test/cdn-cgi/access/cli?redirect_url=...'
  case " $* " in *' --quiet '*|*' -q '*) : ;; *) echo 'Successfully fetched your token:'; echo "$JWT" ;; esac
  exit 0
fi
if [ "$1" = access ] && [ "$2" = token ]; then printf '%s' "$JWT"; exit 0; fi
exit 1
`
	if err := os.WriteFile(filepath.Join(dir, "cloudflared"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cmd := &cobra.Command{}
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	got, err := cloudflaredLogin(cmd, "https://gate.test")
	if err != nil {
		t.Fatalf("cloudflaredLogin: %v", err)
	}
	if got != tok {
		t.Fatalf("returned token mismatch")
	}
	if strings.Contains(out.String(), tok) || strings.Contains(errb.String(), tok) {
		t.Error("login must pass --quiet so cloudflared never prints the JWT to the user's terminal")
	}
}

// TestIsolatedEnv, cloudflared alt-process env'inin tüm home/config/cache anahtarlarını
// tmpHome'a sabitlediğini + cloudflared/tunnel override'larını düşürdüğünü + sıradan
// değişkenleri koruduğunu doğrular (platformdan bağımsız — codex P2 izolasyon).
func TestIsolatedEnv(t *testing.T) {
	t.Setenv("TUNNEL_ORIGIN_CERT", "/real/cert.pem")
	t.Setenv("CLOUDFLARED_EDGE", "x")
	t.Setenv("XDG_CONFIG_HOME", "/real/config")
	t.Setenv("APPDATA", `C:\real\appdata`)

	home := filepath.Join(t.TempDir(), "pinned")
	env := isolatedEnv(home)

	seen := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			seen[kv[:i]] = kv[i+1:]
		}
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		if seen[k] != home {
			t.Errorf("%s = %q, want pinned to %q", k, seen[k], home)
		}
	}
	if _, ok := seen["TUNNEL_ORIGIN_CERT"]; ok {
		t.Error("TUNNEL_* overrides must be dropped")
	}
	if _, ok := seen["CLOUDFLARED_EDGE"]; ok {
		t.Error("CLOUDFLARED_* overrides must be dropped")
	}
	if seen["PATH"] == "" {
		t.Error("ordinary vars like PATH must be preserved")
	}
	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("HOME appears %d times, want exactly 1 (no duplicate)", count)
	}
}

// TestLoginCheck_PrintsSubjectNoToken, --check öznesi + TTL basar, token basmaz;
// oturum yoksa SESSION_EXPIRED.
func TestLoginCheck_PrintsSubjectNoToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("WAPPS_SECRETS_GATE", "https://gate.test.example")

	cmd := loginCmd
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	if err := runLoginCheck(cmd); !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("no session: want SESSION_EXPIRED, got %v", err)
	}

	exp := time.Now().Add(30 * time.Minute).Unix()
	tok := fakeJWT("a@wapps.co", exp)
	if err := session.Save("gate.test.example", session.State{Token: tok, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runLoginCheck(cmd); err != nil {
		t.Fatalf("runLoginCheck: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "a@wapps.co") {
		t.Errorf("--check must print the subject; got %q", got)
	}
	if strings.Contains(got, tok) || strings.Contains(got, "c2ln") {
		t.Errorf("--check must not print token bytes; got %q", got)
	}
}
