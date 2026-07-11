package cmd

// login token-cache testleri (SPEC §7.2): cloudflared seam → 0600 önbellek +
// --check çıktısı token baytları basmaz.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
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
