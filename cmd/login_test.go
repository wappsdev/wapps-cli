package cmd

// login token-cache testleri (SPEC §7.2): callback yakalama + 0600 önbellek +
// --check çıktısı token baytları basmaz.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"net/url"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/session"
)

// fakeJWT, verilen email+exp ile imzasız-shape bir JWT üretir (yalnızca payload
// çözümü test edilir; imza kenarda doğrulanır).
func fakeJWT(email string, exp int64) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"email":%q,"exp":%d}`, email, exp)))
	return "eyJhbGciOiJSUzI1NiJ9." + payload + ".c2ln"
}

// TestWaitForCallbackToken_CapturesToken, tarayıcı callback'inin token query
// param'ını teslim ettiğini doğrular (cloudflared paritesi).
func TestWaitForCallbackToken_CapturesToken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tok := fakeJWT("a@wapps.co", time.Now().Add(time.Hour).Unix())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Tarayıcıyı simüle et: kısa bir gecikmeyle callback'e vur.
		time.Sleep(50 * time.Millisecond)
		resp, herr := http.Get("http://" + ln.Addr().String() + "/callback?token=" + tok)
		if herr == nil {
			// Yanıt gövdesi token'ı ASLA içermemeli.
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			_ = resp.Body.Close()
			if strings.Contains(buf.String(), tok) {
				t.Errorf("callback response must not echo the token")
			}
		}
	}()

	got, err := waitForCallbackToken(ln, 5*time.Second)
	if err != nil {
		t.Fatalf("waitForCallbackToken: %v", err)
	}
	if got != tok {
		t.Fatalf("captured token mismatch")
	}
	<-done
}

// TestWaitForCallbackToken_Timeout, SSO tamamlanmazsa SESSION_EXPIRED döner.
func TestWaitForCallbackToken_Timeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = waitForCallbackToken(ln, 50*time.Millisecond)
	if !clierr.Is(err, clierr.SessionExpired) {
		t.Fatalf("want SESSION_EXPIRED on timeout, got %v", err)
	}
}

// TestRunLogin_CachesToken0600, tam login akışını sürer: openBrowser seam'i
// callback'i tetikler → token session/<host>.json'a 0600 + exp ile yazılır ve
// stdout token baytları içermez.
func TestRunLogin_CachesToken0600(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("WAPPS_SECRETS_GATE", "https://gate.test.example")

	exp := time.Now().Add(45 * time.Minute).Unix()
	tok := fakeJWT("a@wapps.co", exp)

	prevOpen := openBrowser
	openBrowser = func(u string) error {
		// Access CLI login URL'inden redirect_url'ü çöz ve token'la vur.
		i := strings.Index(u, "redirect_url=")
		if i < 0 {
			t.Errorf("login URL missing redirect_url: %s", u)
			return nil
		}
		cb, _ := url.QueryUnescape(u[i+len("redirect_url="):])
		go func() {
			time.Sleep(50 * time.Millisecond)
			_, _ = http.Get(cb + "?token=" + tok)
		}()
		return nil
	}
	t.Cleanup(func() { openBrowser = prevOpen })

	prevTimeout := loginTimeout
	loginTimeout = 5 * time.Second
	t.Cleanup(func() { loginTimeout = prevTimeout })

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
