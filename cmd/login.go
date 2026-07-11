package cmd

// GERÇEK `wapps login` (server-decrypt SPEC §7.2) — cloudflared-stili CF Access
// tarayıcı akışı:
//  1. Efemeral bir 127.0.0.1 dinleyicisi bağlanır;
//  2. Tarayıcı, gate app'inin Access CLI login URL'ine açılır
//     (https://<gate-host>/cdn-cgi/access/cli?redirect_url=http://127.0.0.1:<port>/callback);
//  3. SSO tamamlanınca callback, app token'ını (CF_Authorization JWT) teslim eder;
//  4. Token ~/.config/wapps/session/<gate-host>.json'a 0600 yazılır (ASLA loglanmaz);
//  5. Her Worker isteği onu cf-access-token header'ı olarak sunar (internal/session.Auth).
//
// CI service-token yolu login gerektirmez: CF_ACCESS_CLIENT_ID/SECRET env →
// CF-Access-Client-Id/Secret header'ları (§7.2 sonu).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// openBrowser, platform tarayıcısını açar (test seam'i).
var openBrowser = func(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}

// loginTimeout, tarayıcı SSO akışının beklenme süresi.
var loginTimeout = 5 * time.Minute

var loginCheck bool

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "CF Access browser login for the secrets gate (§7.2) — TTY only",
	Long: `login opens the browser at the Access CLI login URL for the secrets gate,
captures the returned CF_Authorization app token on a localhost callback, and
caches it 0600 at ~/.config/wapps/session/<gate-host>.json. Every store call
then presents it as the cf-access-token header.

Agent/CI contexts never run login: CI uses a CF Access service token via
CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET (no browser, no session file).

--check prints the current session subject + remaining TTL (never token bytes).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if loginCheck {
			return runLoginCheck(cmd)
		}
		// TTY-only oturum verb'ü (§7.1): ajan modunda AGENT_MODE_REFUSED.
		if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
			return err
		}
		return runLogin(cmd)
	},
}

// runLoginCheck, oturum öznesi + kalan TTL basar (token baytları ASLA).
func runLoginCheck(cmd *cobra.Command) error {
	host := session.GateHost()
	s, ok := session.Load(host)
	if !ok {
		return clierr.New(clierr.SessionExpired, "no session cached for "+host)
	}
	now := time.Now()
	if s.Expired(now) {
		return clierr.New(clierr.SessionExpired, "session for "+host+" has expired")
	}
	w := cmd.OutOrStdout()
	subject := "(unknown subject)"
	if c, err := session.ParseClaims(s.Token); err == nil && c.Email != "" {
		subject = c.Email
	}
	fmt.Fprintf(w, "gate:     %s\n", host)
	fmt.Fprintf(w, "subject:  %s\n", subject)
	if s.ExpiresAt == 0 {
		fmt.Fprintln(w, "expires:  unknown (out-of-band token)")
	} else {
		fmt.Fprintf(w, "expires:  in %s\n", s.TTL(now).Round(time.Second))
	}
	return nil
}

// runLogin, tarayıcı SSO akışını sürer ve token'ı önbelleğe yazar.
func runLogin(cmd *cobra.Command) error {
	gate := session.GateURL()
	host := session.GateHost()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "bind localhost callback listener")
	}
	defer ln.Close()
	callback := fmt.Sprintf("http://%s/callback", ln.Addr().String())
	loginURL := gate + "/cdn-cgi/access/cli?redirect_url=" + url.QueryEscape(callback)

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Opening the browser for CF Access SSO…\nIf it does not open, visit:\n  %s\n", loginURL)
	if berr := openBrowser(loginURL); berr != nil {
		fmt.Fprintln(w, "(could not launch a browser automatically — open the URL above manually)")
	}

	token, err := waitForCallbackToken(ln, loginTimeout)
	if err != nil {
		return err
	}
	exp := int64(0)
	if c, cerr := session.ParseClaims(token); cerr == nil && c.Exp > 0 {
		exp = c.Exp
	}
	if err := session.Save(host, session.State{Token: token, ExpiresAt: exp}); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "cache session token")
	}
	subject := ""
	if c, cerr := session.ParseClaims(token); cerr == nil && c.Email != "" {
		subject = " as " + c.Email
	}
	if exp > 0 {
		fmt.Fprintf(w, "✓ logged in%s (session expires in %s)\n", subject, time.Until(time.Unix(exp, 0)).Round(time.Second))
	} else {
		fmt.Fprintf(w, "✓ logged in%s\n", subject)
	}
	return nil
}

// callbackHandler, Access CLI redirect'ini karşılar: token query param'ı
// (cloudflared paritesi: `token`; tolerans: `cf_authorization`) kanala teslim
// edilir. Token ASLA yanıt gövdesine/loga yazılmaz.
func callbackHandler(tokenCh chan<- string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(rw, r)
			return
		}
		tok := r.URL.Query().Get("token")
		if tok == "" {
			tok = r.URL.Query().Get("cf_authorization")
		}
		if tok == "" {
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = rw.Write([]byte("wapps login: no token in the callback — retry wapps login"))
			return
		}
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = rw.Write([]byte("<html><body><h3>wapps login complete</h3>You may close this tab and return to the terminal.</body></html>"))
		select {
		case tokenCh <- tok:
		default:
		}
	})
}

// waitForCallbackToken, dinleyici üzerinde callback'i bekler (≤ timeout).
func waitForCallbackToken(ln net.Listener, timeout time.Duration) (string, error) {
	tokenCh := make(chan string, 1)
	srv := &http.Server{Handler: callbackHandler(tokenCh), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = err // dinleyici kapanışı normal yol
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	select {
	case tok := <-tokenCh:
		return tok, nil
	case <-time.After(timeout):
		return "", clierr.New(clierr.SessionExpired, "browser SSO not completed in time; re-run wapps login")
	}
}

// --- whoami -------------------------------------------------------------------

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the gate's view of this principal: groups + effective grants (§7.1)",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		st := store.New(store.Config{BaseURL: session.GateURL(), Auth: session.Auth()})
		ctx, cancel := context.WithTimeout(cmdContext(cmd), 15*time.Second)
		defer cancel()
		res, err := st.Whoami(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "principal:      %s\n", res.Principal)
		if res.Email != "" {
			fmt.Fprintf(w, "email:          %s\n", res.Email)
		}
		if res.CommonName != "" {
			fmt.Fprintf(w, "common_name:    %s\n", res.CommonName)
		}
		fmt.Fprintf(w, "groups:         %s\n", joinOrDash(res.Groups))
		fmt.Fprintf(w, "policy_version: %d\n", res.PolicyVersion)
		fmt.Fprintf(w, "root_admin:     %v\n", res.IsRootAdmin)
		if len(res.Grants) == 0 {
			fmt.Fprintln(w, "grants:         (none)")
			return nil
		}
		fmt.Fprintln(w, "grants:")
		for _, g := range res.Grants {
			sel := g.Group
			if g.Service != "" {
				sel = "service:" + g.Service
			}
			if g.Aud != "" {
				sel = "aud:" + g.Aud
			}
			fmt.Fprintf(w, "  %-28s projects=%s keys=%s verbs=%s\n",
				sel, strings.Join(g.Projects, ","), strings.Join(g.Keys, ","), strings.Join(g.Verbs, ","))
		}
		return nil
	},
}

func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ", ")
}

// --- token exchange (opsiyonel mint katmanı, §5.3) ------------------------------

var (
	tokenProject string
	tokenKeys    []string
	tokenVerbs   []string
	tokenTTL     int
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Machine-token operations (CI)",
}

var tokenExchangeCmd = &cobra.Command{
	Use:   "exchange --project <p> --key K [--key K2] [--verb read]",
	Short: "Exchange the CF Access service token for a ≤10-min scoped token (§5.3)",
	Long: `token exchange swaps the pipeline's CF Access service-token pair
(CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET) for a short-TTL machine token
scoped to {project, keys[], verbs[]} ⊆ the service's policy rows, via
POST /v1/token. The minted token is printed to stdout for the pipeline step to
capture; subsequent calls present it via WAPPS_MACHINE_TOKEN. Optional layer —
service tokens may also use the data plane directly.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, ok := lookupServiceCreds(); !ok {
			return clierr.New(clierr.TokenExchangeFailed, "CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET not set")
		}
		if tokenProject == "" || len(tokenKeys) == 0 {
			return clierr.New(clierr.TokenExchangeFailed, "token exchange needs --project and at least one --key")
		}
		st := store.New(store.Config{BaseURL: session.GateURL(), Auth: session.Auth()})
		ctx, cancel := context.WithTimeout(cmdContext(cmd), 15*time.Second)
		defer cancel()
		tok, exp, err := st.TokenMint(ctx, tokenProject, tokenKeys, tokenVerbs, tokenTTL)
		if err != nil {
			return err
		}
		// Minted token stdout'a basılır (pipeline yakalar); metadata stderr'e.
		fmt.Fprintln(cmd.OutOrStdout(), tok)
		if exp > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "token expires at %s (unix %d)\n", time.Unix(exp, 0).UTC().Format(time.RFC3339), exp)
		}
		return nil
	},
}

// lookupServiceCreds, CI service-token env çiftini döner.
func lookupServiceCreds() (string, bool) {
	id := strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_ID"))
	secret := strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_SECRET"))
	if id == "" || secret == "" {
		return "", false
	}
	return id, true
}

func init() {
	loginCmd.Flags().BoolVar(&loginCheck, "check", false, "print session subject + remaining TTL (no token bytes)")
	tokenExchangeCmd.Flags().StringVar(&tokenProject, "project", "", "project scope for the minted token")
	tokenExchangeCmd.Flags().StringArrayVar(&tokenKeys, "key", nil, "exact key name in scope (repeatable)")
	tokenExchangeCmd.Flags().StringArrayVar(&tokenVerbs, "verb", []string{"read"}, "verb in scope (read|write|rotate)")
	tokenExchangeCmd.Flags().IntVar(&tokenTTL, "ttl", 0, "token TTL seconds (≤600; 0 = gate default)")
	tokenCmd.AddCommand(tokenExchangeCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(tokenCmd)
}

// cmdContext, cobra komut context'ini döner; Execute dışı doğrudan RunE
// çağrılarında (test) nil olabilir → Background.
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
