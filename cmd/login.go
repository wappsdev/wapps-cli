package cmd

// GERÇEK `wapps login` (server-decrypt SPEC §7.2) — CF Access SSO.
//
// CF Access CLI akışı localhost-callback redirect'ini REDDEDER ("Invalid redirect
// URL"); tek desteklenen tarayıcı akışı EDGE-TOKEN-TRANSFER'dir (redirect app'in
// kendi domain'ine + edge polling). cloudflared bunun referans implementasyonudur
// (org-session reuse + token cache + renewal) → login ona delege eder:
//  1. `cloudflared access login <gate>` tarayıcıyı açar, SSO'yu sürer, token'ı cache'ler;
//  2. `cloudflared access token -app=<gate>` app token'ını (CF_Authorization JWT) verir;
//  3. Token ~/.config/wapps/session/<gate-host>.json'a 0600 yazılır (ASLA loglanmaz);
//  4. Her Worker isteği onu cf-access-token header'ı olarak sunar (internal/session.Auth).
//
// CI service-token yolu login gerektirmez: CF_ACCESS_CLIENT_ID/SECRET env →
// CF-Access-Client-Id/Secret header'ları (§7.2 sonu).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// cloudflaredLogin, CF Access SSO'yu cloudflared'e delege eder ve app token'ını
// (JWT) döner (test seam'i). cloudflared kurulu değilse NOT_AVAILABLE. Interaktif
// çıktı (SSO URL'i vb.) kullanıcının KENDİ terminaline gider — chat/transcript'e DEĞİL.
var cloudflaredLogin = func(cmd *cobra.Command, gate string) (string, error) {
	cfPath, lerr := exec.LookPath("cloudflared")
	if lerr != nil {
		return "", clierr.New(clierr.NotAvailable,
			"wapps login needs cloudflared for the CF Access SSO flow (edge token transfer).\n"+
				"  install: brew install cloudflared\n"+
				"  then re-run: wapps login")
	}
	// 1) Interaktif SSO: tarayıcı + org-session reuse + token cache.
	login := exec.Command(cfPath, "access", "login", gate)
	login.Stdout, login.Stderr, login.Stdin = cmd.OutOrStdout(), cmd.ErrOrStderr(), os.Stdin
	if rerr := login.Run(); rerr != nil {
		return "", clierr.Wrapf(clierr.Internal, rerr, "cloudflared access login")
	}
	// 2) Cache'lenmiş app token'ını al — yalnızca stdout (temiz JWT).
	var out, errb bytes.Buffer
	tok := exec.Command(cfPath, "access", "token", "-app="+gate)
	tok.Stdout, tok.Stderr = &out, &errb
	if rerr := tok.Run(); rerr != nil {
		return "", clierr.Wrapf(clierr.Internal, rerr, "cloudflared access token: %s", strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

var loginCheck bool

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "CF Access browser login for the secrets gate (§7.2) — TTY only",
	Long: `login runs the CF Access SSO for the secrets gate via cloudflared
(edge token transfer — the CF Access CLI flow rejects a localhost callback), then
caches the returned app token 0600 at ~/.config/wapps/session/<gate-host>.json.
Every store call then presents it as the cf-access-token header.

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

// runLogin, SSO'yu cloudflared'e delege eder ve token'ı önbelleğe yazar.
func runLogin(cmd *cobra.Command) error {
	gate := session.GateURL()
	host := session.GateHost()
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Opening CF Access SSO for %s via cloudflared…\n", host)
	token, err := cloudflaredLogin(cmd, gate)
	if err != nil {
		return err
	}
	if !looksLikeJWT(token) {
		return clierr.New(clierr.Internal, "cloudflared returned no usable token; re-run wapps login")
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

// looksLikeJWT, kabaca üç boş-olmayan base64url segment (header.payload.sig) doğrular.
func looksLikeJWT(s string) bool {
	p := strings.Split(s, ".")
	return len(p) == 3 && p[0] != "" && p[1] != "" && p[2] != ""
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
