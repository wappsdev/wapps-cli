// Package deploy is a client for the company-deploy-proxy
// (https://deploy-proxy.meapps.dev): the ONLY supported path to redeploy the
// root-level vaulter trio (proxy/db-admin/migrator) and gateway, whose scoped
// Coolify tokens intentionally cannot deploy via the direct Coolify API.
//
// Contract is authoritative from the proxy server (vaulter-api
// deployments/deploy-proxy/main.go); this client mirrors it exactly:
//
//	POST  {EP}/v1/deploy/{service}     → 200 {"deployment_uuid":"<20-32 lc-alnum>"}
//	GET   {EP}/v1/deployments/{id}     → 200 {"status":"<coolify status>"}
//	every non-2xx (that reached Go)    → {"error":"<message>"}
//
// Three headers on every request: Authorization: Bearer <repo-scoped token>
// (read by the Go server) + CF-Access-Client-Id / CF-Access-Client-Secret
// (consumed by Cloudflare Access at the edge, before the request reaches Go).
// That edge is the discriminator between a proxy auth/scope failure and a CF
// Access failure: a proxy response carries the {"error":...} JSON; a CF edge
// block does not.
//
// AI-safe: this package never logs or returns the credential values; callers
// see only the service name, deployment UUID, and status strings.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultEndpoint is the company-deploy-proxy base URL.
const DefaultEndpoint = "https://deploy-proxy.meapps.dev"

// DefaultPollInterval matches the ci.yml wait loop (sleep 15).
const DefaultPollInterval = 15 * time.Second

// Exit codes — the contract callers (CI §6, runbooks, agents) depend on.
const (
	ExitOK        = 0 // triggered (no --wait) or --wait reached "finished"
	ExitUsage     = 1 // bad/extra arg, bad service shape, unknown --repo (no network)
	ExitCreds     = 2 // proxy token and/or CF Access id+secret unresolved
	ExitAuthScope = 3 // proxy 401 unauthorized / 403 not-allowlisted (has proxy JSON)
	ExitCFAccess  = 4 // Cloudflare Access edge block (403/302/5xx, no proxy JSON)
	ExitNetwork   = 5 // DNS / refused / TLS / client timeout — call never completed
	ExitProxy     = 6 // 400/502/404 proxy JSON, or 200 with empty/invalid uuid
	ExitTimeout   = 7 // --wait deadline elapsed, last status non-terminal
	ExitFailed    = 8 // --wait saw failed / error / cancelled*
)

// Validation regexes mirror main.go (serviceNameRe, deploymentIDRe). The
// client pre-validates the service name (fail fast, no round-trip) and
// validates the returned deployment id.
var (
	serviceNameRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	deploymentIDRe = regexp.MustCompile(`^[a-z0-9]{20,32}$`)
)

// ValidateServiceName checks the proxy's own name shape locally so an obviously
// bad name never burns a network round-trip (exit 1).
func ValidateServiceName(service string) error {
	if !serviceNameRe.MatchString(service) {
		return &Error{Code: ExitUsage, Msg: fmt.Sprintf("usage: invalid service name %q (must match ^[a-z][a-z0-9-]{1,40}$)", service)}
	}
	return nil
}

// Error carries an exit code with its message. The message is always AI-safe —
// it names credential KEYS, never values.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Creds are the three proxy credentials plus the endpoint.
type Creds struct {
	Endpoint       string
	Token          string
	CFAccessID     string
	CFAccessSecret string
}

// Client talks to the deploy proxy. Repo is used only for AI-safe error text
// (which env key to check). HTTP is injectable for tests.
type Client struct {
	Creds Creds
	Repo  string
	HTTP  *http.Client
}

// New returns a Client with a 45s-timeout HTTP client (above the proxy's own
// 30s upstream budget so a slow-but-successful trigger is not misread as a
// network failure; the overall --wait deadline is enforced separately via
// context). Redirects are NOT followed: the proxy contract has none, and
// following a Cloudflare-Access edge redirect would (a) make the 302→exit-4
// branch unreachable and (b) replay the CF-Access-Client-* headers to the
// redirect target (Go strips Authorization on a cross-host redirect but not
// custom headers). ErrUseLastResponse surfaces the 3xx to classifyHTTP instead.
func New(creds Creds, repo string) *Client {
	if creds.Endpoint == "" {
		creds.Endpoint = DefaultEndpoint
	}
	return &Client{Creds: creds, Repo: repo, HTTP: &http.Client{
		Timeout:       45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.Creds.Token)
	req.Header.Set("CF-Access-Client-Id", c.Creds.CFAccessID)
	req.Header.Set("CF-Access-Client-Secret", c.Creds.CFAccessSecret)
	req.Header.Set("User-Agent", "wapps-cli")
}

func (c *Client) base() string { return strings.TrimRight(c.Creds.Endpoint, "/") }

// Trigger POSTs the deploy and returns the deployment UUID, classifying every
// failure per the §5 error matrix.
func (c *Client) Trigger(ctx context.Context, service string) (string, *Error) {
	u := c.base() + "/v1/deploy/" + url.PathEscape(service)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", &Error{Code: ExitProxy, Msg: "error: build request: " + err.Error()}
	}
	c.auth(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", &Error{Code: ExitNetwork, Msg: fmt.Sprintf("error: cannot reach proxy at %s (network)", c.Creds.Endpoint)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return "", classifyHTTP("deploy", service, c.Repo, resp.StatusCode, body)
	}

	dep := parseField(body, "deployment_uuid")
	if dep == "" {
		return "", &Error{Code: ExitProxy, Msg: "error: proxy returned empty deployment_uuid"}
	}
	if !deploymentIDRe.MatchString(dep) {
		return "", &Error{Code: ExitProxy, Msg: "error: proxy returned an invalid deployment id"}
	}
	return dep, nil
}

// Status fetches one deployment status. Errors are classified so a mid-poll
// failure maps to the right exit code (fail-closed).
func (c *Client) Status(ctx context.Context, deploymentUUID string) (string, *Error) {
	u := c.base() + "/v1/deployments/" + url.PathEscape(deploymentUUID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", &Error{Code: ExitProxy, Msg: "error: build request: " + err.Error()}
	}
	c.auth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", &Error{Code: ExitNetwork, Msg: fmt.Sprintf("error: cannot reach proxy at %s (network)", c.Creds.Endpoint)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", classifyHTTP("status", deploymentUUID, c.Repo, resp.StatusCode, body)
	}
	st := parseField(body, "status")
	if st == "" {
		// jq `// "unknown"` default — keep polling.
		return "unknown", nil
	}
	return st, nil
}

// classifyStatus maps a proxy status string to (terminal, success), matching
// ci.yml's wait_deploy: finished → ok; failed/cancelled*/error → fail; anything
// else keeps polling.
func classifyStatus(status string) (terminal, success bool) {
	switch {
	case status == "finished":
		return true, true
	case status == "failed" || status == "error" || strings.HasPrefix(status, "cancelled"):
		return true, false
	default:
		return false, false
	}
}

// Wait polls until a terminal status or ctx deadline (the caller sets the
// deadline on ctx). interval defaults to DefaultPollInterval; timeout is used
// only to render the seconds in the TIMEOUT message (the real deadline is on
// ctx). Only NON-terminal progress lines are written to statusW (prefixed with
// label, never credentials); the terminal line/summary is the caller's to print
// (success → its own summary; failure/timeout → the returned Error's message),
// so a status never appears twice. Returns the final status and an *Error with
// the right exit code on failure/timeout.
func (c *Client) Wait(ctx context.Context, deploymentUUID, label string, interval, timeout time.Duration, statusW io.Writer) (string, *Error) {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	timedOut := func() *Error {
		return &Error{Code: ExitTimeout, Msg: fmt.Sprintf("  %s: TIMEOUT (%ds)", label, int(timeout.Seconds()))}
	}
	for {
		st, derr := c.Status(ctx, deploymentUUID)
		if derr != nil {
			// A status-query failure mid-poll is fail-closed (matches ci.yml).
			// A context deadline surfaces as a timeout, not a network error.
			if ctx.Err() != nil {
				return st, timedOut()
			}
			return "", derr
		}
		if terminal, ok := classifyStatus(st); terminal {
			if ok {
				return st, nil
			}
			return st, &Error{Code: ExitFailed, Msg: fmt.Sprintf("  %s: %s", label, st)}
		}
		fmt.Fprintf(statusW, "  %s: %s\n", label, st)
		select {
		case <-ctx.Done():
			return st, timedOut()
		case <-time.After(interval):
		}
	}
}

// classifyHTTP turns a non-2xx proxy/edge response into the right exit code.
// route is "deploy" or "status"; subject is the service name or deployment id.
func classifyHTTP(route, subject, repo string, status int, body []byte) *Error {
	proxyMsg, isProxyJSON := parseProxyError(body)

	if !isProxyJSON {
		// Body is not the proxy's {"error":...} JSON. A 403/302/5xx here was
		// stopped at the Cloudflare Access edge before reaching Go.
		switch {
		case status == http.StatusForbidden || status == http.StatusFound || status >= 500:
			return &Error{Code: ExitCFAccess, Msg: "error: blocked by Cloudflare Access — check DEPLOY_PROXY_CF_ACCESS_CLIENT_ID/_SECRET"}
		default:
			return &Error{Code: ExitProxy, Msg: fmt.Sprintf("error: unexpected proxy response (HTTP %d)", status)}
		}
	}

	// Reached the Go proxy — classify by status.
	switch status {
	case http.StatusUnauthorized:
		return &Error{Code: ExitAuthScope, Msg: "error: proxy rejected token (401 unauthorized) — check DEPLOY_PROXY_TOKEN_" + envRepoSuffix(repo)}
	case http.StatusForbidden:
		return &Error{Code: ExitAuthScope, Msg: fmt.Sprintf("error: %q not in scope for repo %q (proxy 403)", subject, repo)}
	case http.StatusBadRequest:
		return &Error{Code: ExitProxy, Msg: fmt.Sprintf("error: proxy rejected request (400 %s)", proxyMsg)}
	case http.StatusNotFound:
		return &Error{Code: ExitProxy, Msg: fmt.Sprintf("error: deployment %q not known to this token (404 %s)", subject, proxyMsg)}
	case http.StatusBadGateway:
		return &Error{Code: ExitProxy, Msg: fmt.Sprintf("error: proxy upstream error (502 %s)", proxyMsg)}
	default:
		return &Error{Code: ExitProxy, Msg: fmt.Sprintf("error: proxy error (HTTP %d %s)", status, proxyMsg)}
	}
}

// parseProxyError reports whether body is the proxy's {"error":"..."} shape and
// returns the (non-secret, server-authored) message.
func parseProxyError(body []byte) (string, bool) {
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Error == "" {
		return "", false
	}
	return out.Error, true
}

func parseField(body []byte, field string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	raw, ok := m[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// envRepoSuffix mirrors the env key suffix rule: upper-case, dash→underscore.
func envRepoSuffix(repo string) string {
	return strings.ToUpper(strings.ReplaceAll(repo, "-", "_"))
}
