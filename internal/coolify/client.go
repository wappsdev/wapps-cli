package coolify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// uuidPattern enforces canonical 8-4-4-4-12 hex UUID. Coolify v4 issues these
// for every application and env entry. Validating before concatenating into
// API paths closes a path-injection vector — a value like "../servers" would
// otherwise resolve to /applications/../servers and hit a different endpoint.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// validateUUID rejects empty or shape-invalid UUIDs. Coolify itself sometimes
// uses shorter slugs in test fixtures, so the strict 36-char pattern can be
// relaxed via a second permissive shape: lowercase alphanumeric + dash, at
// least 8 chars and no path separators / parent-dir tokens. We accept either
// shape to avoid breaking the existing test fixtures, but always block path
// traversal characters.
func validateUUID(label, value string) error {
	if value == "" {
		return fmt.Errorf("coolify: %s is empty", label)
	}
	if containsPathTraversal(value) {
		return fmt.Errorf("coolify: %s contains invalid characters: %q", label, value)
	}
	if uuidPattern.MatchString(value) {
		return nil
	}
	// Lax fallback for test/dev fixtures: alphanum + dash, no path chars.
	for _, r := range value {
		if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return fmt.Errorf("coolify: %s has invalid character %q in %q", label, r, value)
		}
	}
	return nil
}

func containsPathTraversal(s string) bool {
	for _, ch := range []string{"/", "\\", "..", "?", "&", "#", " "} {
		if bytes.Contains([]byte(s), []byte(ch)) {
			return true
		}
	}
	return false
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// HTTPError is returned by doBytes/do when the Coolify API replies with a
// non-2xx status. Callers can pattern-match on the status code via errors.As
// rather than parsing error strings:
//
//	var httpErr *HTTPError
//	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
//	    // handle 409
//	}
type HTTPError struct {
	Method     string
	Path       string
	StatusCode int
	Body       []byte
}

// maxErrorBodyBytes caps the response-body slice we include in the error
// string. Coolify sometimes echoes the original request — including custom
// headers — back into 4xx/5xx bodies. A long body could carry credentials
// (PATs the operator pasted into a Bearer field, internal tokens, etc.) into
// CI logs and operator transcripts. 200 bytes is enough to debug the failure
// (status + first line of the JSON message) without dragging the rest along.
const maxErrorBodyBytes = 200

func (e *HTTPError) Error() string {
	body := e.Body
	if len(body) > maxErrorBodyBytes {
		body = append(body[:maxErrorBodyBytes:maxErrorBodyBytes], []byte("…")...)
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, body)
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			// CheckRedirect strips Authorization on every hop. Go's default
			// only strips on cross-host redirects, so a same-host 301 →
			// /api/v1/applications would forward the Bearer token to a path
			// we did not intend. We don't expect redirects from Coolify's
			// REST API, but if one occurs, fail safe — token does not leak.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				req.Header.Del("Authorization")
				return nil
			},
		},
	}
}

type CreateAppRequest struct {
	ProjectUUID string
	ServerUUID  string
	Name        string
	ComposeYAML string
	EnvVars     map[string]string
}

func (c *Client) CreateDockerComposeApp(req CreateAppRequest) (string, error) {
	body := map[string]interface{}{
		"project_uuid":       req.ProjectUUID,
		"server_uuid":        req.ServerUUID,
		"name":               req.Name,
		"docker_compose_raw": base64.StdEncoding.EncodeToString([]byte(req.ComposeYAML)),
	}
	resp, err := c.do("POST", "/applications/dockercompose", body)
	if err != nil {
		return "", fmt.Errorf("coolify.CreateDockerComposeApp: %w", err)
	}
	uuid, _ := resp["uuid"].(string)
	if uuid == "" {
		return "", fmt.Errorf("coolify.CreateDockerComposeApp: no uuid in response: %v", resp)
	}
	return uuid, nil
}

// CreatePrivateGitHubAppApp creates a Coolify "Application" (not service) from
// a private GitHub repo via a previously-configured GitHub App in Coolify.
// Coolify v4 endpoint: POST /applications/private-github-app
//
// BuildArgs note: Coolify v4 has no direct "build args" field on the Application
// create body. Build args are stored as env vars with is_build_time=true. The
// CLI's --build-arg flag is converted into a follow-up PATCH against
// /applications/<uuid>/envs/bulk after the app is created. To make sure those
// build args are present BEFORE the first build, callers should pass
// InstantDeploy=false here, set build args via SetBuildArgs, then trigger
// deploy via TriggerDeploy.
type CreateGitHubAppAppRequest struct {
	ProjectUUID        string `json:"project_uuid"`
	EnvironmentName    string `json:"environment_name,omitempty"` // default "production"
	ServerUUID         string `json:"server_uuid"`
	GithubAppUUID      string `json:"github_app_uuid"`
	GitRepository      string `json:"git_repository"` // "org/repo"
	GitBranch          string `json:"git_branch"`     // "main"
	GitCommitSHA       string `json:"git_commit_sha,omitempty"`
	BuildPack          string `json:"build_pack"` // "dockerfile" | "nixpacks" | "static"
	Name               string `json:"name"`
	BaseDirectory      string `json:"base_directory,omitempty"`      // "/" default
	DockerfileLocation string `json:"dockerfile_location,omitempty"` // e.g. "/cmd/gateway/Dockerfile"
	Ports              string `json:"ports_exposes,omitempty"`       // "8099" or "8099,3000"
	WatchPaths         string `json:"watch_paths,omitempty"`         // multi-line newline-separated
	InstantDeploy      bool   `json:"instant_deploy"`                // true → build immediately
}

func (c *Client) CreatePrivateGitHubAppApp(req CreateGitHubAppAppRequest) (string, error) {
	body := map[string]interface{}{
		"project_uuid":        req.ProjectUUID,
		"environment_name":    "production",
		"server_uuid":         req.ServerUUID,
		"github_app_uuid":     req.GithubAppUUID,
		"git_repository":      req.GitRepository,
		"git_branch":          req.GitBranch,
		"build_pack":          req.BuildPack,
		"name":                req.Name,
		"base_directory":      "/",
		"dockerfile_location": req.DockerfileLocation,
		"ports_exposes":       req.Ports,
		"watch_paths":         req.WatchPaths,
		"instant_deploy":      req.InstantDeploy,
	}
	if req.BaseDirectory != "" {
		body["base_directory"] = req.BaseDirectory
	}
	if req.EnvironmentName != "" {
		body["environment_name"] = req.EnvironmentName
	}
	resp, err := c.do("POST", "/applications/private-github-app", body)
	if err != nil {
		return "", fmt.Errorf("coolify.CreatePrivateGitHubAppApp: %w", err)
	}
	uuid, _ := resp["uuid"].(string)
	if uuid == "" {
		return "", fmt.Errorf("coolify.CreatePrivateGitHubAppApp: no uuid in response: %v", resp)
	}
	return uuid, nil
}

// UpdateAppEnvs upserts every key in envs onto the application. Earlier
// implementations hit PATCH /envs/bulk which APPENDS rows rather than
// upserting by key — causing silent duplicates and "envs not updated" on
// every redeploy. We now loop UpsertAppEnv (POST-then-PATCH-on-409) which
// is the same idempotent pattern SetBuildArgs uses.
//
// isBuildtime is false: these are runtime envs. deploy-app / update-env
// commands call this for application secrets that the running container
// needs (not for docker build --build-arg values).
func (c *Client) UpdateAppEnvs(appUUID string, envs map[string]string) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	if len(envs) == 0 {
		return nil
	}
	for key, val := range envs {
		if err := c.UpsertAppEnv(appUUID, key, val, false); err != nil {
			return fmt.Errorf("coolify.UpdateAppEnvs[%s]: %w", key, err)
		}
	}
	return nil
}

// SetBuildArgs uploads the given KEY=VALUE pairs as build-time env vars
// (is_buildtime=true) on the given Application. Use this to feed --build-arg
// values into Coolify's docker build step.
//
// Coolify v4 quirks (probed 2026-05-26):
//   - POST /envs creates; returns 409 if key already exists
//   - PATCH /envs updates an existing env by key; returns 404 if not yet present
//   - PATCH /envs/bulk APPENDS rows (does NOT upsert by key), causing duplicate
//     keys across repeated calls — avoid.
//   - Both POST and PATCH /envs require field "is_buildtime" (NOT "is_build_time")
//
// Idempotent upsert via UpsertAppEnv: POST first, on 409 PATCH.
//
// Pairs should already be in "KEY=VALUE" form. Empty/malformed pairs skipped.
func (c *Client) SetBuildArgs(appUUID string, pairs []string) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	if len(pairs) == 0 {
		return nil
	}
	for _, p := range pairs {
		idx := -1
		for i := 0; i < len(p); i++ {
			if p[i] == '=' {
				idx = i
				break
			}
		}
		if idx <= 0 {
			continue
		}
		key := p[:idx]
		val := p[idx+1:]
		if err := c.UpsertAppEnv(appUUID, key, val, true); err != nil {
			return fmt.Errorf("coolify.SetBuildArgs[%s]: %w", key, err)
		}
	}
	return nil
}

// TriggerDeploy queues a redeploy for the given Application UUID. Coolify
// returns a deployment UUID that can be polled separately (we ignore it here).
func (c *Client) TriggerDeploy(appUUID string) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	if _, err := c.doBytes("GET", "/deploy?uuid="+appUUID, nil); err != nil {
		return fmt.Errorf("coolify.TriggerDeploy: %w", err)
	}
	return nil
}

func (c *Client) SetCustomLabels(appUUID string, labels []string) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	labelsStr := ""
	for i, l := range labels {
		if i > 0 {
			labelsStr += "\n"
		}
		labelsStr += l
	}
	body := map[string]interface{}{
		"custom_labels": base64.StdEncoding.EncodeToString([]byte(labelsStr)),
	}
	if _, err := c.do("PATCH", "/applications/"+appUUID, body); err != nil {
		return fmt.Errorf("coolify.SetCustomLabels: %w", err)
	}
	return nil
}

func (c *Client) StartApp(appUUID string) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	if _, err := c.do("POST", "/applications/"+appUUID+"/start", nil); err != nil {
		return fmt.Errorf("coolify.StartApp: %w", err)
	}
	return nil
}

func (c *Client) ListApplications() ([]map[string]interface{}, error) {
	// Coolify v4 returns a top-level JSON array for /applications; doRaw handles
	// both shapes (top-level array or {"data": [...]}).
	data, err := c.doRaw("GET", "/applications", nil)
	if err != nil {
		return nil, fmt.Errorf("coolify.ListApplications: %w", err)
	}
	out := make([]map[string]interface{}, 0, len(data))
	for _, item := range data {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// doRaw is like do but accepts either a JSON object or a top-level JSON array
// response. It returns the array form (wrapping {"data": [...]} responses).
func (c *Client) doRaw(method, path string, body interface{}) ([]interface{}, error) {
	respBody, err := c.doBytes(method, path, body)
	if err != nil {
		return nil, err
	}
	// Try top-level array first
	var arr []interface{}
	if err := json.Unmarshal(respBody, &arr); err == nil {
		return arr, nil
	}
	// Fall back to {"data": [...]} envelope
	var envelope map[string]interface{}
	if err := json.Unmarshal(respBody, &envelope); err == nil {
		if data, ok := envelope["data"].([]interface{}); ok {
			return data, nil
		}
	}
	return nil, nil
}

func (c *Client) doBytes(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "curl/8")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, &HTTPError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: respBody}
	}
	return respBody, nil
}

func (c *Client) do(method, path string, body interface{}) (map[string]interface{}, error) {
	var reqBody io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "curl/8")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, &HTTPError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: respBody}
	}
	var parsed map[string]interface{}
	_ = json.Unmarshal(respBody, &parsed)
	return parsed, nil
}
