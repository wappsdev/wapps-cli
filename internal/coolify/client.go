package coolify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
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

func (c *Client) UpdateAppEnvs(appUUID string, envs map[string]string) error {
	body := map[string]interface{}{"envs": envs}
	if _, err := c.do("PATCH", "/applications/"+appUUID+"/envs/bulk", body); err != nil {
		return fmt.Errorf("coolify.UpdateAppEnvs: %w", err)
	}
	return nil
}

// SetBuildArgs uploads the given KEY=VALUE pairs as build-time env vars
// (is_buildtime=true) on the given Application. Use this to feed --build-arg
// values into Coolify's docker build step.
//
// Coolify v4 quirks (probed 2026-05-26):
//   - POST /envs accepts "is_buildtime" but NOT "is_build_time" (422)
//   - PATCH /envs (no uuid in path) upserts by key, single env at a time
//   - PATCH /envs/bulk accepts "is_build_time" but does NOT upsert — it
//     appends new rows, causing duplicate keys across calls.
//
// To keep idempotency under repeated runs (Tofu re-applies, etc.), we use
// PATCH /envs which is upsert-by-key. One HTTP call per pair, but the
// catalog is small (~3 build args per service) so this is cheap.
//
// Pairs should already be in "KEY=VALUE" form. Empty pairs are skipped.
func (c *Client) SetBuildArgs(appUUID string, pairs []string) error {
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
		body := map[string]interface{}{
			"key":          key,
			"value":        val,
			"is_preview":   false,
			"is_buildtime": true,
			"is_literal":   true,
		}
		if _, err := c.doBytes("PATCH", "/applications/"+appUUID+"/envs", body); err != nil {
			return fmt.Errorf("coolify.SetBuildArgs[%s]: %w", key, err)
		}
	}
	return nil
}

// TriggerDeploy queues a redeploy for the given Application UUID. Coolify
// returns a deployment UUID that can be polled separately (we ignore it here).
func (c *Client) TriggerDeploy(appUUID string) error {
	if _, err := c.doBytes("GET", "/deploy?uuid="+appUUID, nil); err != nil {
		return fmt.Errorf("coolify.TriggerDeploy: %w", err)
	}
	return nil
}

func (c *Client) SetCustomLabels(appUUID string, labels []string) error {
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
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, respBody)
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
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, respBody)
	}
	var parsed map[string]interface{}
	_ = json.Unmarshal(respBody, &parsed)
	return parsed, nil
}
