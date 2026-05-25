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

func (c *Client) UpdateAppEnvs(appUUID string, envs map[string]string) error {
	body := map[string]interface{}{"envs": envs}
	if _, err := c.do("PATCH", "/applications/"+appUUID+"/envs/bulk", body); err != nil {
		return fmt.Errorf("coolify.UpdateAppEnvs: %w", err)
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
