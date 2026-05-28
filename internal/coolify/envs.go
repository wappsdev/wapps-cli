package coolify

import (
	"errors"
	"fmt"
	"net/http"
)

// EnvEntry mirrors Coolify's per-env-var record. Only the fields the CLI
// needs are exposed; the API may include more (timestamps, audit info)
// that we ignore on parse.
type EnvEntry struct {
	UUID        string `json:"uuid"`
	Key         string `json:"key"`
	Value       string `json:"value"`
	IsBuildtime bool   `json:"is_buildtime"`
}

// ListAppEnvs returns every env entry on the given application. Used by
// the sync --target=coolify diff to compute add/change/remove sets.
//
// Coolify v4 response may be either a top-level array OR a {"data": [...]}
// envelope (same as ListApplications). We accept both shapes via doRaw.
func (c *Client) ListAppEnvs(appUUID string) ([]EnvEntry, error) {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return nil, err
	}
	data, err := c.doRaw("GET", "/applications/"+appUUID+"/envs", nil)
	if err != nil {
		return nil, fmt.Errorf("coolify.ListAppEnvs: %w", err)
	}
	out := make([]EnvEntry, 0, len(data))
	for _, item := range data {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		entry := EnvEntry{
			UUID:        asString(m, "uuid"),
			Key:         asString(m, "key"),
			Value:       asString(m, "value"),
			IsBuildtime: asBool(m, "is_buildtime"),
		}
		out = append(out, entry)
	}
	return out, nil
}

// UpsertAppEnv creates or updates a single env entry on the application.
// Uses the POST-then-PATCH-on-409 pattern that SetBuildArgs introduced
// to handle "key may or may not already exist" idempotently. Generalized
// from SetBuildArgs so sync --target=coolify (isBuildtime=false) and
// SetBuildArgs (isBuildtime=true) share one upsert implementation.
func (c *Client) UpsertAppEnv(appUUID, key, value string, isBuildtime bool) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	body := map[string]interface{}{
		"key":          key,
		"value":        value,
		"is_preview":   false,
		"is_buildtime": isBuildtime,
		"is_literal":   true,
	}
	// Try POST first (create). 409 means the key already exists → PATCH instead.
	_, postErr := c.doBytes("POST", "/applications/"+appUUID+"/envs", body)
	if postErr == nil {
		return nil
	}
	var httpErr *HTTPError
	if !errors.As(postErr, &httpErr) || httpErr.StatusCode != http.StatusConflict {
		return fmt.Errorf("coolify.UpsertAppEnv[%s] POST: %w", key, postErr)
	}
	if _, err := c.doBytes("PATCH", "/applications/"+appUUID+"/envs", body); err != nil {
		return fmt.Errorf("coolify.UpsertAppEnv[%s] PATCH after 409: %w", key, err)
	}
	return nil
}

// DeleteAppEnv removes an env entry by its UUID (Coolify's per-entry id,
// returned by ListAppEnvs). The CLI doesn't expose key-based delete because
// the underlying API requires the UUID.
func (c *Client) DeleteAppEnv(appUUID, envUUID string) error {
	if err := validateUUID("appUUID", appUUID); err != nil {
		return err
	}
	if err := validateUUID("envUUID", envUUID); err != nil {
		return err
	}
	if _, err := c.doBytes("DELETE", "/applications/"+appUUID+"/envs/"+envUUID, nil); err != nil {
		return fmt.Errorf("coolify.DeleteAppEnv[%s]: %w", envUUID, err)
	}
	return nil
}

// asString safely extracts a string from a map. Returns "" if missing or wrong type.
// Coolify responses are loosely typed (interface{} from JSON), so we tolerate
// surprise field types rather than crashing.
func asString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func asBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

