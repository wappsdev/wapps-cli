package source

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// FileSourceHeader is prepended to env files written by `wapps secrets set`.
// Per D6.b (eng-review), file sources are machine-managed: naive sorted
// key=value form, no comment preservation. The header tells operators not
// to hand-edit the file (the next `wapps secrets set` would clobber edits).
const FileSourceHeader = "# wapps-managed file, do not edit manually (use 'wapps secrets set <KEY>')\n"

// WriteFileSource adds or updates KEY=VALUE in the env-file at path.
//
// Behavior:
//   - Reads existing entries (if file exists) via parseEnvFile.
//   - Adds or overrides the named key with the new value.
//   - Emits all entries sorted alphabetically by key.
//   - Always writes the FileSourceHeader at top so operators know not to edit.
//   - File mode 0600 (secrets file — owner read/write only).
//
// Single-quote escaping: values are wrapped in single quotes with embedded
// single quotes escaped via the shell-standard '\''  (close-escape-open)
// sequence. This matches the cmd/secrets/env output convention so the file
// can be source'd directly when needed for ad-hoc debugging.
//
// path is created if it doesn't exist. Parent directory must already exist
// (we don't auto-mkdir to avoid surprise directory creation).
func WriteFileSource(path, key, value string) error {
	existing, err := readExisting(path)
	if err != nil {
		return err
	}
	existing[key] = value
	return writeAll(path, existing)
}

// readExisting parses the env file at path into a flat map. Returns empty
// map (no error) if the file doesn't exist — this is the "first set" case.
func readExisting(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]string), nil
	}
	if err != nil {
		return nil, fmt.Errorf("WriteFileSource: read %s: %w", path, err)
	}
	envelope, err := parseEnvFile(path, data)
	if err != nil {
		return nil, fmt.Errorf("WriteFileSource: parse %s: %w", path, err)
	}
	// parseEnvFile returns json envelopes ({"value": "..."}). Unwrap to plain string.
	out := make(map[string]string, len(envelope))
	for k, v := range envelope {
		var inner struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(v, &inner); err != nil {
			return nil, fmt.Errorf("WriteFileSource: unwrap %s key=%s: %w", path, k, err)
		}
		out[k] = inner.Value
	}
	return out, nil
}

// writeAll emits the full map back to disk: header + sorted KEY='VALUE' lines.
// Atomic write via temp+rename so a power loss mid-write can't corrupt the
// file (existing readers either see old contents or fully new contents).
func writeAll(path string, kv map[string]string) error {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString(FileSourceHeader)
	for _, k := range keys {
		v := kv[k]
		escaped := strings.ReplaceAll(v, "'", "'\\''")
		fmt.Fprintf(&buf, "%s='%s'\n", k, escaped)
	}

	// Use the shared atomic-write helper so we get fsync + unique temp name
	// (concurrent-writer safe) for free. Earlier versions used os.WriteFile +
	// os.Rename which skipped fsync; a power loss between rename and the
	// kernel's data flush could leave the file present but empty.
	if err := ageutil.WriteFileAtomic(path, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("WriteFileSource: %w", err)
	}
	return nil
}
