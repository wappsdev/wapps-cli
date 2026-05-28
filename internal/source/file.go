package source

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// fileSource reads a .env-style file from disk and wraps each KEY=VALUE in
// the tofu-output-shaped envelope so it merges cleanly with tofu sources.
//
// Operators interact with this file directly. We tolerate:
//   - blank lines (skipped)
//   - "# ..." comments (skipped, line must START with #)
//   - "export KEY=VALUE" lines (export keyword stripped)
//   - values wrapped in matching single or double quotes (quotes stripped)
//
// We REJECT (return error) when:
//   - file does not exist
//   - a line is non-empty and non-comment but has no "=" delimiter (likely a
//     syntax mistake; silent skip would lose data without telling the operator)
type fileSource struct {
	path string

	// readFile is dependency-injected for tests. Production = os.ReadFile.
	readFile func(string) ([]byte, error)
}

func newFileSource(cfg Config) (*fileSource, error) {
	if cfg.Workdir != "" {
		return nil, fmt.Errorf("source[file]: unexpected field 'workdir' (use 'path')")
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("source[file]: missing required field 'path'")
	}
	return &fileSource{path: cfg.Path, readFile: os.ReadFile}, nil
}

func (f *fileSource) Name() string { return "file (" + f.path + ")" }
func (f *fileSource) Type() string { return "file" }

func (f *fileSource) Read(ctx context.Context) (map[string]json.RawMessage, error) {
	data, err := f.readFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("source[%s]: %w", f.Name(), err)
	}
	return parseEnvFile(f.path, data)
}

// parseEnvFile walks an env-file byte stream and returns the same shape as
// tofu output -json: {"KEY": {"value": "..."}}. Errors quote the file path
// and line number so operators can fix the source quickly.
func parseEnvFile(path string, data []byte) (map[string]json.RawMessage, error) {
	out := make(map[string]json.RawMessage)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip "export " prefix if present.
		line = strings.TrimPrefix(line, "export ")
		idx := strings.Index(line, "=")
		if idx <= 0 {
			return nil, fmt.Errorf("source[file (%s)]: line %d: no '=' delimiter (got %q)", path, lineNo, line)
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = unquote(val)

		// Wrap in tofu-output value envelope so downstream code (env, get)
		// reads from one canonical shape regardless of source.
		envelope, err := json.Marshal(map[string]string{"value": val})
		if err != nil {
			return nil, fmt.Errorf("source[file (%s)]: line %d: marshal: %w", path, lineNo, err)
		}
		out[key] = envelope
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("source[file (%s)]: scan: %w", path, err)
	}
	return out, nil
}

// unquote strips a matching pair of single or double quotes wrapping the
// value. KEY="value with spaces" → "value with spaces". KEY='it''s' → "it''s"
// (we don't try to decode shell-style escape sequences; operators who want
// embedded quotes should use json:value form or a tofu source).
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	first := s[0]
	last := s[len(s)-1]
	if (first == '"' || first == '\'') && first == last {
		return s[1 : len(s)-1]
	}
	return s
}
