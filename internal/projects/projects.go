// Package projects implements the optional ~/.config/wapps/projects.yaml
// registry that backs the `--project <name>` flag: a name → directory map so an
// operator can run `wapps secrets get X --project vaulter` from any cwd instead
// of `cd`-ing into the project and using `--config`.
//
//	projects:
//	  vaulter:  /Users/me/Documents/Projects/infra-tofu/projects/vaulter
//	  vibe-pro: /Users/me/Documents/Projects/infra-tofu/projects/vibe-pro
//	  lab:      /Users/me/Documents/Projects/infra-tofu/projects/lab
//
// The registry is purely a convenience layer over --config: --project resolves
// to <dir>/.wapps.yaml, which then feeds the same config-root path resolution.
package projects

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Registry is the parsed projects.yaml.
type Registry struct {
	Projects map[string]string `yaml:"projects"`
}

// DefaultPath returns ~/.config/wapps/projects.yaml, honoring XDG_CONFIG_HOME.
func DefaultPath() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps", "projects.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("projects: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "wapps", "projects.yaml"), nil
}

// Resolve returns the directory registered for name. Returns a typed
// not-found error (matching the spec's message) when the registry is missing or
// the name is absent; a real read/parse error surfaces verbatim so the operator
// fixes a corrupted file rather than seeing a misleading "unknown project".
func Resolve(name string) (string, error) {
	path, err := DefaultPath()
	if err != nil {
		return "", unknownProject(name)
	}
	return resolveIn(path, name)
}

// resolveIn is Resolve with an explicit registry path (testable without
// touching the real home dir).
func resolveIn(path, name string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", unknownProject(name)
		}
		return "", fmt.Errorf("projects: read %s: %w", path, err)
	}
	var r Registry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return "", fmt.Errorf("projects: parse %s: %w", path, err)
	}
	dir, ok := r.Projects[name]
	if !ok || dir == "" {
		return "", unknownProject(name)
	}
	return expandHome(dir), nil
}

// expandHome turns a leading ~/ into the absolute home dir so operators can
// write portable entries in projects.yaml.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func unknownProject(name string) error {
	return fmt.Errorf("unknown project %q (add to ~/.config/wapps/projects.yaml or use --config)", name)
}
