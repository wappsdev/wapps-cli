// Package source defines the abstraction over a place secrets can come from.
//
// Each Source implementation reads its underlying system (tofu state, a local
// .env file, a SaaS API, etc.) and returns a map of key → JSON-encoded value
// envelope. The envelope shape mirrors `tofu output -json`:
//
//	{
//	  "JWT_SIGNING_KEY": {"value": "...", "type": "string", "sensitive": true},
//	  "ALLOWED_ORIGINS": {"value": ["a.com", "b.com"], "type": ["tuple", ...]}
//	}
//
// Multiple Sources are merged into the encrypted archive on disk. Later
// readers (`wapps secrets env`, `wapps secrets get`) parse the merged JSON.
package source

import (
	"context"
	"encoding/json"
	"fmt"
)

// Source reads secrets from one place (one source kind in .wapps.yaml).
//
// Implementations should be cheap to construct via New; do real work only in
// Read so misconfiguration surfaces at the call site, not at startup.
type Source interface {
	// Name is a human-friendly identifier for error messages (e.g.,
	// "tofu (workdir=.)", "file (.env.shared)"). Not unique across sources.
	Name() string
	// Type returns the source type as declared in .wapps.yaml ("tofu", "file").
	// Used for diagnostic logging and dispatch in tests.
	Type() string
	// Read returns the secret payload keyed by name. Values are raw JSON so
	// non-string types (lists, maps, numbers, bools) round-trip without loss.
	Read(ctx context.Context) (map[string]json.RawMessage, error)
}

// Config is the per-source declaration parsed from .wapps.yaml.
//
// Only Type is required; the rest are interpreted by the matching adapter.
// Unknown fields surface as ConfigError so typos don't silently produce empty
// archives.
type Config struct {
	Type    string `yaml:"type"`
	Path    string `yaml:"path,omitempty"`    // file source: env-file path
	Workdir string `yaml:"workdir,omitempty"` // tofu source: directory holding .tf files
	Prefix  string `yaml:"prefix,omitempty"`  // reserved (applied at env emit time, not at Read)
}

// New constructs the Source for the given Config. Adapter selection is fixed
// at compile time (P3): unknown types fail loudly rather than dispatching to
// a runtime plugin loader.
func New(cfg Config) (Source, error) {
	switch cfg.Type {
	case "tofu":
		return newTofuSource(cfg)
	case "file":
		return newFileSource(cfg)
	case "":
		return nil, fmt.Errorf("source: missing required field 'type'")
	default:
		return nil, fmt.Errorf("source: unknown type %q (allowed: tofu, file)", cfg.Type)
	}
}

// Merge combines outputs from multiple sources into one map. Later sources
// override earlier ones on key collision, with the collision tracked so the
// caller can warn the operator (an accidental override of a Tofu-managed
// secret by a manually-edited file is almost always a bug).
//
// Returns the merged map AND any keys that were overridden so the caller can
// log/warn. Empty input → empty map, no error.
func Merge(parts []map[string]json.RawMessage) (map[string]json.RawMessage, []string) {
	out := make(map[string]json.RawMessage)
	var overridden []string
	for _, part := range parts {
		for k, v := range part {
			if _, exists := out[k]; exists {
				overridden = append(overridden, k)
			}
			out[k] = v
		}
	}
	return out, overridden
}
