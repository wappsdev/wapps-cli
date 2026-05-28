// Package config parses the per-repo .wapps.yaml file.
//
// .wapps.yaml lives at the repo root and declares which secret sources feed
// the encrypted archive, where to write it, and a few policy knobs. Keeping
// the schema small + fixed (Source.Type values are compile-time, not plugin-
// loaded) means typos surface as parse errors, not silent empty archives.
//
// Example:
//
//	version: 1
//	dest: secrets/all.enc.age
//	sources:
//	  - type: tofu
//	    workdir: .
//	    prefix: "TF_VAR_"
//	  - type: file
//	    path: .env.shared
//	    prefix: ""
//	redact_in_logs: true
//	require_clean_git: true
package config

import (
	"fmt"
	"os"

	"github.com/wappsdev/wapps-cli/internal/source"
	"gopkg.in/yaml.v3"
)

// WappsYAML is the parsed schema. Defaults are applied during Load, so callers
// can rely on fields being populated.
type WappsYAML struct {
	Version         int             `yaml:"version"`
	Dest            string          `yaml:"dest"`
	Sources         []source.Config `yaml:"sources"`
	RedactInLogs    bool            `yaml:"redact_in_logs"`
	RequireCleanGit bool            `yaml:"require_clean_git"`
}

const (
	defaultDest    = "secrets/all.enc.age"
	defaultVersion = 1
)

// Load reads and validates .wapps.yaml at path. Missing fields get sensible
// defaults (version=1, dest=secrets/all.enc.age). Anything that looks like a
// typo (unknown source type, missing required source field, version > 1)
// returns an error so the operator sees the problem before they sync.
func Load(path string) (*WappsYAML, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse is Load split out for testability. Same validation runs in both paths.
func Parse(data []byte) (*WappsYAML, error) {
	var y WappsYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := applyDefaultsAndValidate(&y); err != nil {
		return nil, err
	}
	return &y, nil
}

func applyDefaultsAndValidate(y *WappsYAML) error {
	if y.Version == 0 {
		y.Version = defaultVersion
	}
	if y.Version != 1 {
		return fmt.Errorf("config: unsupported version %d (only 1 is supported by this CLI)", y.Version)
	}
	if y.Dest == "" {
		y.Dest = defaultDest
	}
	if len(y.Sources) == 0 {
		return fmt.Errorf("config: at least one source required (got empty sources list)")
	}
	// Validate each source declaration by attempting to construct its adapter.
	// This catches unknown types, missing required fields, mutually-exclusive
	// fields (e.g., tofu source with 'path' set) at config-load time rather
	// than at first sync.
	for i, cfg := range y.Sources {
		if _, err := source.New(cfg); err != nil {
			return fmt.Errorf("config: sources[%d]: %w", i, err)
		}
	}
	return nil
}
