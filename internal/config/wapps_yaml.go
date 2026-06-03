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
//	default_prefix: ""
//	sources:
//	  - type: tofu
//	    workdir: .
//	    prefix: "TF_VAR_"
//	  - type: file
//	    path: .env.shared
//	    prefix: ""
//	targets:
//	  - path: .env.local
//	  - path: terraform.tfvars.json
//	    prefix: "TF_VAR_"
//	redact_in_logs: true
//	require_clean_git: true
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/source"
	"gopkg.in/yaml.v3"
)

// Target deklarasyonu: archive'dan üretilen plaintext consumption dosyası.
// Prefix *string çünkü "yokken default'u kullan" ile "açıkça boş istiyorum"
// arasında fark var: default_prefix='TF_VAR_' iken bir target'in '' istemesi
// gerçek bir senaryo (terraform.tfvars için TF_VAR_, .env.local için plain).
type Target struct {
	Path   string  `yaml:"path"`
	Prefix *string `yaml:"prefix,omitempty"`
}

// EffectivePrefix returns the prefix actually used for this target: explicit
// per-target prefix if set (even to ""), otherwise the repo-wide default.
func (t Target) EffectivePrefix(defaultPrefix string) string {
	if t.Prefix != nil {
		return *t.Prefix
	}
	return defaultPrefix
}

// ResolvePath resolves this target's path against configRoot. Relative paths
// are joined to configRoot; absolute paths (and the empty-configRoot case from
// a Parse-constructed config) pass through unchanged.
func (t Target) ResolvePath(configRoot string) string {
	return resolveRel(configRoot, t.Path)
}

// resolveRel joins p onto configRoot when p is relative. Absolute paths and
// the empty-configRoot case (a config built via Parse, with no file on disk —
// e.g. unit tests) pass through unchanged. This is the single rule the
// secrets-from-anywhere spec mandates: a relative path resolves against the
// .wapps.yaml's directory, an absolute path is used verbatim.
func resolveRel(configRoot, p string) string {
	if p == "" || configRoot == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(configRoot, p)
}

// CoolifyApp maps an archive key-prefix to a single Coolify application for
// multi-app sync (`wapps secrets sync --target=coolify --all-apps`).
//
// ArchivePrefix is matched against archive keys; matching keys are pushed to
// the app's env with the prefix STRIPPED. e.g. ArchivePrefix "KREEVA_WEB_"
// turns archive key "KREEVA_WEB_VITE_API_URL" into Coolify env "VITE_API_URL".
// This is the opposite direction from the single-app `--prefix` flag (which
// prepends).
type CoolifyApp struct {
	UUID          string `yaml:"uuid"`
	Name          string `yaml:"name"`           // comment-only, for readability
	ArchivePrefix string `yaml:"archive_prefix"` // archive keys with this prefix → this app (stripped)
}

// CoolifySync configures multi-app push. Optional; only consulted by
// `--all-apps`. Keys not matched by ANY app's ArchivePrefix are never pushed
// (this is how Tofu outputs like lab_01_* are excluded automatically).
type CoolifySync struct {
	// DeleteUnmanaged, when false (default), makes sync purely additive: a
	// Coolify env key absent from the app's mapped+stripped set is left
	// alone. When true, such keys are deleted to mirror the archive — a
	// destructive operation, off by default on purpose.
	DeleteUnmanaged bool `yaml:"delete_unmanaged"`
	// ExcludeKeys are STRIPPED env-var names (as Coolify sees them, after
	// archive_prefix removal) that sync never pushes, changes, or deletes.
	// For keys owned by the deploy pipeline rather than the archive — e.g.
	// SENTRY_RELEASE, which CI rewrites every deploy and would otherwise
	// perpetually show as drift. Applied to both sides of the diff.
	ExcludeKeys []string     `yaml:"exclude_keys"`
	Apps        []CoolifyApp `yaml:"apps"`
}

// WappsYAML is the parsed schema. Defaults are applied during Load, so callers
// can rely on fields being populated.
type WappsYAML struct {
	Version         int             `yaml:"version"`
	Dest            string          `yaml:"dest"`
	DefaultPrefix   string          `yaml:"default_prefix"`
	Sources         []source.Config `yaml:"sources"`
	Targets         []Target        `yaml:"targets"`
	CoolifySync     *CoolifySync    `yaml:"coolify_sync,omitempty"`
	RedactInLogs    bool            `yaml:"redact_in_logs"`
	RequireCleanGit bool            `yaml:"require_clean_git"`

	// configRoot is the absolute directory of the loaded .wapps.yaml. Set by
	// Load (not Parse). Empty for Parse-constructed configs (no file on disk,
	// e.g. unit tests), which the Resolve* helpers treat as "leave relative
	// paths as-is" (cwd-relative — the legacy behavior).
	configRoot string
}

// ConfigRoot is the absolute directory of the loaded .wapps.yaml, or "" when
// the config was Parse-constructed.
func (c *WappsYAML) ConfigRoot() string { return c.configRoot }

// Resolve joins an arbitrary relative path against this config's configRoot
// (absolute paths and the empty-configRoot case pass through). Used for paths
// that don't have a dedicated helper, e.g. the single file-source path in `set`.
func (c *WappsYAML) Resolve(p string) string { return resolveRel(c.configRoot, p) }

// ResolveDest returns the archive path resolved against configRoot. Dest is
// already defaulted to "secrets/all.enc.age" by applyDefaultsAndValidate, so
// this only ever joins (relative) or passes through (absolute) — the default
// interacts here lazily and Dest itself is never mutated (display/commit hints
// keep the raw repo-relative value).
func (c *WappsYAML) ResolveDest() string { return resolveRel(c.configRoot, c.Dest) }

// ResolvedSources returns a copy of Sources with Path (file source env-file)
// and Workdir (tofu .tf dir) joined to configRoot. Callers pass these to
// source.New so the file/tofu adapters read from the config dir, not cwd. The
// spec lists sources[].path explicitly; we resolve Workdir too because a tofu
// source whose workdir resolved against cwd would silently run `tofu output`
// in the wrong directory — the same class of bug as the dest one.
func (c *WappsYAML) ResolvedSources() []source.Config {
	out := make([]source.Config, len(c.Sources))
	for i, s := range c.Sources {
		s.Path = resolveRel(c.configRoot, s.Path)
		// A tofu source with an omitted workdir defaults to the config dir, not
		// the process cwd. Without this, `--project sync` of a repo whose tofu
		// source leaves workdir blank would silently run `tofu output` in the
		// operator's cwd. We map "" → "." so resolveRel joins it to configRoot
		// (Join(root,".")==root); explicit "." already works the same way. Only
		// applied to tofu — a file source rejects a non-empty workdir.
		if s.Type == "tofu" && s.Workdir == "" {
			s.Workdir = "."
		}
		s.Workdir = resolveRel(c.configRoot, s.Workdir)
		out[i] = s
	}
	return out
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
	y, err := Parse(data)
	if err != nil {
		return nil, err
	}
	// Record the absolute directory of the loaded file so all relative paths
	// (dest, targets, sources) resolve against it rather than cwd. Load is the
	// only entry point that knows the on-disk path; Parse stays pure (configRoot
	// "") so the parse-only unit tests are unaffected.
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve abs path %s: %w", path, err)
	}
	y.configRoot = filepath.Dir(abs)
	return y, nil
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
	if err := validateTargets(y.Targets); err != nil {
		return err
	}
	if err := validateCoolifySync(y.CoolifySync); err != nil {
		return err
	}
	return nil
}

// validateCoolifySync enforces, when the block is present:
//   - each app has a non-empty uuid + archive_prefix
//   - no duplicate uuid (two mappings to the same app is almost always a typo)
//   - no overlapping archive_prefix. We REJECT overlap rather than picking
//     longest-match: silent longest-match could misroute a secret to the
//     wrong app (e.g. "ROYCO_" vs "ROYCO_API_" — a key meant for one could
//     land on the other). For secret material, explicit beats clever.
func validateCoolifySync(cs *CoolifySync) error {
	if cs == nil {
		return nil
	}
	seenUUID := make(map[string]int, len(cs.Apps))
	for i, app := range cs.Apps {
		if app.UUID == "" {
			return fmt.Errorf("config: coolify_sync.apps[%d]: missing required field 'uuid'", i)
		}
		if app.ArchivePrefix == "" {
			return fmt.Errorf("config: coolify_sync.apps[%d] (%s): missing required field 'archive_prefix'", i, app.UUID)
		}
		if j, dup := seenUUID[app.UUID]; dup {
			return fmt.Errorf("config: coolify_sync.apps[%d]: duplicate uuid %q (also at apps[%d])", i, app.UUID, j)
		}
		seenUUID[app.UUID] = i
	}
	// Overlap check: any prefix that is a prefix of another is ambiguous.
	for i := range cs.Apps {
		for j := range cs.Apps {
			if i == j {
				continue
			}
			if strings.HasPrefix(cs.Apps[j].ArchivePrefix, cs.Apps[i].ArchivePrefix) {
				return fmt.Errorf("config: coolify_sync.apps: overlapping archive_prefix %q (apps[%d]) and %q (apps[%d]) — prefixes must be mutually exclusive so a key routes to exactly one app",
					cs.Apps[i].ArchivePrefix, i, cs.Apps[j].ArchivePrefix, j)
			}
		}
	}
	return nil
}

// validateTargets enforces: path non-empty, no duplicates, no path traversal
// (../) so a misconfigured yaml can't write outside the repo root.
func validateTargets(targets []Target) error {
	seen := make(map[string]int, len(targets))
	for i, t := range targets {
		if t.Path == "" {
			return fmt.Errorf("config: targets[%d]: missing required field 'path'", i)
		}
		if strings.Contains(t.Path, "..") {
			return fmt.Errorf("config: targets[%d]: path %q contains '..' (path traversal not allowed)", i, t.Path)
		}
		if j, dup := seen[t.Path]; dup {
			return fmt.Errorf("config: targets[%d]: duplicate path %q (also at targets[%d])", i, t.Path, j)
		}
		seen[t.Path] = i
	}
	return nil
}
