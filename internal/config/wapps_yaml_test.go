package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- config-dir-relative path resolution (secrets-from-anywhere) ---

func TestLoad_RecordsConfigRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".wapps.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nsources:\n  - type: file\n    path: .env.shared\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	absDir, _ := filepath.Abs(dir)
	if cfg.ConfigRoot() != absDir {
		t.Errorf("ConfigRoot = %q, want %q", cfg.ConfigRoot(), absDir)
	}
}

func TestParse_NoConfigRoot(t *testing.T) {
	cfg, err := Parse([]byte("version: 1\nsources:\n  - type: tofu\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ConfigRoot() != "" {
		t.Errorf("Parse-built config should have empty ConfigRoot, got %q", cfg.ConfigRoot())
	}
	// With empty configRoot, ResolveDest returns the raw relative dest (no Join).
	if got := cfg.ResolveDest(); got != "secrets/all.enc.age" {
		t.Errorf("ResolveDest with empty configRoot = %q, want raw default", got)
	}
}

func TestResolveDest_RelativeJoined(t *testing.T) {
	cfg, _ := Parse([]byte("version: 1\ndest: secrets/all.enc.age\nsources:\n  - type: tofu\n"))
	cfg.configRoot = "/p/vaulter"
	if got := cfg.ResolveDest(); got != "/p/vaulter/secrets/all.enc.age" {
		t.Errorf("ResolveDest = %q, want joined", got)
	}
}

func TestResolveDest_AbsoluteUnchanged(t *testing.T) {
	cfg, _ := Parse([]byte("version: 1\ndest: /abs/secrets/all.enc.age\nsources:\n  - type: tofu\n"))
	cfg.configRoot = "/p/vaulter"
	if got := cfg.ResolveDest(); got != "/abs/secrets/all.enc.age" {
		t.Errorf("absolute dest must pass through unchanged, got %q", got)
	}
}

func TestResolveTargetPath(t *testing.T) {
	rel := Target{Path: ".env.local"}
	if got := rel.ResolvePath("/p/vaulter"); got != "/p/vaulter/.env.local" {
		t.Errorf("relative target = %q, want joined", got)
	}
	abs := Target{Path: "/etc/app/.env"}
	if got := abs.ResolvePath("/p/vaulter"); got != "/etc/app/.env" {
		t.Errorf("absolute target must pass through, got %q", got)
	}
	// Empty configRoot → unchanged (parse-only / legacy cwd path).
	if got := rel.ResolvePath(""); got != ".env.local" {
		t.Errorf("empty configRoot must leave path raw, got %q", got)
	}
}

func TestResolvedSources_JoinsPathAndWorkdir(t *testing.T) {
	cfg, _ := Parse([]byte("version: 1\nsources:\n  - type: tofu\n    workdir: .\n  - type: file\n    path: .env.shared\n"))
	cfg.configRoot = "/p/vaulter"
	got := cfg.ResolvedSources()
	if got[0].Workdir != "/p/vaulter" {
		t.Errorf("tofu workdir = %q, want joined (filepath.Join('/p/vaulter','.'))", got[0].Workdir)
	}
	if got[1].Path != "/p/vaulter/.env.shared" {
		t.Errorf("file source path = %q, want joined", got[1].Path)
	}
	// Original cfg.Sources must be untouched (ResolvedSources returns a copy).
	if cfg.Sources[1].Path != ".env.shared" {
		t.Errorf("ResolvedSources mutated the original Sources: %q", cfg.Sources[1].Path)
	}
}

func TestResolvedSources_AbsoluteUnchanged(t *testing.T) {
	cfg, _ := Parse([]byte("version: 1\nsources:\n  - type: file\n    path: /abs/.env\n"))
	cfg.configRoot = "/p"
	if got := cfg.ResolvedSources(); got[0].Path != "/abs/.env" {
		t.Errorf("absolute source path must pass through, got %q", got[0].Path)
	}
}

// A tofu source with an omitted workdir must resolve to configRoot, not stay
// empty (which would make tofu run in cwd). Regression for the review finding.
func TestResolvedSources_OmittedTofuWorkdirDefaultsToConfigRoot(t *testing.T) {
	cfg, _ := Parse([]byte("version: 1\nsources:\n  - type: tofu\n"))
	cfg.configRoot = "/p/vaulter"
	got := cfg.ResolvedSources()
	if got[0].Workdir != "/p/vaulter" {
		t.Errorf("omitted tofu workdir should default to configRoot, got %q", got[0].Workdir)
	}
}

// A file source must NOT gain a workdir (it rejects one) — empty stays empty.
func TestResolvedSources_FileSourceWorkdirStaysEmpty(t *testing.T) {
	cfg, _ := Parse([]byte("version: 1\nsources:\n  - type: file\n    path: .env.shared\n"))
	cfg.configRoot = "/p/vaulter"
	got := cfg.ResolvedSources()
	if got[0].Workdir != "" {
		t.Errorf("file source workdir must stay empty (file rejects workdir), got %q", got[0].Workdir)
	}
}

func TestParse_VaulterExample(t *testing.T) {
	// Matches the design-doc example for infra-tofu/projects/vaulter.
	data := []byte(`
version: 1
dest: secrets/all.enc.age
sources:
  - type: tofu
    workdir: .
    prefix: "TF_VAR_"
  - type: file
    path: .env.shared
    prefix: ""
redact_in_logs: true
require_clean_git: true
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version: %d", got.Version)
	}
	if got.Dest != "secrets/all.enc.age" {
		t.Errorf("Dest: %q", got.Dest)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(got.Sources))
	}
	if got.Sources[0].Type != "tofu" || got.Sources[0].Prefix != "TF_VAR_" {
		t.Errorf("source[0]: %+v", got.Sources[0])
	}
	if got.Sources[1].Type != "file" || got.Sources[1].Path != ".env.shared" {
		t.Errorf("source[1]: %+v", got.Sources[1])
	}
	if !got.RedactInLogs {
		t.Errorf("RedactInLogs should be true")
	}
	if !got.RequireCleanGit {
		t.Errorf("RequireCleanGit should be true")
	}
}

func TestParse_VaulterApiExample(t *testing.T) {
	// File-only source (non-Tofu repo).
	data := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Dest != "secrets/all.enc.age" {
		t.Errorf("Dest should default to secrets/all.enc.age, got %q", got.Dest)
	}
	if len(got.Sources) != 1 || got.Sources[0].Type != "file" {
		t.Errorf("sources: %+v", got.Sources)
	}
}

func TestParse_VersionDefaultsTo1(t *testing.T) {
	data := []byte(`
sources:
  - type: tofu
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version should default to 1, got %d", got.Version)
	}
}

func TestParse_RejectsUnsupportedVersion(t *testing.T) {
	data := []byte(`
version: 2
sources:
  - type: tofu
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for version 2")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error should mention version: %v", err)
	}
}

func TestParse_RejectsEmptySources(t *testing.T) {
	data := []byte(`
version: 1
sources: []
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for empty sources")
	}
	if !strings.Contains(err.Error(), "at least one source") {
		t.Errorf("error should explain requirement, got: %v", err)
	}
}

func TestParse_RejectsUnknownSourceType(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: doppler
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for unknown source type")
	}
	if !strings.Contains(err.Error(), "sources[0]") {
		t.Errorf("error should pinpoint source index, got: %v", err)
	}
	if !strings.Contains(err.Error(), "doppler") {
		t.Errorf("error should quote the bad type, got: %v", err)
	}
}

func TestParse_RejectsTofuWithPathField(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
    path: .env.shared
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: tofu source should reject 'path'")
	}
}

func TestParse_RejectsFileWithoutPath(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: file
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error: file source requires 'path'")
	}
}

func TestParse_MalformedYAML(t *testing.T) {
	_, err := Parse([]byte("not: valid: yaml: here"))
	if err == nil {
		t.Fatal("expected parse error on malformed YAML")
	}
	if !strings.Contains(err.Error(), "parse yaml") {
		t.Errorf("error should mention yaml parse failure, got: %v", err)
	}
}

func TestParse_DefaultPrefix(t *testing.T) {
	data := []byte(`
version: 1
default_prefix: ""
sources:
  - type: file
    path: .env.shared
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.DefaultPrefix != "" {
		t.Errorf("DefaultPrefix: %q", got.DefaultPrefix)
	}
}

func TestParse_TargetsBasic(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
targets:
  - path: .env.local
  - path: terraform.tfvars.json
    prefix: "TF_VAR_"
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(got.Targets))
	}
	if got.Targets[0].Path != ".env.local" {
		t.Errorf("targets[0].Path: %q", got.Targets[0].Path)
	}
	if got.Targets[0].Prefix != nil {
		t.Errorf("targets[0].Prefix should be nil (unset), got %v", got.Targets[0].Prefix)
	}
	if got.Targets[1].Prefix == nil || *got.Targets[1].Prefix != "TF_VAR_" {
		t.Errorf("targets[1].Prefix: %v", got.Targets[1].Prefix)
	}
}

func TestTarget_EffectivePrefix(t *testing.T) {
	empty := ""
	tfvar := "TF_VAR_"
	cases := []struct {
		name          string
		target        Target
		defaultPrefix string
		want          string
	}{
		{"unset uses default", Target{Path: "x"}, "TF_VAR_", "TF_VAR_"},
		{"explicit empty wins over non-empty default", Target{Path: "x", Prefix: &empty}, "TF_VAR_", ""},
		{"explicit value wins over default", Target{Path: "x", Prefix: &tfvar}, "", "TF_VAR_"},
		{"unset + empty default = empty", Target{Path: "x"}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.target.EffectivePrefix(c.defaultPrefix); got != c.want {
				t.Errorf("EffectivePrefix: got %q want %q", got, c.want)
			}
		})
	}
}

func TestParse_RejectsTargetWithoutPath(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
targets:
  - prefix: "TF_VAR_"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for target missing path")
	}
	if !strings.Contains(err.Error(), "targets[0]") {
		t.Errorf("error should pinpoint target index, got: %v", err)
	}
}

func TestParse_RejectsDuplicateTargetPath(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
targets:
  - path: .env.local
  - path: .env.local
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for duplicate target path")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention duplicate, got: %v", err)
	}
}

func TestParse_RejectsTargetPathTraversal(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
targets:
  - path: ../etc/passwd
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "traversal") {
		t.Errorf("error should mention traversal, got: %v", err)
	}
}

func TestParse_EmptyTargetsIsOK(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: file
    path: .env.shared
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Targets) != 0 {
		t.Errorf("expected no targets, got %d", len(got.Targets))
	}
}

func TestParse_CoolifySync_Basic(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  delete_unmanaged: false
  apps:
    - uuid: vaesbm45up4jyk7hhk77ka74
      name: kreeva-web
      archive_prefix: "KREEVA_WEB_"
    - uuid: wpv0glv7usj90t268ntfggby
      name: labellens-api
      archive_prefix: "LABELLENS_API_"
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.CoolifySync == nil {
		t.Fatal("CoolifySync should be parsed")
	}
	if got.CoolifySync.DeleteUnmanaged {
		t.Error("delete_unmanaged should be false")
	}
	if len(got.CoolifySync.Apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(got.CoolifySync.Apps))
	}
	if got.CoolifySync.Apps[0].ArchivePrefix != "KREEVA_WEB_" {
		t.Errorf("apps[0].ArchivePrefix: %q", got.CoolifySync.Apps[0].ArchivePrefix)
	}
}

func TestParse_CoolifySync_AbsentIsNil(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.CoolifySync != nil {
		t.Errorf("CoolifySync should be nil when absent, got %+v", got.CoolifySync)
	}
}

func TestParse_CoolifySync_RejectsMissingUUID(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  apps:
    - archive_prefix: "FOO_"
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "uuid") {
		t.Errorf("expected uuid error, got: %v", err)
	}
}

func TestParse_CoolifySync_RejectsMissingPrefix(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  apps:
    - uuid: app-1
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "archive_prefix") {
		t.Errorf("expected archive_prefix error, got: %v", err)
	}
}

func TestParse_CoolifySync_RejectsDuplicateUUID(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  apps:
    - uuid: app-1
      archive_prefix: "A_"
    - uuid: app-1
      archive_prefix: "B_"
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "duplicate uuid") {
		t.Errorf("expected duplicate uuid error, got: %v", err)
	}
}

func TestParse_CoolifySync_RejectsOverlappingPrefix(t *testing.T) {
	// "ROYCO_" is a prefix of "ROYCO_API_" → ambiguous routing, must error.
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  apps:
    - uuid: app-royco
      archive_prefix: "ROYCO_"
    - uuid: app-royco-api
      archive_prefix: "ROYCO_API_"
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "overlapping") {
		t.Errorf("expected overlapping prefix error, got: %v", err)
	}
}

func TestParse_CoolifySync_OverlapErrorRegardlessOfOrder(t *testing.T) {
	// Same overlap but declared in the opposite order — must still error.
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  apps:
    - uuid: app-royco-api
      archive_prefix: "ROYCO_API_"
    - uuid: app-royco
      archive_prefix: "ROYCO_"
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "overlapping") {
		t.Errorf("expected overlapping prefix error regardless of order, got: %v", err)
	}
}

func TestParse_CoolifySync_NonOverlappingOK(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
coolify_sync:
  apps:
    - uuid: app-royco
      archive_prefix: "ROYCO_"
    - uuid: app-kreeva
      archive_prefix: "KREEVA_"
`)
	if _, err := Parse(data); err != nil {
		t.Errorf("non-overlapping prefixes should be valid, got: %v", err)
	}
}

func TestParse_MultiTofuMultiFile(t *testing.T) {
	data := []byte(`
version: 1
sources:
  - type: tofu
    workdir: ./projects/vaulter
  - type: tofu
    workdir: ./projects/platform
  - type: file
    path: .env.shared
  - type: file
    path: .env.build
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Sources) != 4 {
		t.Errorf("expected 4 sources, got %d", len(got.Sources))
	}
}
