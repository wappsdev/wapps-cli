package config

import (
	"strings"
	"testing"
)

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
