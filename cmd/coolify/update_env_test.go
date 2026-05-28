package coolify

import (
	"strings"
	"testing"
)

func TestParseEnvKVs_HappyPath(t *testing.T) {
	got, err := parseEnvKVs([]string{"DB=pg", "PORT=8080"})
	if err != nil {
		t.Fatalf("parseEnvKVs: %v", err)
	}
	if got["DB"] != "pg" || got["PORT"] != "8080" {
		t.Errorf("got %v", got)
	}
}

func TestParseEnvKVs_AllowsEqualsInValue(t *testing.T) {
	// SplitN(_, "=", 2) keeps everything after the first = as the value,
	// so JWT-style values with embedded = still work end-to-end.
	got, err := parseEnvKVs([]string{"TOKEN=abc=def=xyz"})
	if err != nil {
		t.Fatalf("parseEnvKVs: %v", err)
	}
	if got["TOKEN"] != "abc=def=xyz" {
		t.Errorf("got TOKEN=%q, want abc=def=xyz", got["TOKEN"])
	}
}

func TestParseEnvKVs_RejectsMissingEquals(t *testing.T) {
	_, err := parseEnvKVs([]string{"NO_EQUALS"})
	if err == nil {
		t.Fatal("expected error for entry with no =")
	}
	if !strings.Contains(err.Error(), "KEY=VAL") {
		t.Errorf("error should show expected format: %v", err)
	}
}

func TestParseEnvKVs_RejectsEmptyKey(t *testing.T) {
	_, err := parseEnvKVs([]string{"=orphan-value"})
	if err == nil {
		t.Fatal("expected error for entry with empty KEY")
	}
}

func TestParseEnvKVs_EmptyValueAllowed(t *testing.T) {
	// `KEY=` with no value is a legitimate "set to empty" — Coolify allows
	// this and `unset KEY` from the shell is the same byte sequence.
	got, err := parseEnvKVs([]string{"EMPTY="})
	if err != nil {
		t.Fatalf("empty value should be allowed: %v", err)
	}
	if v, ok := got["EMPTY"]; !ok || v != "" {
		t.Errorf("EMPTY: got (%q, %v), want ('', true)", v, ok)
	}
}

func TestParseEnvKVs_NoPairsReturnsEmptyMap(t *testing.T) {
	got, err := parseEnvKVs(nil)
	if err != nil {
		t.Fatalf("nil input: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil input should yield empty map, got %v", got)
	}
}
