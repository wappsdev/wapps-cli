package secrets

import (
	"bytes"
	"strings"
	"testing"
)

// Bug 1 regression: writeTofuOutputsAsEnv used to force all values to string
// at unmarshal time, crashing on non-string Tofu outputs like
// vaulter_traefik_cert_paths (a []string). After the fix, any JSON type
// round-trips via TF_VAR_<name>='<json>'.
func TestWriteTofuOutputsAsEnv_HandlesMixedValueTypes(t *testing.T) {
	input := []byte(`{
		"pg_password": {"value": "s3cr3t"},
		"vaulter_traefik_cert_paths": {"value": ["a.crt", "b.crt"]},
		"meta": {"value": {"version": 2, "ready": true}},
		"replicas": {"value": 3},
		"enabled": {"value": true},
		"optional": {"value": null}
	}`)

	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(input, &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv: unexpected error: %v", err)
	}

	got := buf.String()
	// String: emit unquoted value
	if !strings.Contains(got, "export TF_VAR_pg_password='s3cr3t'\n") {
		t.Errorf("string output missing or wrong:\n%s", got)
	}
	// List: emit JSON-string (the bug 1 regression case)
	if !strings.Contains(got, `export TF_VAR_vaulter_traefik_cert_paths='["a.crt","b.crt"]'`) {
		t.Errorf("list output (Bug 1 regression) missing or wrong:\n%s", got)
	}
	// Map: emit JSON-string
	if !strings.Contains(got, `export TF_VAR_meta='{"version":2,"ready":true}'`) {
		t.Errorf("map output missing or wrong:\n%s", got)
	}
	// Number: emit JSON-string
	if !strings.Contains(got, "export TF_VAR_replicas='3'\n") {
		t.Errorf("number output missing or wrong:\n%s", got)
	}
	// Bool: emit JSON-string
	if !strings.Contains(got, "export TF_VAR_enabled='true'\n") {
		t.Errorf("bool output missing or wrong:\n%s", got)
	}
	// Null: emit JSON-string
	if !strings.Contains(got, "export TF_VAR_optional='null'\n") {
		t.Errorf("null output missing or wrong:\n%s", got)
	}
}

func TestWriteTofuOutputsAsEnv_EscapesSingleQuotes(t *testing.T) {
	input := []byte(`{
		"tricky": {"value": "it's a 'value'"}
	}`)

	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(input, &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv: %v", err)
	}

	// Single quotes inside the value must be escaped as '\'' (close-escape-open).
	want := `export TF_VAR_tricky='it'\''s a '\''value'\'''` + "\n"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("single-quote escape wrong.\nwant substring: %q\ngot: %q", want, buf.String())
	}
}

func TestWriteTofuOutputsAsEnv_DeterministicOrder(t *testing.T) {
	input := []byte(`{
		"zebra": {"value": "z"},
		"alpha": {"value": "a"},
		"mango": {"value": "m"}
	}`)

	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(input, &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv: %v", err)
	}

	got := buf.String()
	alphaIdx := strings.Index(got, "TF_VAR_alpha")
	mangoIdx := strings.Index(got, "TF_VAR_mango")
	zebraIdx := strings.Index(got, "TF_VAR_zebra")

	if alphaIdx == -1 || mangoIdx == -1 || zebraIdx == -1 {
		t.Fatalf("expected all keys in output, got:\n%s", got)
	}
	if !(alphaIdx < mangoIdx && mangoIdx < zebraIdx) {
		t.Errorf("expected alphabetical order, got:\n%s", got)
	}
}

func TestWriteTofuOutputsAsEnv_EmptyInput(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv([]byte(`{}`), &buf); err != nil {
		t.Fatalf("writeTofuOutputsAsEnv on empty: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output on empty input, got: %q", buf.String())
	}
}

func TestWriteTofuOutputsAsEnv_MalformedJSON(t *testing.T) {
	var buf bytes.Buffer
	err := writeTofuOutputsAsEnv([]byte(`not json`), &buf)
	if err == nil {
		t.Fatal("expected error on malformed JSON input, got nil")
	}
	if !strings.Contains(err.Error(), "parse tofu output") {
		t.Errorf("expected error to mention 'parse tofu output', got: %v", err)
	}
}
