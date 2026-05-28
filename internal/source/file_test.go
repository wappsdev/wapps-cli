package source

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFileSource_ParsesBasicEnvFile(t *testing.T) {
	data := []byte("STRIPE_KEY=sk_test_123\nDB_PASSWORD=hunter2\n")
	got, err := parseEnvFile(".env.shared", data)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 keys, got %d: %v", len(got), got)
	}
	// Values are wrapped in tofu-output-shaped envelope.
	if string(got["STRIPE_KEY"]) != `{"value":"sk_test_123"}` {
		t.Errorf("STRIPE_KEY envelope wrong: %s", got["STRIPE_KEY"])
	}
	if string(got["DB_PASSWORD"]) != `{"value":"hunter2"}` {
		t.Errorf("DB_PASSWORD envelope wrong: %s", got["DB_PASSWORD"])
	}
}

func TestFileSource_SkipsCommentsAndBlankLines(t *testing.T) {
	data := []byte(`
# This is a comment
KEY1=value1

# Another comment
KEY2=value2
`)
	got, err := parseEnvFile(".env", data)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 keys (comments/blanks skipped), got %d: %v", len(got), got)
	}
}

func TestFileSource_StripsExportPrefix(t *testing.T) {
	data := []byte("export FOO=bar\nBAZ=qux\n")
	got, err := parseEnvFile(".env", data)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	if _, ok := got["FOO"]; !ok {
		t.Errorf("FOO missing (export prefix should be stripped): %v", got)
	}
	if string(got["FOO"]) != `{"value":"bar"}` {
		t.Errorf("FOO value wrong: %s", got["FOO"])
	}
}

func TestFileSource_StripsMatchingQuotes(t *testing.T) {
	data := []byte(`SINGLE='inside single'
DOUBLE="inside double"
MIXED="quote' apostrophe"
NONE=no quotes here
`)
	got, err := parseEnvFile(".env", data)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	if string(got["SINGLE"]) != `{"value":"inside single"}` {
		t.Errorf("SINGLE: %s", got["SINGLE"])
	}
	if string(got["DOUBLE"]) != `{"value":"inside double"}` {
		t.Errorf("DOUBLE: %s", got["DOUBLE"])
	}
	if string(got["MIXED"]) != `{"value":"quote' apostrophe"}` {
		t.Errorf("MIXED: %s", got["MIXED"])
	}
	if string(got["NONE"]) != `{"value":"no quotes here"}` {
		t.Errorf("NONE: %s", got["NONE"])
	}
}

func TestFileSource_RejectsMalformedLine(t *testing.T) {
	data := []byte("VALID=ok\nMALFORMED_NO_EQUAL\nANOTHER=fine\n")
	_, err := parseEnvFile(".env", data)
	if err == nil {
		t.Fatal("expected error on missing '=' delimiter")
	}
	msg := err.Error()
	if !strings.Contains(msg, "line 2") {
		t.Errorf("error should name line number, got: %v", err)
	}
	// We deliberately do NOT echo the line content — if a user pasted a
	// raw secret with no KEY= prefix, the line IS the value. We report the
	// length instead so the operator can pinpoint without leaking.
	if !strings.Contains(msg, "line length") {
		t.Errorf("error should report line length, got: %v", err)
	}
}

// TestFileSource_MalformedLineErrorDoesNotEchoSecretValue is the explicit
// safety regression: if a token-shaped value is on a malformed line, the
// error message must NOT contain it.
func TestFileSource_MalformedLineErrorDoesNotEchoSecretValue(t *testing.T) {
	secret := "sk_live_supersecret_token_pasted_by_mistake"
	data := []byte("VALID=ok\n" + secret + "\n")
	_, err := parseEnvFile(".env", data)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("malformed-line error leaked secret value: %v", err)
	}
}

func TestFileSource_RejectsEmptyKey(t *testing.T) {
	data := []byte("=value-without-key\n")
	_, err := parseEnvFile(".env", data)
	if err == nil {
		t.Fatal("expected error on empty key")
	}
}

func TestFileSource_AllowsEmptyValue(t *testing.T) {
	data := []byte("OPTIONAL_FLAG=\n")
	got, err := parseEnvFile(".env", data)
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	if string(got["OPTIONAL_FLAG"]) != `{"value":""}` {
		t.Errorf("empty value not handled: %s", got["OPTIONAL_FLAG"])
	}
}

func TestFileSource_Read_FileMissing(t *testing.T) {
	src := &fileSource{
		path: "/nope/missing.env",
		readFile: func(p string) ([]byte, error) {
			return nil, errors.New("open: no such file or directory")
		},
	}
	_, err := src.Read(context.Background())
	if err == nil {
		t.Fatal("expected error when file missing")
	}
	// Error should name the source so multi-source diagnostics are unambiguous.
	if !strings.Contains(err.Error(), "/nope/missing.env") {
		t.Errorf("error should include file path, got: %v", err)
	}
}

func TestFileSource_NameAndType(t *testing.T) {
	src := &fileSource{path: ".env.shared"}
	if src.Name() != "file (.env.shared)" {
		t.Errorf("Name(): %q", src.Name())
	}
	if src.Type() != "file" {
		t.Errorf("Type(): %q", src.Type())
	}
}

func TestNewFileSource_RejectsWorkdirField(t *testing.T) {
	_, err := newFileSource(Config{Type: "file", Path: ".env", Workdir: "/"})
	if err == nil {
		t.Fatal("file source should reject 'workdir' (tofu-only field)")
	}
}

func TestNewFileSource_RequiresPath(t *testing.T) {
	_, err := newFileSource(Config{Type: "file"})
	if err == nil {
		t.Fatal("file source should require 'path'")
	}
}
