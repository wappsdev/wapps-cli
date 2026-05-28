package source

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestTofuSource_Read_HappyPath(t *testing.T) {
	stub := []byte(`{
		"jwt_key": {"value": "secret", "type": "string", "sensitive": true},
		"replicas": {"value": 3, "type": "number"}
	}`)
	src := &tofuSource{
		workdir: "/some/dir",
		runner: func(ctx context.Context, workdir string) ([]byte, error) {
			if workdir != "/some/dir" {
				t.Errorf("runner called with wrong workdir: %q", workdir)
			}
			return stub, nil
		},
	}

	out, err := src.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 keys, got %d", len(out))
	}
	if got := string(out["jwt_key"]); !strings.Contains(got, "secret") {
		t.Errorf("jwt_key envelope missing value, got: %s", got)
	}
}

func TestTofuSource_Name_ReflectsWorkdir(t *testing.T) {
	cases := []struct {
		workdir string
		want    string
	}{
		{"", "tofu (cwd)"},
		{".", "tofu (workdir=.)"},
		{"/abs/path", "tofu (workdir=/abs/path)"},
	}
	for _, tc := range cases {
		src := &tofuSource{workdir: tc.workdir}
		if got := src.Name(); got != tc.want {
			t.Errorf("workdir=%q: Name() = %q, want %q", tc.workdir, got, tc.want)
		}
	}
}

func TestTofuSource_Type(t *testing.T) {
	src := &tofuSource{}
	if src.Type() != "tofu" {
		t.Errorf("Type() = %q, want tofu", src.Type())
	}
}

func TestTofuSource_Read_RunnerError(t *testing.T) {
	wantErr := errors.New("tofu binary missing")
	src := &tofuSource{
		runner: func(ctx context.Context, workdir string) ([]byte, error) {
			return nil, wantErr
		},
	}
	_, err := src.Read(context.Background())
	if err == nil {
		t.Fatal("expected error when runner fails")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error chain should include runner error, got: %v", err)
	}
}

func TestTofuSource_Read_MalformedJSON(t *testing.T) {
	src := &tofuSource{
		runner: func(ctx context.Context, workdir string) ([]byte, error) {
			return []byte(`not json`), nil
		},
	}
	_, err := src.Read(context.Background())
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse tofu output") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestNewTofuSource_RejectsPathField(t *testing.T) {
	_, err := newTofuSource(Config{Type: "tofu", Path: "/etc/env"})
	if err == nil {
		t.Fatal("tofu source should reject 'path' field (file-source-only)")
	}
}
