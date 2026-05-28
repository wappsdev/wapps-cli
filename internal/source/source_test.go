package source

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestNew_DispatchesByType(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		wantType string
		wantErr  bool
	}{
		{"tofu happy", Config{Type: "tofu", Workdir: "."}, "tofu", false},
		{"tofu cwd default", Config{Type: "tofu"}, "tofu", false},
		{"file happy", Config{Type: "file", Path: ".env.shared"}, "file", false},
		{"unknown type", Config{Type: "doppler"}, "", true},
		{"missing type", Config{}, "", true},
		{"file missing path", Config{Type: "file"}, "", true},
		{"file with workdir", Config{Type: "file", Path: ".env", Workdir: "."}, "", true},
		{"tofu with path", Config{Type: "tofu", Path: ".env"}, "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := New(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %+v, got src=%v", tc.cfg, src)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if src.Type() != tc.wantType {
				t.Errorf("Type(): want %q, got %q", tc.wantType, src.Type())
			}
		})
	}
}

func TestNew_UnknownTypeErrorNamesAllowedTypes(t *testing.T) {
	_, err := New(Config{Type: "vault"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	// Operator-facing error should help them recover, not just say "no".
	if !strings.Contains(err.Error(), "tofu") || !strings.Contains(err.Error(), "file") {
		t.Errorf("error should list allowed types, got: %v", err)
	}
}

func TestMerge_EmptyInput(t *testing.T) {
	merged, overridden := Merge(nil)
	if len(merged) != 0 {
		t.Errorf("expected empty map, got %v", merged)
	}
	if len(overridden) != 0 {
		t.Errorf("expected no overrides, got %v", overridden)
	}
}

func TestMerge_NonOverlappingSources(t *testing.T) {
	a := map[string]json.RawMessage{
		"JWT_KEY": json.RawMessage(`{"value":"a"}`),
	}
	b := map[string]json.RawMessage{
		"DB_PASSWORD": json.RawMessage(`{"value":"b"}`),
	}
	merged, overridden := Merge([]map[string]json.RawMessage{a, b})
	if len(merged) != 2 {
		t.Errorf("expected 2 keys, got %d: %v", len(merged), merged)
	}
	if len(overridden) != 0 {
		t.Errorf("expected no overrides for disjoint inputs, got %v", overridden)
	}
}

// Later sources override earlier ones (last-write-wins) AND the override is
// recorded so the caller can warn the operator. A silent override of a
// Tofu-managed secret by a manually-edited file is almost always a bug.
func TestMerge_TracksOverrides(t *testing.T) {
	tofu := map[string]json.RawMessage{
		"SHARED_KEY": json.RawMessage(`{"value":"from-tofu"}`),
	}
	file := map[string]json.RawMessage{
		"SHARED_KEY": json.RawMessage(`{"value":"from-file"}`),
	}
	merged, overridden := Merge([]map[string]json.RawMessage{tofu, file})

	if got := string(merged["SHARED_KEY"]); !strings.Contains(got, "from-file") {
		t.Errorf("later source should win, got: %s", got)
	}
	if len(overridden) != 1 || overridden[0] != "SHARED_KEY" {
		t.Errorf("expected SHARED_KEY in overridden, got: %v", overridden)
	}
}

// Stub source for end-to-end Merge tests + future sync-level tests.
type stubSource struct {
	name string
	t    string
	data map[string]json.RawMessage
	err  error
}

func (s *stubSource) Name() string { return s.name }
func (s *stubSource) Type() string { return s.t }
func (s *stubSource) Read(ctx context.Context) (map[string]json.RawMessage, error) {
	return s.data, s.err
}
