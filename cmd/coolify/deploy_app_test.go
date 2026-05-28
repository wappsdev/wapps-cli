package coolify

import (
	"strings"
	"testing"
)

func TestCollectEnvFromShell_HappyPath(t *testing.T) {
	lookup := func(k string) string {
		switch k {
		case "DB_URL":
			return "postgres://x"
		case "STRIPE_KEY":
			return "sk_test"
		}
		return ""
	}
	got, err := collectEnvFromShell([]string{"DB_URL", "STRIPE_KEY"}, lookup)
	if err != nil {
		t.Fatalf("collectEnvFromShell: %v", err)
	}
	if got["DB_URL"] != "postgres://x" || got["STRIPE_KEY"] != "sk_test" {
		t.Errorf("got %v", got)
	}
}

// TestCollectEnvFromShell_FailsOnMissingKey is the key behavior the helper
// exists for: an operator who lists --env-from-shell FOO but forgot to
// export FOO before invoking deploy-app must get a refusal, not a silently
// missing env on the deployed app.
func TestCollectEnvFromShell_FailsOnMissingKey(t *testing.T) {
	lookup := func(k string) string { return "" }
	_, err := collectEnvFromShell([]string{"REQUIRED"}, lookup)
	if err == nil {
		t.Fatal("expected error for missing env")
	}
	if !strings.Contains(err.Error(), "REQUIRED") {
		t.Errorf("error should name the missing key, got: %v", err)
	}
}

func TestCollectEnvFromShell_EmptyKeysReturnsEmptyMap(t *testing.T) {
	got, err := collectEnvFromShell(nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("nil input: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil input should yield empty map, got %v", got)
	}
}
