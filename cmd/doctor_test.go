package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestCoolifyHealthEndpoint covers the URL composition that fixed the
// false-failure: doctor used to GET the operator's COOLIFY_URL verbatim,
// but COOLIFY_URL is the API BASE (matches getEndpoint in cmd/coolify).
// Without appending /health the probe hit the base URL and registered
// 404 → false failure on a healthy Coolify instance.
func TestCoolifyHealthEndpoint(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty → default", "", "https://coolify.meapps.dev/api/v1/health"},
		{"base appends /health", "https://x.test/api/v1", "https://x.test/api/v1/health"},
		{"trailing slash kept clean", "https://x.test/api/v1/", "https://x.test/api/v1/health"},
		{"already /health → kept", "https://x.test/api/v1/health", "https://x.test/api/v1/health"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := coolifyHealthEndpoint(c.in); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDoctorReportsAllChecks(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"doctor"})

	_ = rootCmd.Execute()
	output := buf.String()

	wantChecks := []string{
		"opentofu", "age", "git", "jq", "gh", "cloudflared",
		"R2 access", "Coolify API", "git remote",
	}
	for _, check := range wantChecks {
		if !strings.Contains(output, check) {
			t.Errorf("doctor output missing check %q\nGot:\n%s", check, output)
		}
	}
}
