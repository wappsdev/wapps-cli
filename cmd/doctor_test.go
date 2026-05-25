package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctorReportsAllChecks(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"doctor"})

	_ = rootCmd.Execute()
	output := buf.String()

	wantChecks := []string{
		"opentofu", "age", "git", "jq", "gh",
		"R2 access", "Coolify API", "git remote",
	}
	for _, check := range wantChecks {
		if !strings.Contains(output, check) {
			t.Errorf("doctor output missing check %q\nGot:\n%s", check, output)
		}
	}
}
