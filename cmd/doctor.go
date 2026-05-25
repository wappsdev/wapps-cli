package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check all dependencies + access (onboarding preflight)",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		allOK := true

		// CLI tools
		for _, tool := range []string{"opentofu", "age", "git", "jq", "gh"} {
			binName := tool
			if tool == "opentofu" {
				binName = "tofu"
			}
			if _, err := exec.LookPath(binName); err != nil {
				fmt.Fprintf(out, "✗ %s not found in PATH\n", tool)
				allOK = false
			} else {
				fmt.Fprintf(out, "✓ %s present\n", tool)
			}
		}

		// R2 access — env vars set?
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			fmt.Fprintln(out, "✗ R2 access: AWS_ACCESS_KEY_ID not set")
			allOK = false
		} else {
			fmt.Fprintln(out, "✓ R2 access env vars set")
		}

		// Coolify API reachable
		client := &http.Client{Timeout: 5 * time.Second}
		coolifyURL := os.Getenv("COOLIFY_URL")
		if coolifyURL == "" {
			coolifyURL = "https://coolify.meapps.dev/api/v1/health"
		}
		req, _ := http.NewRequest("GET", coolifyURL, nil)
		req.Header.Set("User-Agent", "curl/8")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode >= 500 {
			fmt.Fprintf(out, "✗ Coolify API unreachable: %v\n", err)
			allOK = false
		} else {
			fmt.Fprintln(out, "✓ Coolify API reachable")
			resp.Body.Close()
		}

		// Git remote
		gitOut, err := exec.Command("git", "remote", "-v").Output()
		if err != nil || !strings.Contains(string(gitOut), "wappsdev/infra-tofu") {
			fmt.Fprintln(out, "✗ git remote: not in infra-tofu repo or missing origin")
			allOK = false
		} else {
			fmt.Fprintln(out, "✓ git remote configured")
		}

		if !allOK {
			return fmt.Errorf("doctor reported failures")
		}
		fmt.Fprintln(out, "\nAll checks passed.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
