package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

var doctorFor string

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check all dependencies + access (onboarding preflight)",
	Long: `Verify the local environment can run wapps commands.

Default mode runs the full battery of checks (CLI tools, R2 env, Coolify
API reachability, git remote). Use --for to scope:

  --for tofu     check ONLY the env required by 'wapps secrets sync' against
                 a Tofu project (AWS_*, TF_VAR_state_passphrase, tofu binary).
                 Useful before the first sync in a freshly-bootstrapped repo.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()

		switch doctorFor {
		case "tofu":
			return runDoctorTofu(out)
		case "", "all":
			return runDoctorFull(out)
		default:
			return fmt.Errorf("doctor: unknown --for mode %q (allowed: tofu, all)", doctorFor)
		}
	},
}

// runDoctorTofu validates ONLY the environment required by `wapps secrets sync`
// against a Tofu-source project. Decoupled from the full doctor so operators
// can verify their R2/state passphrase setup before attempting a sync that
// would otherwise fail with a confusing tofu error.
func runDoctorTofu(out interface{ Write(p []byte) (int, error) }) error {
	allOK := true

	// tofu binary itself.
	if _, err := exec.LookPath("tofu"); err != nil {
		fmt.Fprintln(out, "✗ tofu binary not found in PATH")
		allOK = false
	} else {
		fmt.Fprintln(out, "✓ tofu binary present")
	}

	// Required env vars (reused from internal/tofu so sync and doctor agree).
	var missing []tofu.RequiredEnvVar
	for _, r := range tofu.RequiredEnvVars {
		if os.Getenv(r.Name) == "" {
			missing = append(missing, r)
		} else {
			fmt.Fprintf(out, "✓ %s set\n", r.Name)
		}
	}
	for _, r := range missing {
		fmt.Fprintf(out, "✗ %s not set (%s)\n", r.Name, r.Hint)
		allOK = false
	}

	if !allOK {
		fmt.Fprintln(out, "\nRun: wapps secrets sync (will print recovery snippet for missing env)")
		return fmt.Errorf("doctor --for tofu: env not ready")
	}
	fmt.Fprintln(out, "\n✓ Tofu environment ready for sync.")
	return nil
}

// runDoctorFull preserves the original doctor behavior — full dependency
// check covering CLI tools, R2 env, Coolify reachability, git remote.
// Kept verbatim so existing operators see no change.
func runDoctorFull(out interface{ Write(p []byte) (int, error) }) error {
	allOK := true

	// CLI tools
	for _, tool := range []string{"opentofu", "age", "git", "jq", "gh", "cloudflared"} {
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

	// Coolify API reachable. COOLIFY_URL is the BASE url (matches getEndpoint
	// in cmd/coolify/coolify.go), so we append /health here. Earlier this
	// path used COOLIFY_URL verbatim, which made doctor probe the base URL
	// when an operator had set it and report a false failure if the base
	// URL didn't respond with a 2xx to a plain GET.
	client := &http.Client{Timeout: 5 * time.Second}
	coolifyHealthURL := coolifyHealthEndpoint(os.Getenv("COOLIFY_URL"))
	req, reqErr := http.NewRequest("GET", coolifyHealthURL, nil)
	if reqErr != nil {
		fmt.Fprintf(out, "✗ Coolify API URL invalid: %v\n", reqErr)
		allOK = false
	} else {
		req.Header.Set("User-Agent", "curl/8")
		resp, err := client.Do(req)
		switch {
		case err != nil:
			fmt.Fprintf(out, "✗ Coolify API unreachable: %v\n", err)
			allOK = false
		case resp.StatusCode >= 500:
			resp.Body.Close()
			fmt.Fprintf(out, "✗ Coolify API server error (HTTP %d)\n", resp.StatusCode)
			allOK = false
		default:
			resp.Body.Close()
			fmt.Fprintln(out, "✓ Coolify API reachable")
		}
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
}

// coolifyHealthEndpoint derives the /health URL from the operator's base
// COOLIFY_URL. If the operator didn't set anything we fall back to the
// hard-coded default. Otherwise we append /health to whatever they gave us
// — accommodating the COOLIFY_URL convention shared with cmd/coolify which
// stores the base ("https://coolify.example.com/api/v1") rather than a
// concrete endpoint.
func coolifyHealthEndpoint(base string) string {
	if base == "" {
		return "https://coolify.meapps.dev/api/v1/health"
	}
	if strings.HasSuffix(base, "/health") {
		return base
	}
	if strings.HasSuffix(base, "/") {
		return base + "health"
	}
	return base + "/health"
}

func init() {
	doctorCmd.Flags().StringVar(&doctorFor, "for", "",
		"scope the check: 'tofu' validates only the env needed by 'wapps secrets sync'; empty/'all' runs the full check")
	rootCmd.AddCommand(doctorCmd)
}
