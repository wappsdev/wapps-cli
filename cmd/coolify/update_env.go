package coolify

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/coolify"
)

var (
	ueAppUUID string
	ueEnvKVs  []string
)

var updateEnvCmd = &cobra.Command{
	Use:   "update-env",
	Short: "Update application env vars (--env KEY=VAL, repeatable)",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := os.Getenv("COOLIFY_API_TOKEN")
		if token == "" {
			return fmt.Errorf("COOLIFY_API_TOKEN not set")
		}

		envs, err := parseEnvKVs(ueEnvKVs)
		if err != nil {
			return err
		}

		c := coolify.New(getEndpoint(), token)
		if err := c.UpdateAppEnvs(ueAppUUID, envs); err != nil {
			return err
		}
		fmt.Printf("✓ Updated %d env vars on %s\n", len(envs), ueAppUUID)
		return nil
	},
}

// parseEnvKVs splits the --env KEY=VAL repeats into a map. Extracted so
// the parsing logic (the only testable piece of update-env without a real
// Coolify API) can be unit-tested separately from the API call.
//
// Rejects entries with no '=' so a typo'd `--env DB_PASSWORD` doesn't get
// silently dropped and ship to Coolify as zero updates.
func parseEnvKVs(pairs []string) (map[string]string, error) {
	out := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env (need KEY=VAL): %q", kv)
		}
		if parts[0] == "" {
			return nil, fmt.Errorf("invalid env (empty KEY): %q", kv)
		}
		out[parts[0]] = parts[1]
	}
	return out, nil
}

func init() {
	updateEnvCmd.Flags().StringVar(&ueAppUUID, "app-uuid", "", "Coolify app UUID")
	updateEnvCmd.Flags().StringSliceVar(&ueEnvKVs, "env", []string{}, "KEY=VAL (repeatable)")
	_ = updateEnvCmd.MarkFlagRequired("app-uuid")
	CoolifyCmd.AddCommand(updateEnvCmd)
}
