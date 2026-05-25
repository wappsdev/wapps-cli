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

		envs := make(map[string]string)
		for _, kv := range ueEnvKVs {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid env (need KEY=VAL): %q", kv)
			}
			envs[parts[0]] = parts[1]
		}

		c := coolify.New(getEndpoint(), token)
		if err := c.UpdateAppEnvs(ueAppUUID, envs); err != nil {
			return err
		}
		fmt.Printf("✓ Updated %d env vars on %s\n", len(envs), ueAppUUID)
		return nil
	},
}

func init() {
	updateEnvCmd.Flags().StringVar(&ueAppUUID, "app-uuid", "", "Coolify app UUID")
	updateEnvCmd.Flags().StringSliceVar(&ueEnvKVs, "env", []string{}, "KEY=VAL (repeatable)")
	_ = updateEnvCmd.MarkFlagRequired("app-uuid")
	CoolifyCmd.AddCommand(updateEnvCmd)
}
