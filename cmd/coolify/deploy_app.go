package coolify

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/coolify"
)

var (
	depProjectUUID  string
	depServerUUID   string
	depName         string
	depComposeFile  string
	depEnvFromShell []string
)

var deployAppCmd = &cobra.Command{
	Use:   "deploy-app",
	Short: "Create a dockercompose application via Coolify API (and start it)",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := os.Getenv("COOLIFY_API_TOKEN")
		if token == "" {
			return fmt.Errorf("COOLIFY_API_TOKEN not set")
		}

		composeData, err := os.ReadFile(depComposeFile)
		if err != nil {
			return fmt.Errorf("read compose file: %w", err)
		}

		envs := make(map[string]string)
		for _, key := range depEnvFromShell {
			val := os.Getenv(key)
			if val == "" {
				return fmt.Errorf("env %s not set in current shell (expected by --env-from-shell)", key)
			}
			envs[key] = val
		}

		c := coolify.New(getEndpoint(), token)
		uuid, err := c.CreateDockerComposeApp(coolify.CreateAppRequest{
			ProjectUUID: depProjectUUID,
			ServerUUID:  depServerUUID,
			Name:        depName,
			ComposeYAML: string(composeData),
			EnvVars:     envs,
		})
		if err != nil {
			return fmt.Errorf("create app: %w", err)
		}

		if len(envs) > 0 {
			if err := c.UpdateAppEnvs(uuid, envs); err != nil {
				return fmt.Errorf("update envs: %w", err)
			}
		}

		if err := c.StartApp(uuid); err != nil {
			return fmt.Errorf("start app: %w", err)
		}

		// Write uuid for Tofu null_resource to read
		_ = os.MkdirAll(".outputs", 0755)
		_ = os.WriteFile(".outputs/"+depName+"-uuid", []byte(uuid), 0644)

		fmt.Printf("✓ Deployed %s (uuid=%s)\n", depName, uuid)
		return nil
	},
}

func init() {
	deployAppCmd.Flags().StringVar(&depProjectUUID, "project-uuid", "", "Coolify project UUID")
	deployAppCmd.Flags().StringVar(&depServerUUID, "server-uuid", "", "Target server UUID")
	deployAppCmd.Flags().StringVar(&depName, "name", "", "Application name")
	deployAppCmd.Flags().StringVar(&depComposeFile, "compose-file", "", "Path to docker-compose.yml")
	deployAppCmd.Flags().StringSliceVar(&depEnvFromShell, "env-from-shell", []string{}, "Env var names to pass through (repeatable)")
	_ = deployAppCmd.MarkFlagRequired("project-uuid")
	_ = deployAppCmd.MarkFlagRequired("server-uuid")
	_ = deployAppCmd.MarkFlagRequired("name")
	_ = deployAppCmd.MarkFlagRequired("compose-file")
	CoolifyCmd.AddCommand(deployAppCmd)
}
