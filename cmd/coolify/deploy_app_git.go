package coolify

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/coolify"
)

var (
	dgProjectUUID   string
	dgServerUUID    string
	dgGithubAppUUID string
	dgName          string
	dgGitRepo       string
	dgGitBranch     string
	dgDockerfile    string
	dgBaseDir       string
	dgPorts         string
	dgWatchPaths    []string
	dgBuildPack     string
	dgInstantDeploy bool
)

var deployAppGitCmd = &cobra.Command{
	Use:   "deploy-app-git",
	Short: "Create Coolify Application from a private GitHub repo (Coolify builds on the target server)",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := os.Getenv("COOLIFY_API_TOKEN")
		if token == "" {
			return fmt.Errorf("COOLIFY_API_TOKEN not set")
		}

		c := coolify.New(getEndpoint(), token)
		uuid, err := c.CreatePrivateGitHubAppApp(coolify.CreateGitHubAppAppRequest{
			ProjectUUID:        dgProjectUUID,
			ServerUUID:         dgServerUUID,
			GithubAppUUID:      dgGithubAppUUID,
			GitRepository:      dgGitRepo,
			GitBranch:          dgGitBranch,
			BuildPack:          dgBuildPack,
			Name:               dgName,
			BaseDirectory:      dgBaseDir,
			DockerfileLocation: dgDockerfile,
			Ports:              dgPorts,
			WatchPaths:         strings.Join(dgWatchPaths, "\n"),
			InstantDeploy:      dgInstantDeploy,
		})
		if err != nil {
			return fmt.Errorf("create app: %w", err)
		}

		_ = os.MkdirAll(".outputs", 0755)
		_ = os.WriteFile(".outputs/"+dgName+"-uuid", []byte(uuid), 0644)

		fmt.Printf("✓ Created Coolify Application '%s' (uuid=%s, source=github:%s@%s)\n",
			dgName, uuid, dgGitRepo, dgGitBranch)
		return nil
	},
}

func init() {
	deployAppGitCmd.Flags().StringVar(&dgProjectUUID, "project-uuid", "", "Coolify project UUID")
	deployAppGitCmd.Flags().StringVar(&dgServerUUID, "server-uuid", "", "Target server UUID")
	deployAppGitCmd.Flags().StringVar(&dgGithubAppUUID, "github-app-uuid", "", "Coolify GitHub App source UUID")
	deployAppGitCmd.Flags().StringVar(&dgName, "name", "", "Application name")
	deployAppGitCmd.Flags().StringVar(&dgGitRepo, "git-repo", "", "GitHub org/repo (e.g. wappsdev/vaulter-api)")
	deployAppGitCmd.Flags().StringVar(&dgGitBranch, "git-branch", "main", "Git branch")
	deployAppGitCmd.Flags().StringVar(&dgDockerfile, "dockerfile", "Dockerfile", "Dockerfile path relative to base-dir")
	deployAppGitCmd.Flags().StringVar(&dgBaseDir, "base-dir", "/", "Build context base directory")
	deployAppGitCmd.Flags().StringVar(&dgPorts, "ports", "", "Exposed ports (comma-separated)")
	deployAppGitCmd.Flags().StringSliceVar(&dgWatchPaths, "watch-path", []string{}, "Path patterns to trigger rebuild (repeatable, e.g. cmd/gateway/**)")
	deployAppGitCmd.Flags().StringVar(&dgBuildPack, "build-pack", "dockerfile", "Build pack: dockerfile, nixpacks, static")
	deployAppGitCmd.Flags().BoolVar(&dgInstantDeploy, "instant-deploy", true, "Trigger initial build immediately on create")

	for _, flag := range []string{"project-uuid", "server-uuid", "github-app-uuid", "name", "git-repo"} {
		_ = deployAppGitCmd.MarkFlagRequired(flag)
	}
	CoolifyCmd.AddCommand(deployAppGitCmd)
}
