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
	dgBuildArgs     []string
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

		// shouldDeferDeploy: when build args are present, we MUST set them
		// before Coolify kicks off the docker build (Coolify ignores
		// post-build env changes for the in-flight build). The decision
		// logic is extracted to a helper so it can be unit-tested without
		// needing a real Coolify instance.
		createInstant := dgInstantDeploy && !shouldDeferDeploy(dgInstantDeploy, dgBuildArgs)

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
			InstantDeploy:      createInstant,
		})
		if err != nil {
			return fmt.Errorf("create app: %w", err)
		}

		_ = os.MkdirAll(".outputs", 0755)
		_ = os.WriteFile(".outputs/"+dgName+"-uuid", []byte(uuid), 0644)

		fmt.Printf("✓ Created Coolify Application '%s' (uuid=%s, source=github:%s@%s)\n",
			dgName, uuid, dgGitRepo, dgGitBranch)

		if len(dgBuildArgs) > 0 {
			if err := c.SetBuildArgs(uuid, dgBuildArgs); err != nil {
				return fmt.Errorf("set build args: %w", err)
			}
			fmt.Printf("✓ Set %d build arg(s) on '%s'\n", len(dgBuildArgs), dgName)

			if dgInstantDeploy {
				if err := c.TriggerDeploy(uuid); err != nil {
					return fmt.Errorf("trigger deploy: %w", err)
				}
				fmt.Printf("✓ Triggered deploy for '%s'\n", dgName)
			}
		}
		return nil
	},
}

// shouldDeferDeploy returns true when the create call must NOT trigger an
// instant deploy because we still have build args to push first. If the
// operator already passed --instant-deploy=false, no deferral needed (the
// human is already controlling the trigger). If no build args, no deferral
// needed (nothing to push between create and deploy).
func shouldDeferDeploy(instantDeployRequested bool, buildArgs []string) bool {
	return instantDeployRequested && len(buildArgs) > 0
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
	deployAppGitCmd.Flags().StringSliceVar(&dgBuildArgs, "build-arg", []string{}, "Docker build arg KEY=VALUE (repeatable). Stored as is_build_time env var.")

	for _, flag := range []string{"project-uuid", "server-uuid", "github-app-uuid", "name", "git-repo"} {
		_ = deployAppGitCmd.MarkFlagRequired(flag)
	}
	CoolifyCmd.AddCommand(deployAppGitCmd)
}
