package git

import (
	"fmt"

	"github.com/spf13/cobra"
	gitutil "github.com/wappsdev/wapps-cli/internal/git"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show secrets/all.enc.age drift summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !gitutil.IsRepo(".") {
			fmt.Fprintln(cmd.ErrOrStderr(), "ℹ not inside a git repository — drift check skipped")
			return nil
		}
		drift, err := gitutil.HasDrift(".", "secrets/all.enc.age")
		if err != nil {
			return err
		}
		if drift {
			fmt.Println("⚠ Local secrets archive differs from origin/main")
			fmt.Println("Run: wapps git sync OR git pull")
			return nil
		}
		fmt.Println("✓ In sync with origin/main")
		return nil
	},
}

func init() {
	GitCmd.AddCommand(statusCmd)
}
