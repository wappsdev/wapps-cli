package git

import "github.com/spf13/cobra"

var GitCmd = &cobra.Command{
	Use:   "git",
	Short: "Git operations (status, manual sync)",
}
