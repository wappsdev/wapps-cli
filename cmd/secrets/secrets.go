package secrets

import "github.com/spf13/cobra"

var SecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage encrypted secret archive (age + Tofu state)",
}
