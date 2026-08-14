package secrets

import "github.com/spf13/cobra"

var SecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Read and write this project's secrets in the gate",
}
