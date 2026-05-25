package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/cmd/secrets"
)

var (
	noSync  bool
	verbose bool
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "wapps",
	Short: "wapps umbrella CLI — Tofu monorepo helper for Coolify + age secrets + git auto-sync",
	Long: `wapps is the umbrella CLI for the wappsdev/infra-tofu monorepo.

It wraps:
  - age encryption (secret archive sync)
  - Coolify v4 REST API (gap shim for SierraJC Tofu provider)
  - git auto-sync preflight (pull latest secrets/all.enc.age before any read)
  - doctor (end-to-end dependency check)`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Auto git-sync runs here in Task 17. Stub for now.
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&noSync, "no-sync", false, "Skip git auto-sync preflight")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default: ./.wapps.yaml)")
	rootCmd.AddCommand(secrets.SecretsCmd)
}
