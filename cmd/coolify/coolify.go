package coolify

import (
	"os"

	"github.com/spf13/cobra"
)

var CoolifyCmd = &cobra.Command{
	Use:   "coolify",
	Short: "Coolify v4 API shim commands (fill gaps in SierraJC Tofu provider)",
}

func getEndpoint() string {
	if e := os.Getenv("COOLIFY_URL"); e != "" {
		return e
	}
	return "https://coolify.meapps.dev/api/v1"
}
