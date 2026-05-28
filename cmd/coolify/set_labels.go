package coolify

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/coolify"
)

var (
	slAppUUID   string
	slLabels    []string
	slStripCert bool
)

var setLabelsCmd = &cobra.Command{
	Use:   "set-labels",
	Short: "PATCH custom_labels (base64) with optional certresolver=letsencrypt strip",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := os.Getenv("COOLIFY_API_TOKEN")
		if token == "" {
			return fmt.Errorf("COOLIFY_API_TOKEN not set")
		}

		filtered := slLabels
		if slStripCert {
			filtered = make([]string, 0, len(slLabels))
			for _, l := range slLabels {
				if !strings.Contains(l, "certresolver=letsencrypt") {
					filtered = append(filtered, l)
				}
			}
		}

		// Refuse to PATCH with an empty label set. Coolify's PATCH treats
		// custom_labels="" as "clear all labels", which is a destructive
		// no-warn data loss path — an operator who forgot --label would
		// silently wipe their traefik routing rules.
		if len(filtered) == 0 {
			return fmt.Errorf("set-labels: no labels to set (pass --label at least once); refusing to wipe existing labels")
		}

		c := coolify.New(getEndpoint(), token)
		if err := c.SetCustomLabels(slAppUUID, filtered); err != nil {
			return err
		}
		fmt.Printf("✓ Set %d labels on %s\n", len(filtered), slAppUUID)
		return nil
	},
}

func init() {
	setLabelsCmd.Flags().StringVar(&slAppUUID, "app-uuid", "", "Coolify app UUID")
	setLabelsCmd.Flags().StringSliceVar(&slLabels, "label", []string{}, "Label (repeatable, e.g. --label 'traefik.enable=true')")
	setLabelsCmd.Flags().BoolVar(&slStripCert, "strip-cert-resolver", true, "Strip certresolver=letsencrypt labels (file-based Origin Cert pattern)")
	_ = setLabelsCmd.MarkFlagRequired("app-uuid")
	CoolifyCmd.AddCommand(setLabelsCmd)
}
