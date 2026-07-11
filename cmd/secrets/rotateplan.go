package secrets

// `wapps secrets rotate-plan` (SPEC §6.3): audit ledger'ı rotate-set oracle'ı
// olarak sorgular — verilen kimliğin OKUDUĞU/yazdığı/sync'lediği (project, key)
// çiftlerini döner. Offboard adım 3'ün girdisidir: çıkan worklist `wapps
// secrets rotate` recipe'leriyle yürütülür. Ajan modu: control-plane REFUSED.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

var (
	rotatePlanIdentity     string
	rotatePlanSince        string
	rotatePlanAssumePolicy bool
	rotatePlanJSON         bool
)

var rotatePlanCmd = &cobra.Command{
	Use:   "rotate-plan --identity <principal>",
	Short: "Audit-ledger rotate-set oracle: what must rotate after an offboard (§6.3)",
	Long: `rotate-plan queries the gate's hash-chained audit ledger (GET
/v1/admin/rotate-plan, admin verb + write-AUD session) for every (project, key)
the identity read, wrote, imported, synced or rotation-wrote — the precise
rotate set for offboarding (§6.2 step 3).

  --identity        human:<email> | service:<common_name>
  --since           RFC3339 lower bound (optional)
  --assume-policy   ALSO union every key the identity's policy rules COULD read
                    (paranoid superset when audit coverage is doubted)

Execute the resulting worklist with wapps secrets rotate.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rotatePlanIdentity == "" {
			return clierr.New(clierr.Internal, "rotate-plan: --identity is required (human:<email> | service:<common_name>)")
		}
		if rotatePlanSince != "" {
			if _, err := time.Parse(time.RFC3339, rotatePlanSince); err != nil {
				return clierr.Wrapf(clierr.Internal, err, "rotate-plan: --since must be RFC3339")
			}
		}
		ctx, cancel := context.WithTimeout(cmdContext(cmd), 30*time.Second)
		defer cancel()
		res, err := openAdminStore().RotatePlan(ctx, rotatePlanIdentity, rotatePlanSince, rotatePlanAssumePolicy)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		if rotatePlanJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			return enc.Encode(res)
		}
		fmt.Fprintf(w, "rotate plan for %s (generated %s): %d item(s)\n", res.Identity, res.GeneratedAt, len(res.Items))
		if len(res.Items) == 0 {
			fmt.Fprintln(w, "  (nothing to rotate — the ledger has no plaintext-knowing rows for this identity)")
			return nil
		}
		fmt.Fprintf(w, "  %-20s %-32s %-25s %s\n", "PROJECT", "KEY", "LAST_READ", "READS")
		for _, it := range res.Items {
			last := it.LastRead
			if last == "" {
				last = "(assume-policy)"
			}
			fmt.Fprintf(w, "  %-20s %-32s %-25s %d\n", it.Project, it.Key, last, it.Reads)
		}
		fmt.Fprintln(w, "\nNext: execute the worklist with `wapps secrets rotate <project>` (typed recipes, highest blast radius first).")
		return nil
	},
}

func init() {
	rotatePlanCmd.Flags().StringVar(&rotatePlanIdentity, "identity", "", "principal to plan for (human:<email> | service:<common_name>)")
	rotatePlanCmd.Flags().StringVar(&rotatePlanSince, "since", "", "RFC3339 lower bound for ledger rows")
	rotatePlanCmd.Flags().BoolVar(&rotatePlanAssumePolicy, "assume-policy", false, "union every key the identity's rules COULD read (paranoid superset)")
	rotatePlanCmd.Flags().BoolVar(&rotatePlanJSON, "json", false, "emit machine-readable JSON")
	SecretsCmd.AddCommand(rotatePlanCmd)
}
