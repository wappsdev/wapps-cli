package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Print a single secret value (TTY only; refused in agent mode)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// get, gizli bir DÜZ METİN değeri basar → ajan modunda YAPISAL red (§7.4.2).
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		return runGet(args[0], cmd.OutOrStdout())
	},
}

// runGet, get'in backend-aware çekirdeğidir: backend:store ise değeri store'dan
// çeker; aksi halde legacy age-arşivinden (readKey AYNEN korunur). Değer + tek
// newline yazılır (legacy `fmt.Println` ile aynı çıktı).
func runGet(key string, out io.Writer) error {
	cfg, err := storeProject("get")
	if err != nil {
		return err
	}
	val, err := getStore(cfg, key)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, val)
	return nil
}

// rawValueToString renders one archive value for `get`:
//   - absent "value" field or JSON null → "" (matches the pre-fix struct-into-
//     string zero-value semantics; never prints a raw envelope blob)
//   - JSON string → the string verbatim (unquoted, for piping)
//   - any other type (array/map/number/bool) → compact JSON
func rawValueToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		// Covers JSON string (→ value) and JSON null (→ ""), matching legacy.
		return s
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err == nil {
		return compact.String()
	}
	return strings.TrimSpace(string(raw))
}

func init() {
	SecretsCmd.AddCommand(getCmd)
}
