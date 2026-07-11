package secrets

// `wapps secrets policy` ailesi (SPEC §7.3): show/set/lint. policy.json,
// Worker'ın /v1/policy admin API'siyle düzenlenir (write-AUD 15 dk WebAuthn
// oturumu + `admin` verb'i, §4.5). set CAS-bilinçlidir: version = current+1
// gönderilir; yarışta 412 POLICY_CONFLICT → refetch + retry (insan kararı).
// Ajan modu: control-plane REFUSED (CONTROL_PLANE_REQUIRED, §7.1).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/policy"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

// policyTopology, PRIMARY/FALLBACK seçimi (§3.2/§3.3) — Worker'daki TOPOLOGY
// sabitiyle hizalı; PRIMARY'de aud selector'leri istemci lint'inde de reddedilir.
const policyTopology = "primary"

// openAdminStore, kontrol-düzlemi çağrıları için WorkerStore kurar (test seam'i).
var openAdminStore = func() *store.WorkerStore {
	return store.New(store.Config{BaseURL: session.GateURL(), Auth: session.Auth()})
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Show / set / lint the gate's policy.json (admin, §7.3)",
}

var policyShowJSON bool

var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "GET /v1/policy — active version + rules (admin verb, write-AUD session)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmdContext(cmd), 15*time.Second)
		defer cancel()
		res, err := openAdminStore().PolicyGet(ctx)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		if policyShowJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			return enc.Encode(res)
		}
		fmt.Fprintf(w, "version: %d\nsha256:  %s\nrules:   %d\n", res.Version, res.SHA256, len(res.Policy.Rules))
		for i, r := range res.Policy.Rules {
			fmt.Fprintf(w, "  [%d] %s\n", i, renderRule(r))
		}
		return nil
	},
}

var policySetYes bool

var policySetCmd = &cobra.Command{
	Use:   "set <file>",
	Short: "Lint + diff + CAS PUT /v1/policy (version = current+1)",
	Long: `policy set validates <file> offline (schema §4.2/§4.4 + lint §7.3), fetches
the current policy for the version CAS, prints the rule diff old→new, asks for a
TTY confirm, then PUTs with version = current+1. A concurrent admin edit loses
the CAS (412 POLICY_CONFLICT) — refetch with policy show and retry.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPolicySet(cmd, args[0])
	},
}

func runPolicySet(cmd *cobra.Command, path string) error {
	doc, err := readPolicyFile(path)
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	// Çevrimdışı lint (uyarılar bloklamaz; şema hatası bloklar).
	for _, warn := range policy.Lint(*doc) {
		fmt.Fprintf(w, "⚠ %s\n", warn)
	}

	ctx, cancel := context.WithTimeout(cmdContext(cmd), 30*time.Second)
	defer cancel()
	st := openAdminStore()
	cur, err := st.PolicyGet(ctx)
	if err != nil {
		return err
	}
	doc.Version = cur.Version + 1
	if verr := policy.Validate(*doc, policyTopology); verr != nil {
		return clierr.Wrapf(clierr.PolicyInvalid, verr, "policy file rejected offline")
	}

	printRuleDiff(w, cur.Policy.Rules, doc.Rules)
	fmt.Fprintf(w, "\nPUT policy v%d → v%d (%d rules). ", cur.Version, doc.Version, len(doc.Rules))
	if !policySetYes {
		ok, cerr := confirmTTY(cmd.InOrStdin(), w, "Type 'yes' to apply: ")
		if cerr != nil {
			return cerr
		}
		if !ok {
			return clierr.New(clierr.NotAvailable, "policy set aborted (not confirmed)")
		}
	} else {
		fmt.Fprintln(w, "(--yes)")
	}

	version, sha, err := st.PolicyPut(ctx, *doc)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "✓ policy v%d active (sha256 %s)\n", version, short12(sha))
	return nil
}

var policyLintCmd = &cobra.Command{
	Use:   "lint <file>",
	Short: "Offline schema validation (§4.2/§4.4) + overlap analysis (§7.3 a–e)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := readPolicyFile(args[0])
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		warns := policy.Lint(*doc)
		for _, warn := range warns {
			fmt.Fprintf(w, "⚠ %s\n", warn)
		}
		fmt.Fprintf(w, "✓ %s: schema valid (%d rules, %d warnings)\n", args[0], len(doc.Rules), len(warns))
		return nil
	},
}

// readPolicyFile, bir policy dosyasını okur + şema doğrular (version alanı
// lint'te olduğu gibi ≥1 aranır; set yolunda sunucu CAS'ı için üzerine yazılır).
func readPolicyFile(path string) (*store.PolicyDoc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "read policy file %s", path)
	}
	var doc store.PolicyDoc
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, clierr.Wrapf(clierr.PolicyInvalid, err, "policy file %s not valid JSON", path)
	}
	if doc.Version == 0 {
		doc.Version = 1 // set yolu sunucudan current+1 ile değiştirir
	}
	if err := policy.Validate(doc, policyTopology); err != nil {
		return nil, clierr.Wrapf(clierr.PolicyInvalid, err, "policy file %s invalid", path)
	}
	return &doc, nil
}

// renderRule, bir kuralı tek satır insan-okunur basar (değer içermez).
func renderRule(r store.Rule) string {
	sel := "group=" + r.Group
	if r.Service != "" {
		sel = "service=" + r.Service
	}
	if r.Aud != "" {
		sel = "aud=" + r.Aud
	}
	return fmt.Sprintf("%s projects=[%s] keys=[%s] verbs=[%s]",
		sel, strings.Join(r.Projects, ","), strings.Join(r.Keys, ","), strings.Join(r.Verbs, ","))
}

// printRuleDiff, kural listelerinin satır-bazlı farkını basar (basit küme farkı:
// render edilmiş kural metni üzerinden — policy kuralları sıra-bağımsızdır §4.3).
func printRuleDiff(w io.Writer, oldRules, newRules []store.Rule) {
	oldSet := map[string]bool{}
	for _, r := range oldRules {
		oldSet[renderRule(r)] = true
	}
	newSet := map[string]bool{}
	for _, r := range newRules {
		newSet[renderRule(r)] = true
	}
	fmt.Fprintln(w, "rule diff:")
	changed := false
	for _, r := range oldRules {
		if !newSet[renderRule(r)] {
			fmt.Fprintf(w, "  - %s\n", renderRule(r))
			changed = true
		}
	}
	for _, r := range newRules {
		if !oldSet[renderRule(r)] {
			fmt.Fprintf(w, "  + %s\n", renderRule(r))
			changed = true
		}
	}
	if !changed {
		fmt.Fprintln(w, "  (no rule changes)")
	}
}

// confirmTTY, stdin'den 'yes' onayı okur.
func confirmTTY(in io.Reader, w io.Writer, prompt string) (bool, error) {
	fmt.Fprint(w, prompt)
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return false, nil
	}
	return strings.TrimSpace(sc.Text()) == "yes", nil
}

func short12(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

func init() {
	policyShowCmd.Flags().BoolVar(&policyShowJSON, "json", false, "emit the raw policy JSON")
	policySetCmd.Flags().BoolVar(&policySetYes, "yes", false, "skip the interactive confirm (still TTY-only via the agent gate)")
	policyCmd.AddCommand(policyShowCmd, policySetCmd, policyLintCmd)
	SecretsCmd.AddCommand(policyCmd)
}

// cmdContext, cobra komut context'ini döner; Execute dışı doğrudan RunE
// çağrılarında (test) nil olabilir → Background.
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
