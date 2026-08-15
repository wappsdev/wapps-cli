package secrets

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
)

// TofuCmd — `wapps tofu <args...>`: `wapps secrets exec --prefix "" -- tofu <args...>`
// için temiz, birinci-sınıf sarım.
//
// NEDEN ayrı bir komut: exec-tabanlı form üç ayrı parça istiyordu ve kafa
// karıştırıyordu — `--project` (aslında cwd `.wapps.yaml`'dan çözülür, gereksiz),
// `--prefix ""` (artık exec'in VARSAYILANI ile aynı; v0.23.0 öncesinde exec
// `TF_VAR_` ekliyordu ve store anahtarları zaten TAM isimle durduğu için
// (`TF_VAR_*`, `AWS_*`) bu çift-prefix
// ekleyip apply'ı bozardı), ve `secrets exec --` boilerplate'i. Bu sarım üçünü
// de gizler: cwd'den projeyi çözer, secret'ları VERBATIM enjekte eder, tofu'yu
// çalıştırır.
//
// Mekanizma runExec ile AYNEN paylaşılır (store okuması,
// scrubber, exit-code propagation). GÜVENLİK: TofuCmd root'a mount'lu olduğundan
// SecretsCmd.PersistentPreRunE (agent-guard + trust-repo binding pin) ÇALIŞMAZ;
// bu yüzden `wapps secrets exec`'in confused-deputy korumasını (SPEC §7.1)
// BYPASS etmemek için gate runTofu içinde AÇIKÇA uygulanır (F1 fix).
var TofuCmd = &cobra.Command{
	Use:   "tofu [args...]",
	Short: "Run tofu with the project's secrets injected as TF_VAR_*",
	Long: `Resolve the project from the current directory's .wapps.yaml, inject its
secrets as env vars (VERBATIM — the store holds TF_VAR_* / AWS_* names directly),
and run tofu with the given args. Secrets never touch disk; the child's stdout/
stderr pass through the same scrubber as 'secrets exec' (injected values -> ***).

  wapps tofu init
  wapps tofu plan -target=module.gate
  wapps tofu apply

Equivalent to (but cleaner than):
  wapps secrets exec -- tofu <args...>

Project resolution is cwd-based (run it from the project's .wapps.yaml dir, as you
would tofu). AI-safe: wapps prints no secret values — safe from agent/CI
contexts (a fresh CI container authenticates with a CF Access service-token pair).`,
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true, // tofu bayrakları (-target, -var, -input=false...) tofu'ya AYNEN geçer
	// NOT: TofuCmd root'a mount'lu → PersistentPreRunE tabanlı Annotations gate'i
	// (agentPolicy) OKUNMAZDI ve yanıltıcıydı; ajan-modu izni + binding pini artık
	// runTofu'da açıkça uygulanıyor (aşağı bak).
	RunE: func(cmd *cobra.Command, args []string) error {
		// DisableFlagParsing açık → --help/-h ve boş çağrı bize ham gelir; sarımın
		// kendi yardımını göster (yoksa `--help` tofu'ya geçer / boş çağrı çıplak
		// tofu'yu çalıştırıp hata verirdi).
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
			return cmd.Help()
		}
		return runTofu(args, agentmode.IsAgent(), cmd.OutOrStdout(), cmd.ErrOrStderr(), defaultExecRunner)
	},
}

// runTofu, TofuCmd'in test edilebilir çekirdeğidir. tofuArgs'ın başına "tofu"
// eklenir ve exec-ailesinin ORTAK yolu (runExec) prefix="" (verbatim) + intent
// "dev" ile çağrılır — böylece store okuması, scrubber ve
// exit-code propagation runExec ile birebir paylaşılır (çift kod yok).
func runTofu(tofuArgs []string, isAgent bool, out, errW io.Writer, runner execRunner) error {
	// F1 fix: TofuCmd root'a mount'lu → SecretsCmd.PersistentPreRunE (agent guard +
	// trust-repo binding pin) çalışmaz. `wapps secrets exec`'in confused-deputy
	// korumasını BYPASS etmemek için gate'i BURADA açıkça uygula (SPEC §7.1). exec
	// gibi ajan modunda SERBEST (PolicyAllow) ama store-backend pin AYNEN enforce edilir
	if err := agentmode.Guard(agentmode.PolicyAllow, isAgent); err != nil {
		return err
	}
	if err := checkRepoBinding(isAgent); err != nil {
		return err
	}
	return runExec(append([]string{"tofu"}, tofuArgs...), "", "dev", false, isAgent, out, errW, runner)
}

func init() {
	// TofuCmd root'a cmd/root.go'da eklenir (secrets.TofuCmd) — top-level `wapps tofu`.
}
