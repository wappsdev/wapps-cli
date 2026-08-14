package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

var (
	execPrefix     string
	execBreakGlass bool
	execIntent     string
)

var execCmd = &cobra.Command{
	Use:   "exec -- <command> [args...]",
	Short: "Run a command with the project's secrets injected as env vars",
	Long: `Decrypt secrets and exec the given command with each secret exported
as an env var. wapps forwards the subprocess's stdout and stderr THROUGH A
STREAMING SCRUBBER that redacts any injected secret value to ***, then
exits with the subprocess's exit code.

AI-safe contract: wapps itself prints no secret values — only the
subprocess does, and even that output is scrubbed of injected values. Use this
from agent contexts that need credentialed commands without putting values in
the agent transcript.

  wapps secrets exec -- pnpm dev
  wapps secrets exec --prefix '' -- ./scripts/deploy.sh`,
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: false,
	// Ajan modunda exec SERBEST'tir; yalnızca --break-glass reddedilir.
	Annotations: map[string]string{agentmode.AnnotationKey: agentmode.PolicyAllow},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExec(args, execPrefix, execIntent, execBreakGlass, agentmode.IsAgent(),
			cmd.OutOrStdout(), cmd.ErrOrStderr(), defaultExecRunner)
	},
}

// execRunner is the subprocess-spawn seam. Implementations forward stdin to the
// child and the child's stdout/stderr to the supplied writers (production wires
// scrubbers), then return the child's exit code.
type execRunner func(name string, args, env []string, stdout, stderr io.Writer) (int, error)

// runExec is the testable entry point for `wapps secrets exec --`.
//
// out/errW receive the child's SCRUBBED output. isAgent gates --break-glass
// (BREAK_GLASS_REFUSED under agent mode / non-TTY, §7.4.2). The scrubber applies
// in BOTH modes — a failing tool echoing a connection string prints *** in
// anyone's transcript.
func runExec(args []string, prefix, intent string, breakGlass, isAgent bool, out, errW io.Writer, runner execRunner) error {
	if len(args) == 0 {
		return fmt.Errorf("exec: at least one positional arg required (the command to run)")
	}
	if breakGlass && isAgent {
		return clierr.New(clierr.BreakGlassRefused, "--break-glass refused in agent mode")
	}

	// FIX #4 (korundu): --intent deploy, §7.3.4 fresh-or-fail (receipt/witness/
	// epoch) güvenlik yüzeyini VAAT EDER ama o yol hâlâ bağlanmadı. Sessiz
	// no-op yerine FAIL LOUD — deploy güvenlik yüzeyi işlevsel sanılmasın.
	if intent == "deploy" || breakGlass {
		return clierr.New(clierr.NotAvailable,
			"deploy intent not yet wired to the store; --intent deploy is unavailable in this build (use --intent dev)")
	}

	cfg, cerr := requireStoreConfig("exec")
	if cerr != nil {
		return cerr
	}
	return runExecStore(args, prefix, intent, cfg, out, errW, runner)
}

// runWithInjectedEnv, exec-ailesi verb'lerin ORTAK inject→scrub→run→flush→exit
// bloğudur (P1.1 dedup — legacy runExec, store runExecStore ve ileride
// runDrBootstrap aynı sözleşmeyi paylaşır):
//   - injected ("KEY=VALUE" girdileri) kalıtılan env'in SONUNA eklenir → çakışmada
//     enjekte edilen kazanır (last-wins);
//   - scrubValues, agentmode.FilterScrubbable'dan geçirilir (P3-b: floor-altı
//     atlanan değer için errW'ye TEK, değersiz uyarı — child spawn'dan ÖNCE);
//   - child stdout/stderr agentmode.NewScrubber ile sarılır (§7.4.3: enjekte
//     edilen her süzülmüş değer *** olur) ve HER durumda flush edilir (hata olsa
//     bile kısmi çıktı redakte edilmiş kalır);
//   - runner hatası "exec:" ile sarılıp döner; sıfır-dışı exit kodu os.Exit ile
//     AYNEN alt-sürecinkine yansıtılır.
func runWithInjectedEnv(args, injected, scrubValues []string, out, errW io.Writer, runner execRunner) error {
	mergedEnv := append(os.Environ(), injected...)

	scrubVals := agentmode.FilterScrubbable(scrubValues, errW)
	so := agentmode.NewScrubber(out, scrubVals)
	se := agentmode.NewScrubber(errW, scrubVals)

	exitCode, runErr := runner(args[0], args[1:], mergedEnv, so, se)
	_ = so.Flush()
	_ = se.Flush()
	if runErr != nil {
		return fmt.Errorf("exec: %w", runErr)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// buildExecEnv converts the envelope JSON into "KEY=VALUE" entries.
func buildExecEnv(archiveDecrypted []byte, prefix string) ([]string, error) {
	env, _, err := execEnvAndValues(archiveDecrypted, prefix)
	return env, err
}

// execEnvAndValues mirrors buildExecEnv but ALSO returns the raw injected values
// (candidates for the output scrubber — ALL non-empty values). The scrub-floor +
// entropy gate is applied later by agentmode.FilterScrubbable (P3-b) so the caller
// can surface a one-time leak note for sub-floor secrets it must skip.
func execEnvAndValues(archiveDecrypted []byte, prefix string) (env, values []string, err error) {
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(archiveDecrypted, &outputs); err != nil {
		return nil, nil, fmt.Errorf("parse archive: %w", err)
	}

	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	env = make([]string, 0, len(keys))
	for _, k := range keys {
		val, verr := valueToShellString(outputs[k].Value)
		if verr != nil {
			return nil, nil, fmt.Errorf("key %s: %w", k, verr)
		}
		env = append(env, envName(prefix, k)+"="+val)
		// Tüm boş-olmayan değerler scrubber adayıdır; floor/entropi süzgeci
		// agentmode.FilterScrubbable'da (P3-b) uygulanır.
		if val != "" {
			values = append(values, val)
		}
	}
	return env, values, nil
}

// valueToShellString reduces a JSON value to a single string for cmd.Env.
func valueToShellString(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		return "null", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	return trimmed, nil
}

func init() {
	execCmd.Flags().StringVar(&execPrefix, "prefix", "TF_VAR_",
		"prefix prepended to each env var name (default 'TF_VAR_' for Tofu; pass '' for plain)")
	execCmd.Flags().BoolVar(&execBreakGlass, "break-glass", false,
		"deploy-intent only: TTY-only CF-outage override; HARD-REFUSED in agent mode")
	execCmd.Flags().StringVar(&execIntent, "intent", "dev",
		"freshness intent: dev (tolerate cache) | deploy (fresh-or-fail)")
	SecretsCmd.AddCommand(execCmd)
}
