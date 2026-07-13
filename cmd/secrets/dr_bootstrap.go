package secrets

// wapps dr bootstrap — store'a ULAŞILAMAYAN senaryolar (örn. bricked Worker,
// mimari §4.3 F3) için TTY-only runbook verb'ü (mimari §3.3, plan P1.3):
//
//  1. Operatörden dashboard-mint bootstrap token'larını İNTERAKTİF ister
//     (no-echo prompt); env'de ZATEN set olanlar atlanır (child kalıtımla alır).
//  2. tofu.PreflightEnv ile backend env kontratını doğrular (--skip-preflight
//     ile atlanabilir).
//  3. Verilen komutu runWithInjectedEnv (P1.1 ortak helper) ile exec eder —
//     child çıktısı scrubber'dan geçer: token'ı echo'layan başarısız bir apply
//     bile transcript'e *** basar.
//  4. Başarılı bitişte FARKLILAŞTIRILMIŞ burn epilogue'u basar (§3.3 tablosu):
//     yalnızca ceremony/temp ve rotasyonla değiştirilen token'lar burn edilir;
//     store'a self-host edilen standing token'lar KORUNUR.
//
// Hiçbir değer diske / store'a / pin'e yazılmaz; değerler yalnızca child
// process env'inde yaşar.

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

var (
	drBootstrapExtraVars     []string
	drBootstrapSkipPreflight bool
)

// bootstrapPrompt, no-echo TTY prompt'unun PAKET-DÜZEYİ seam'idir (plan P1.3).
// Üretimde promptValueNoEcho (set.go — keystrokes echo edilmez); testte
// scripted prompt ile değiştirilir. Değer HİÇBİR çıktıya yazılmaz.
var bootstrapPrompt = promptValueNoEcho

var drBootstrapCmd = &cobra.Command{
	Use:   "bootstrap [--var NAME]... -- <command> [args...]",
	Short: "TTY-only: prompt dashboard-mint bootstrap tokens (no-echo) and exec a command with them injected (§3.3)",
	Long: `Bootstrap/DR runbook verb for when the store itself is unreachable (e.g. a
bricked Worker — flow F3). REFUSED in agent mode: bootstrap tokens must never
cross an AI transcript.

For every bootstrap env var (backend contract + provisioning tokens + --var):
  - already set in your environment  -> inherited, NOT prompted
  - constant (AWS_REGION=auto)       -> injected as-is, NEVER prompted
  - otherwise                        -> no-echo TTY prompt (Enter = skip)

The command then runs with the values injected as process env, through the
same output scrubber as 'wapps secrets exec' — an apply that echoes a token
prints ***. Nothing is ever written to disk, the store, or shell history.

  wapps dr bootstrap -- tofu apply
  wapps dr bootstrap --var TF_VAR_extra_token -- tofu apply -target=module.gate

On success it prints the differentiated burn checklist (§3.3): burn ceremony/
temp tokens NOW, burn a rotated-out token only AFTER its successor is in the
store, and do NOT burn standing tokens self-hosted in the store.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDrBootstrap(args, drBootstrapExtraVars, drBootstrapSkipPreflight,
			agentmode.IsAgent(), cmd.OutOrStdout(), cmd.ErrOrStderr(), os.Getenv, defaultExecRunner)
	},
}

// runDrBootstrap, verb'ün test edilebilir çekirdeğidir (runExec kalıbı).
// lookup dependency-injected'tır (üretimde os.Getenv) — skip-if-set ve
// preflight senaryoları parent env'i mutasyona uğratmadan test edilir.
func runDrBootstrap(args, extraVars []string, skipPreflight, isAgent bool,
	out, errW io.Writer, lookup func(string) string, runner execRunner,
) error {
	// (0) TTY-only guard HER ŞEYDEN ÖNCE: ajan modunda tek bir prompt bile
	// atılmadan reddedilir (§3.3 invariant — token'lar transcript'e giremez).
	if err := agentmode.Guard(agentmode.PolicyTTY, isAgent); err != nil {
		return err
	}
	if len(args) == 0 {
		return clierr.New(clierr.Internal,
			"dr bootstrap: a command is required after -- (e.g. wapps dr bootstrap -- tofu apply)")
	}

	// (1) BootstrapEnvVars ∪ --var kataloğu üzerinden değerleri topla.
	vars := bootstrapVarUnion(extraVars)
	injected := make([]string, 0, len(vars))
	scrub := make([]string, 0, len(vars))
	collected := make(map[string]string, len(vars)) // preflight'ın birleşik görünümü için
	warnedNonTTY := false
	for _, v := range vars {
		if inherited := lookup(v.Name); inherited != "" {
			// Skip-if-set: parent env'de zaten var — child kalıtımla alır, PROMPTLANMAZ
			// ve yeniden enjekte edilmez (yalnızca AD yazılır, değer asla).
			fmt.Fprintf(errW, "  %s: already set — inherited, not prompted\n", v.Name)
			// Kalıtılan da olsa promptable bir token HASSAS'tır: scrubber setine
			// ekle ki "echo eden apply *** basar" garantisi kalıtılan token'lar
			// için de tutsun (constant AWS_REGION=auto scrub'a girmez — over-
			// redaction'a karşı FilterScrubbable ayrıca eşik-altını süzer).
			if v.Promptable() {
				scrub = append(scrub, inherited)
			}
			continue
		}
		if !v.Promptable() {
			// Sabit değerli girdi (AWS_REGION=auto): hiçbir koşulda promptlanmaz.
			injected = append(injected, v.Name+"="+v.Constant)
			collected[v.Name] = v.Constant
			continue
		}
		val, isTTY, perr := bootstrapPrompt(fmt.Sprintf("%s — %s (Enter = skip): ", v.Name, v.Hint))
		if perr != nil {
			return clierr.Wrapf(clierr.Internal, perr, "dr bootstrap: read %s", v.Name)
		}
		if !isTTY && !warnedNonTTY {
			fmt.Fprintln(errW, "  ⚠ stdin is not a TTY — piped values may be captured by shell history")
			warnedNonTTY = true
		}
		if val == "" {
			// Enter = skip: bu apply için gerekmeyen provisioning token'ı atlanabilir;
			// backend kontratından eksik kalanı aşağıda preflight yakalar.
			fmt.Fprintf(errW, "  %s: skipped (empty input)\n", v.Name)
			continue
		}
		injected = append(injected, v.Name+"="+val)
		collected[v.Name] = val
		scrub = append(scrub, val)
	}

	// (2) Backend env kontratı preflight'ı: enjekte edilen + kalıtılan birleşik görünüm.
	if !skipPreflight {
		merged := func(name string) string {
			if v, ok := collected[name]; ok {
				return v
			}
			return lookup(name)
		}
		if perr := tofu.PreflightEnv(merged); perr != nil {
			return fmt.Errorf("dr bootstrap: %w", perr)
		}
	}

	// (3) Exec — P1.1 ortak helper: inject→scrub→run→flush→exit sözleşmesi.
	// Sıfır-dışı exit kodu helper içinde os.Exit ile AYNEN yansıtılır; epilogue
	// bu yüzden yalnızca BAŞARILI bitişte basılır — iş bitmeden burn edilmez
	// (§3.3 "mint-use-burn: iş biter bitmez"), başarısız apply'da operatör
	// token'larla yeniden dener.
	if err := runWithInjectedEnv(args, injected, scrub, out, errW, runner); err != nil {
		return err
	}

	// (4) Farklılaştırılmış burn epilogue (§3.3 tablosu + §5.5 zarf hatırlatması).
	printBootstrapBurnEpilogue(errW)
	return nil
}

// bootstrapVarUnion, BootstrapEnvVars kataloğu ile operatörün --var eklerinin
// birleşimini döner (katalog sırası korunur; mükerrer adlar tekilleştirilir).
func bootstrapVarUnion(extra []string) []tofu.BootstrapEnvVar {
	vars := append([]tofu.BootstrapEnvVar(nil), tofu.BootstrapEnvVars...)
	seen := make(map[string]bool, len(vars))
	for _, v := range vars {
		seen[v.Name] = true
	}
	for _, name := range extra {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		vars = append(vars, tofu.BootstrapEnvVar{Name: name, Hint: "operator-supplied (--var)"})
	}
	return vars
}

// printBootstrapBurnEpilogue, §3.3'ün DÜZELTİLMİŞ burn tablosunu basar: burn
// YALNIZCA ceremony/temp token'a ve rotasyonla değiştirilen eski token'a
// uygulanır; store'a self-host edilen standing credential'lar kalıcıdır
// (hayat döngüleri rotasyondur). + shell hijyeni ve §5.5 zarf hatırlatması.
func printBootstrapBurnEpilogue(w io.Writer) {
	fmt.Fprint(w, `
✓ bootstrap command finished — burn checklist (differentiated, §3.3):
  BURN NOW      every CEREMONY/TEMP token minted just for this run (e.g. the
                R2-admin ceremony token): delete it from the dashboard now.
  BURN AFTER    a token you ROTATED OUT here: burn the OLD one only AFTER its
                successor is written to the store.
  DO NOT BURN   standing tokens SELF-HOSTED in the store (Token A/B, R2 state
                creds, ...): keep them — their lifecycle is rotation, not burn.
  SHELL         unset TF_VAR_state_passphrase from your shell NOW (just the
                passphrase env var — NOT the TF_ENCRYPTION block) and make sure
                no value landed in shell history.
  PAPER (§5.5)  if state_passphrase or the audit-chain head changed, re-record
                the head hash on paper and RE-SEAL the Shamir envelopes.
`)
}

func init() {
	drBootstrapCmd.Flags().StringArrayVar(&drBootstrapExtraVars, "var", nil,
		"extra env var NAME to prompt and inject (repeatable; skipped if already set)")
	drBootstrapCmd.Flags().BoolVar(&drBootstrapSkipPreflight, "skip-preflight", false,
		"skip the tofu backend env contract preflight (non-tofu commands)")
	DrCmd.AddCommand(drBootstrapCmd)
}
