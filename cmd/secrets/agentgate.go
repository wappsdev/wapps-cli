package secrets

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
)

// agentPolicy, her secrets verb'ünün ajan-modu sınıfıdır (SPEC §7.4.2). MERKEZİ
// kayıt: yeni bir verb bu haritada YOKSA fail-closed REFUSED sayılır (§7.4.2:
// "unannotated new verbs default to REFUSED"). Bir verb yazarı, verb'ünü buraya
// açıkça eklemek zorundadır — "AgentPolicy: allow" beyanının somut hali.
var agentPolicy = map[string]string{
	// data-plane yazımlar + okumalar → ajan serbest (hardware daily imzası yetki verir).
	"exec":       agentmode.PolicyAllow, // --break-glass RunE'de reddedilir
	"apply":      agentmode.PolicyAllow,
	"set":        agentmode.PolicyAllow,
	"import-env": agentmode.PolicyAllow,
	"sync":       agentmode.PolicyAllow,
	"rotate":     agentmode.PolicyAllow,
	"init":       agentmode.PolicyAllow,
	"list":       agentmode.PolicyAllow,
	"diff":       agentmode.PolicyAllow,
	"verify":     agentmode.PolicyAllow,
	"env":        agentmode.PolicyAllow, // print-form RunE'de reddedilir (§7.4.2)
	"status":     agentmode.PolicyAllow,
	// gizli-değer basan yüzey → ajan reddedilir.
	"get": agentmode.PolicyRefuseAgent,
	// TTY-only pin verb'ü.
	"trust-repo": agentmode.PolicyTTY,
	// Yaşam döngüsü (SPEC §8, G9). enroll TTY-only anahtar-üretim seremonisidir
	// (§8.1.1: ajan AGENT_MODE_REFUSED). vouch/grant/revoke/offboard control-plane
	// admin seremonileridir (§8.5: ajan CONTROL_PLANE_REQUIRED).
	"enroll":   agentmode.PolicyTTY,
	"vouch":    agentmode.PolicyControl,
	"grant":    agentmode.PolicyControl,
	"revoke":   agentmode.PolicyControl,
	"offboard": agentmode.PolicyControl,
}

// bindingExempt, repo→proje bağlama kontrolünden muaf verb'ler: trust-repo
// (bağlamayı KURAN), status (her durumda güvenli olmalı §7.10).
var bindingExempt = map[string]bool{
	"trust-repo": true,
	"status":     true,
	// Yaşam döngüsü seremonileri bir repo→proje bağlamasına bağlı değildir: enroll
	// yeni prensibin kendi makinesinde, vouch/offboard bir operatör workstation'ında
	// çalışır; --project'i açıkça isimlendirirler (SPEC §8).
	"enroll":   true,
	"vouch":    true,
	"grant":    true,
	"revoke":   true,
	"offboard": true,
}

func init() {
	// Cobra'nın parent PersistentPreRunE'unu (root: config resolve + git preflight)
	// EZMEDEN, SecretsCmd'nin kendi hook'unu da çalıştır: zincirdeki TÜM
	// PersistentPreRunE'lar root→leaf sırayla koşar (§7.4.1: hook SecretsCmd'de).
	cobra.EnableTraverseRunHooks = true
	SecretsCmd.PersistentPreRunE = secretsPreRunE
}

// secretsPreRunE, HER secrets verb'ünden önce ajan-modu gating'i + repo→proje
// bağlama pinini uygular (SPEC §7.4/§7.7). SecretsCmd'de olduğu için hiçbir verb
// bunu unutamaz; annotation'sız verb fail-closed REFUSED olur.
func secretsPreRunE(cmd *cobra.Command, _ []string) error {
	// Grup komutu (bare `wapps secrets`) veya yardım → gating yok.
	if !cmd.Runnable() || cmd.Name() == "secrets" {
		return nil
	}
	isAgent := agentmode.IsAgent()
	policy := agentPolicy[cmd.Name()] // yoksa "" → Guard fail-closed REFUSED
	if err := agentmode.Guard(policy, isAgent); err != nil {
		return err
	}
	if bindingExempt[cmd.Name()] {
		return nil
	}
	return checkRepoBinding(isAgent)
}

// checkRepoBinding, store-backed bir config için repo→proje bağlamasının GÜVENİLEN
// home-dir'de pinli olduğunu doğrular (SPEC §7.7). legacy-git config'lerde no-op.
//   - pinsiz → BINDING_UNPINNED (ajan asla pinleyemez; insan trust-repo çalıştırır)
//   - farklı proje → hard fail (re-pin bir insan ister)
func checkRepoBinding(_ bool) error {
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil || cfg == nil || !cfg.IsStoreBackend() {
		return nil // config yok / bozuk-legacy / legacy-git → bağlama kontrolü yok
	}
	repoID := repoIdentity(cfg)
	fp := binding.Fingerprint(repoID)

	path, err := binding.DefaultPath()
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "resolve repo-pins path")
	}
	store, err := binding.Load(path)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "load repo pins")
	}
	if cerr := store.Check(fp, cfg.Project); cerr != nil {
		if errors.Is(cerr, binding.ErrMismatch) {
			return clierr.Newf(clierr.BindingUnpinned, "repo is pinned to a different project than %q; re-pin required", cfg.Project)
		}
		return clierr.Newf(clierr.BindingUnpinned, "repo→project binding for %q is not pinned", cfg.Project)
	}
	return nil
}

// repoIdentity, bir repo'nun kararlı kimliğini döner: git remote 'origin' URL'i
// (birden çok checkout aynı pini paylaşır), yoksa mutlak config-root yolu.
func repoIdentity(cfg *config.WappsYAML) string {
	root := cfg.ConfigRoot()
	if root == "" {
		root = "."
	}
	if url := gitRemoteURL(root); url != "" {
		return url
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	return abs
}

// gitRemoteURL, `git -C <dir> remote get-url origin` döner; hata/boşsa "".
func gitRemoteURL(dir string) string {
	out, err := exec.Command("git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
