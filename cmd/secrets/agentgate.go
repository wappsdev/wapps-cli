package secrets

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
)

// agentPolicy, her secrets verb'ünün ajan-modu sınıfıdır (SPEC §7.1). MERKEZİ
// kayıt: yeni bir verb bu haritada YOKSA fail-closed REFUSED sayılır
// ("unannotated new verbs default to REFUSED"). Bir verb yazarı, verb'ünü
// buraya açıkça eklemek zorundadır. Alt-komut aileleri (policy show/set/lint,
// migrate ...) SecretsCmd'nin ALTINDAKİ ilk seviye adıyla anahtarlanır
// (gateKey) — böylece "policy set", data-plane "set" iznini MİRAS ALAMAZ.
var agentPolicy = map[string]string{
	// data-plane yazımlar + okumalar → ajan serbest (policy.json sunucuda yetkilendirir).
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
	"env":        agentmode.PolicyAllow, // print-form RunE'de reddedilir (§7.1)
	"status":     agentmode.PolicyAllow,
	// gizli-değer basan yüzey → ajan reddedilir.
	"get": agentmode.PolicyRefuseAgent,
	// TTY-only pin verb'ü.
	"trust-repo": agentmode.PolicyTTY,
	// Kontrol düzlemi (SPEC §7.1): policy düzenleme + rotate-plan admin
	// op'larıdır (write-AUD 15 dk WebAuthn oturumu) → ajan CONTROL_PLANE_REQUIRED.
	"policy":      agentmode.PolicyControl,
	"rotate-plan": agentmode.PolicyControl,
	// migrate import/export/tombstone insan-eli admin op'larıdır (SPEC §7.1);
	// haritada YOK → fail-closed REFUSED.
}

// bindingExempt, repo→proje bağlama kontrolünden muaf verb'ler: trust-repo
// (bağlamayı KURAN), status (her durumda güvenli olmalı). policy/rotate-plan
// GLOBAL admin op'larıdır — bir repo→proje bağlamasına bağlı değildirler.
var bindingExempt = map[string]bool{
	"trust-repo":  true,
	"status":      true,
	"policy":      true,
	"rotate-plan": true,
}

func init() {
	// Cobra'nın parent PersistentPreRunE'unu (root: config resolve + git preflight)
	// EZMEDEN, SecretsCmd'nin kendi hook'unu da çalıştır: zincirdeki TÜM
	// PersistentPreRunE'lar root→leaf sırayla koşar.
	cobra.EnableTraverseRunHooks = true
	SecretsCmd.PersistentPreRunE = secretsPreRunE
}

// gateKey, gating anahtarını döner: SecretsCmd'nin ALTINDAKİ ilk seviye komut
// adı. Yaprak bir alt-komutsa (örn. `policy set`) ailenin adı ("policy")
// kullanılır — yaprak adları data-plane verb'leriyle çakışıp yanlış izin
// devralmasın diye.
func gateKey(cmd *cobra.Command) string {
	name := cmd.Name()
	for c := cmd; c != nil; c = c.Parent() {
		p := c.Parent()
		if p != nil && p.Name() == "secrets" {
			name = c.Name()
			break
		}
	}
	return name
}

// secretsPreRunE, HER secrets verb'ünden önce ajan-modu gating'i + repo→proje
// bağlama pinini uygular (SPEC §7.1). SecretsCmd'de olduğu için hiçbir verb
// bunu unutamaz; annotation'sız verb fail-closed REFUSED olur.
func secretsPreRunE(cmd *cobra.Command, _ []string) error {
	// Grup komutu (bare `wapps secrets` / `wapps secrets policy`) veya yardım → gating yok.
	if !cmd.Runnable() || cmd.Name() == "secrets" {
		return nil
	}
	isAgent := agentmode.IsAgent()
	key := gateKey(cmd)
	policy := agentPolicy[key] // yoksa "" → Guard fail-closed REFUSED
	if err := agentmode.Guard(policy, isAgent); err != nil {
		return err
	}
	if bindingExempt[key] {
		return nil
	}
	return checkRepoBinding(isAgent)
}

// checkRepoBinding, store-backed bir config için repo→proje bağlamasının GÜVENİLEN
// home-dir'de pinli olduğunu doğrular (SPEC §7.1 trust-repo). legacy-git
// config'lerde no-op.
//   - pinsiz → BINDING_UNPINNED (ajan asla pinleyemez; insan trust-repo çalıştırır)
//   - farklı proje → hard fail (re-pin bir insan ister)
//   - service principal (CI) → pin kontrolü ATLANIR (aşağıya bak)
func checkRepoBinding(_ bool) error {
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil || cfg == nil || !cfg.IsStoreBackend() {
		return nil // config yok / bozuk-legacy / legacy-git → bağlama kontrolü yok
	}
	// Service principal (P1.8): CF Access service-token ÇİFTİ env'de doluysa
	// repo-pin kontrolü atlanır. Fresh CI container'da trust-repo (TTY) imkânsız —
	// bu muafiyet olmadan store tüketen HER Woodpecker adımı BINDING_UNPINNED ile
	// ölür. Confused-deputy riski sunucu tarafında per-key policy (`service:`
	// selector kuralları, worker/src/policy.ts) ile zaten sınırlandırılmış.
	// Çiftin YARISI set ise bypass YOK — fail-closed davranış aynen sürer.
	//
	// GÜVENLİK KISITI (fresh-eyes P3): repo→proje pin muafiyeti, per-repo
	// confused-deputy hapsini kaldırır; tek kalan kontrol sunucu-tarafı per-key
	// policy'dir. Bu YALNIZCA service token'lar PER-PROJECT scoped ise güvenlidir
	// (her repo tofu-mint edilmiş kendi `repo_seed` token'ını kullanır — plan
	// P3.6; scope-policy: infra-tofu/docs/SECURITY-token-scopes.md). Geniş-scope'lu
	// (çok-proje) bir service token bu muafiyetle proje sınırını aşabilir —
	// provisioning DAİMA dar tutulmalı.
	if serviceTokenPairSet() {
		return nil
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

// serviceTokenPairSet, CF Access service-token çiftinin (CF_ACCESS_CLIENT_ID +
// CF_ACCESS_CLIENT_SECRET) İKİSİNİN de env'de dolu olduğunu söyler — okuma,
// non-interactive auth yolundaki (cmd/login.go path-1) TrimSpace davranışıyla
// birebir aynıdır ki "auth geçer ama pin-muafiyeti geçmez" ayrışması olmasın.
func serviceTokenPairSet() bool {
	return strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_ID")) != "" &&
		strings.TrimSpace(os.Getenv("CF_ACCESS_CLIENT_SECRET")) != ""
}

// gitRemoteURL, `git -C <dir> remote get-url origin` döner; hata/boşsa "".
func gitRemoteURL(dir string) string {
	out, err := exec.Command("git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
