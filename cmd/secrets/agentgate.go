package secrets

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/binding"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"golang.org/x/term"
)

// agentPolicy, her secrets verb'ünün ajan-modu sınıfıdır (SPEC §7.1). MERKEZİ
// kayıt: yeni bir verb bu haritada YOKSA fail-closed REFUSED sayılır
// ("unannotated new verbs default to REFUSED"). Bir verb yazarı, verb'ünü
// buraya açıkça eklemek zorundadır. Alt-komut aileleri (policy show/set/lint,
// projects list/rm) SecretsCmd'nin ALTINDAKİ ilk seviye adıyla anahtarlanır
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
	"env":        agentmode.PolicyAllow, // print-form RunE'de reddedilir (§7.1)
	"status":     agentmode.PolicyAllow,
	// gizli-değer basan yüzey → ajan reddedilir.
	"get": agentmode.PolicyRefuseAgent,
	// GERİ ALINAMAZ yıkıcı yüzey → ajan reddedilir. Sunucu tarafı zaten ayrı bir
	// `delete` grant'i istiyor (§4.2 rev4); bu, istemci tarafındaki ikinci kilit.
	"rm": agentmode.PolicyRefuseAgent,
	// TTY-only pin verb'ü.
	"trust-repo": agentmode.PolicyTTY,
	// Kontrol düzlemi (SPEC §7.1): policy düzenleme + rotate-plan admin
	// op'larıdır (write-AUD 15 dk WebAuthn oturumu) → ajan CONTROL_PLANE_REQUIRED.
	"policy":      agentmode.PolicyControl,
	"rotate-plan": agentmode.PolicyControl,
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
	// Cobra'nın parent PersistentPreRunE'unu (root: config resolve)
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

// checkRepoBinding, bir config için repo→proje bağlamasının GÜVENİLEN home-dir'de
// pinli olduğunu doğrular (SPEC §7.1 trust-repo).
//   - pinsiz → BINDING_UNPINNED (ajan asla pinleyemez; insan trust-repo çalıştırır)
//   - farklı proje → hard fail (re-pin bir insan ister)
//   - service principal (CI) → pin kontrolü ATLANIR (aşağıya bak)
func checkRepoBinding(isAgent bool) error {
	// Bare `--project <ad>` (kayıt defterinde olmayan): ortada bağlanacak bir
	// repo YOKTUR. Bir İNSAN için bu, hedefi komut satırında açıkça adlandırmaktır
	// — pinin koruduğu confused-deputy durumu değil. Bir AJAN için öyle değildir:
	// pin tam olarak "A repo'sundaki ajan B projesini okumasın" içindir, ve ajanın
	// --project yazabilmesi onu yetkili yapmaz → ajan modunda fail-closed.
	if projectOverride != "" {
		if isAgent {
			// Kurtarma satırı override ediliyor: ortada pinlenecek bir repo YOK,
			// o yüzden registry'nin "trust-repo çalıştır" varsayılanı burada
			// anlamsız olurdu.
			return clierr.Newf(clierr.BindingUnpinned,
				"--project %q names a project with no local repo; an agent may not target a project this way", projectOverride).
				WithRecovery("a human must run this in a terminal, or work inside the project's repo")
		}
		return nil
	}
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil || cfg == nil {
		return nil // config yok → bağlama kontrolü yok
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
	cerr := store.Check(fp, cfg.Project)
	if cerr == nil {
		return nil
	}
	if errors.Is(cerr, binding.ErrMismatch) {
		// UYUŞMAZLIK satır içi çözülmez. Bu, config'in PİNLİ OLANDAN BAŞKA bir
		// projeyi talep etmesi demek — pinin var olma sebebinin ta kendisi.
		// Yeni bir bağlama (aşağısı) sıradan ve zararsızdır; bir bağlamayı
		// DEĞİŞTİRMEK ise kasıtlı bir karar ister: açıkça trust-repo.
		return clierr.Newf(clierr.BindingUnpinned,
			"repo is pinned to a different project than %q; re-pin required", cfg.Project).
			WithRecovery("if this is intended, run: wapps secrets trust-repo")
	}

	// Buradan sonrası PİNSİZ durumu: bağlama henüz hiç kurulmamış.
	//
	// Ajan/CI → fail-closed. Pinin gerçekten iş gördüğü yer burasıdır: uydurulmuş
	// ya da ele geçmiş bir .wapps.yaml, kendi başına bir proje talep edemesin.
	// Bir ajanın o dosyayı yazabiliyor olması, onu yetkili yapmaz.
	if isAgent {
		return clierr.Newf(clierr.BindingUnpinned, "repo→project binding for %q is not pinned", cfg.Project)
	}
	// İnsan ama TTY yok (pipe/script) → soramayız, o yüzden sormuş gibi yapmayız.
	if !stdinIsTTY() {
		return clierr.Newf(clierr.BindingUnpinned, "repo→project binding for %q is not pinned", cfg.Project)
	}
	// İnsan, terminalde: bu dizine gelip komutu yazmış olması niyet beyanıdır.
	// Ayrı bir komut öğretmek yerine BURADA soruyoruz — güvenlik aynı (onaylayan
	// yine bir insan), sürtünme repo başına tek tuş. Projeyi ADIYLA gösteriyoruz:
	// korunan şey tam olarak bu, hangi projenin talep edildiğini görebilmek.
	if !bindPrompt(repoID, cfg.Project) {
		return clierr.Newf(clierr.BindingUnpinned, "not pinned; binding declined for %q", cfg.Project)
	}
	store.Pin(fp, binding.Pin{Repo: repoID, Project: cfg.Project, Backend: cfg.Backend})
	if serr := store.Save(path); serr != nil {
		return clierr.Wrapf(clierr.Internal, serr, "save repo pin")
	}
	fmt.Fprintf(os.Stderr, "✓ bound this repo to project %q (change it later with: wapps secrets trust-repo)\n", cfg.Project)
	return nil
}

// bindPrompt, pinsiz bir bağlamayı satır içi onaylatır. PAKET SEAM'i: testler
// stdin'e takılmasın diye değiştirilir.
var bindPrompt = func(repoID, project string) bool {
	fmt.Fprintf(os.Stderr, "This repo is not bound to a project yet.\n")
	fmt.Fprintf(os.Stderr, "  repo:    %s\n", repoID)
	fmt.Fprintf(os.Stderr, "  project: %s\n", project)
	fmt.Fprintf(os.Stderr, "Bind them? [y/N]: ")
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(sc.Text()))
	return a == "y" || a == "yes"
}

// stdinIsTTY, satır içi soru sorulabilir mi (PAKET SEAM'i: testte false).
var stdinIsTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// repoIdentity, bağlanan birimin kararlı kimliğini döner. Bu birim REPO DEĞİL,
// "şu .wapps.yaml"dır: origin URL'i + config'in repo kökine göre yolu.
//
// Neden yol da dahil: eskiden kimlik yalnızca origin URL'iydi, yani bir
// monorepo'daki BÜTÜN projeler tek parmak izine çakışıyordu. infra-tofu beş
// proje barındırıyor (vaulter, lab, vibe-pro, platform, secrets-gate); biri
// pinlenince diğer dördü "repo is pinned to a different project" ile
// ERİŞİLEMEZ hale geliyordu. Yolu eklemek ilişkiyi çok-çoka çevirir: bir proje
// birden çok repo'dan, bir repo birden çok projeden kullanılabilir.
//
// Config repo KÖKÜNDEYSE kimlik çıplak URL olarak kalır — böylece tek-projeli
// repo'ların mevcut pinleri geçerliliğini korur (yeniden pinleme gerekmez) ve
// aynı repo'nun farklı checkout'ları pini paylaşmaya devam eder.
func repoIdentity(cfg *config.WappsYAML) string {
	root := cfg.ConfigRoot()
	if root == "" {
		root = "."
	}
	sub := gitRepoSubpath(root)
	// origin varsa kimlik ona bağlanır: aynı repo'nun her checkout'u pini paylaşır.
	if url := gitRemoteURL(root); url != "" {
		if sub != "" {
			return url + "#" + sub
		}
		return url
	}
	// origin YOKSA (yerel repo) ANA repo kökü kullanılır — worktree'nin kendi
	// kökü DEĞİL. Aksi halde her worktree ayrı bir kimlik alırdı: navlun'un 25
	// worktree'si 25 kez bağlama sorusu ve ajan tarafında 25 ayrı
	// BINDING_UNPINNED demek olurdu. git --git-common-dir worktree'den de ana
	// repo'dan da aynı .git'i gösterir, o yüzden hepsi tek pinde buluşur.
	if main := gitMainRepoRoot(root); main != "" {
		if sub != "" {
			return main + "#" + sub
		}
		return main
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	return abs
}

// gitMainRepoRoot, ANA çalışma ağacının kökünü döner (worktree'den çağrılsa
// bile). git repo'su değilse "".
func gitMainRepoRoot(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--path-format=absolute", "--git-common-dir").Output()
	if err != nil {
		return ""
	}
	gitDir := strings.TrimSpace(string(out))
	if gitDir == "" {
		return ""
	}
	return filepath.Dir(gitDir)
}

// gitRepoSubpath, dir'in git kökine göre yolunu döner ("" = kökün kendisi).
func gitRepoSubpath(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-prefix").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(string(out)), "/")
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
