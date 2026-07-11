// Package agentmode, ajan/CI bağlamını saptar ve gizli-değer basan her verb
// yüzeyini yapısal olarak reddeder (SPEC §7.4). Ajan modu, herhangi bir
// ajan/CI ortam işareti VARSA veya stdin bir TTY DEĞİLSE default-ON'dur.
//
// Bir insan gerçek bir terminalde insan modu alır; başka HER ŞEY — Claude Code
// oturumları, Woodpecker pipeline'ları, cron, pipe'lar — ajan modu alır.
// Gating, SecretsCmd'nin PersistentPreRunE'unda değerlendirilir; böylece HİÇBİR
// verb bunu unutamaz — açık ajan-modu annotation'ı olmayan yeni bir verb en
// kısıtlayıcı sınıfa (REFUSED) DÜŞER (fail-closed kayıt).
package agentmode

import (
	"os"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"golang.org/x/term"
)

// agentEnvMarkers, varlığı ajan/CI bağlamı işaret eden ortam değişkenleridir
// (SPEC §7.4.1). Claude Code harness + yaygın CI sistemleri.
var agentEnvMarkers = []string{
	"CLAUDECODE",  // Claude Code oturumu
	"CLAUDE_CODE", // alternatif harness işareti
	"CI",          // jenerik CI
	"CONTINUOUS_INTEGRATION",
	"GITHUB_ACTIONS",
	"WOODPECKER",     // Woodpecker pipeline
	"CI_PIPELINE_ID", // Woodpecker/GitLab
	"BUILDKITE",
	"GITLAB_CI",
	"JENKINS_URL",
	"TEAMCITY_VERSION",
	"TF_BUILD", // Azure Pipelines
}

// Detector, ajan-modu saptamasının test-edilebilir biçimidir. Üretim
// Default()'u kullanır (os.Getenv + gerçek stdin TTY).
type Detector struct {
	// Env, bir ortam değişkeni okur (üretimde os.Getenv).
	Env func(string) string
	// StdinIsTTY, stdin'in bir terminal olup olmadığını döner.
	StdinIsTTY func() bool
	// AllowOverride true ise WAPPS_AGENT_MODE=0 sadece stdin TTY iken onurlandırılır
	// (bir ajan kendini insan moduna çeviremez — yapısal, konvansiyonel değil).
	AllowOverride bool
}

// Default, üretim saptayıcısını döner.
func Default() Detector {
	return Detector{
		Env: os.Getenv,
		StdinIsTTY: func() bool {
			return term.IsTerminal(int(os.Stdin.Fd()))
		},
		AllowOverride: true,
	}
}

// IsAgent, ajan modunun etkin olup olmadığını döner (SPEC §7.4.1).
//
// Ajan modu default-ON'dur: herhangi bir ajan/CI işareti VEYA non-TTY stdin.
// WAPPS_AGENT_MODE=0 override'ı YALNIZCA stdin bir TTY iken onurlandırılır — bir
// ajan therefore kendini insan moduna geçiremez (yapısal garanti §7.4.1).
func (d Detector) IsAgent() bool {
	tty := d.StdinIsTTY != nil && d.StdinIsTTY()

	// Override: yalnızca TTY iken (insan etkileşimli oturum) devre dışı bırakılabilir.
	if d.AllowOverride && tty && d.Env("WAPPS_AGENT_MODE") == "0" {
		return false
	}

	// Non-TTY stdin → daima ajan.
	if !tty {
		return true
	}
	// TTY olsa bile bir ajan/CI işareti varsa → ajan.
	for _, k := range agentEnvMarkers {
		if d.Env(k) != "" {
			return true
		}
	}
	return false
}

// IsAgent, üretim saptayıcısıyla ajan modunu döner.
func IsAgent() bool { return Default().IsAgent() }

// --- Verb gating (SPEC §7.4.2) ----------------------------------------------

// Cobra command annotation anahtarı + politika değerleri. Bir verb, init'inde
// bu annotation'ı SET ETMELİDİR; etmezse (missing) en kısıtlayıcı sınıfa düşer.
const AnnotationKey = "wapps_agent_policy"

// Politika değerleri (annotation string'leri).
const (
	// PolicyAllow, verb ajan modunda serbesttir (exec/apply/env --write/set/...).
	PolicyAllow = "allow"
	// PolicyRefuseAgent, gizli-değer basan yüzey → ajan modunda AGENT_MODE_REFUSED
	// (get, env-print). İnsan terminalde çalıştırabilir.
	PolicyRefuseAgent = "refuse_agent"
	// PolicyControl, control-plane verb → ajan modunda CONTROL_PLANE_REQUIRED.
	PolicyControl = "control"
	// PolicyTTY, TTY-only pin/oturum verb (login/trust-repo) → ajan modunda
	// insan terminali ister.
	PolicyTTY = "tty"
)

// Guard, bir politika + ajan-modu durumunda verb'ün çalışıp çalışamayacağını
// döner. Reddedilirse doğru clierr kodu döner (SPEC §7.4.2/§7.5). Bilinmeyen/
// boş politika fail-closed REFUSED sayılır.
func Guard(policy string, isAgent bool) error {
	if !isAgent {
		return nil // insan modu: tüm verb'ler serbest (Worker/oturum yine de kapı bekçisi)
	}
	switch policy {
	case PolicyAllow:
		return nil
	case PolicyControl:
		return clierr.New(clierr.ControlPlaneRequired,
			"control-plane operation refused in agent mode")
	case PolicyTTY:
		return clierr.New(clierr.AgentModeRefused,
			"this command requires a human terminal")
	case PolicyRefuseAgent:
		fallthrough
	default:
		// Boş/bilinmeyen → fail-closed (yeni annotation'sız verb REFUSED).
		return clierr.New(clierr.AgentModeRefused,
			"plaintext-printing surface refused in agent mode")
	}
}
