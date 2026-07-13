package tofu

import (
	"fmt"
	"strings"
)

// RequiredEnvVar names a single environment variable that must be set
// before `tofu output -json` can succeed in a vaulter-style project.
// The hint tells the operator what the variable is for so the recovery
// snippet (below) makes sense out of context.
type RequiredEnvVar struct {
	Name string
	Hint string
}

// RequiredEnvVars lists every env var `tofu output` needs at startup.
// Order matters for the recovery snippet — we emit exports in this
// sequence so the operator's shell loads them deterministically.
var RequiredEnvVars = []RequiredEnvVar{
	{Name: "AWS_ACCESS_KEY_ID", Hint: "R2 backend credentials (map from WAPPS_R2_ACCESS_KEY_ID)"},
	{Name: "AWS_SECRET_ACCESS_KEY", Hint: "R2 backend credentials (map from WAPPS_R2_SECRET_ACCESS_KEY)"},
	{Name: "AWS_ENDPOINT_URL_S3", Hint: "R2 backend endpoint (map from WAPPS_R2_ENDPOINT)"},
	{Name: "AWS_REGION", Hint: "R2 backend region (must be 'auto' for Cloudflare R2)"},
	{Name: "TF_VAR_state_passphrase", Hint: "Tofu encryption block (map from WAPPS_TOFU_STATE_PASSPHRASE)"},
}

// BootstrapEnvVar, `wapps dr bootstrap` akışının child process env'ine
// enjekte ettiği TEK bir değişkeni tanımlar (mimari §3.3). İki sınıf var:
//
//   - Promptable: değer operatörden no-echo TTY prompt'u ile alınır
//     (dashboard-mint token'lar, paper `state_passphrase` vb.).
//   - Constant: değer sabittir ve ASLA promptlanmaz — Constant alanı
//     boş değilse verb bu değeri aynen enjekte eder (örn. AWS_REGION,
//     Cloudflare R2 sözleşmesi gereği her zaman "auto").
type BootstrapEnvVar struct {
	Name string
	Hint string
	// Constant boş değilse bu değişken promptlanmaz; sabit değer
	// olduğu gibi enjekte edilir.
	Constant string
}

// Promptable, değişkenin operatörden interaktif olarak istenip
// istenmeyeceğini söyler. Sabit değerli girdiler (AWS_REGION=auto)
// hiçbir koşulda prompt'a düşmez.
func (b BootstrapEnvVar) Promptable() bool {
	return b.Constant == ""
}

// BootstrapEnvVars, `wapps dr bootstrap` verb'ünün env kataloğudur:
// backend env kontratının (RequiredEnvVars) TAMAMI + dashboard-mint
// provisioning input'ları. Süperset değişmezi (BootstrapEnvVars ⊇
// RequiredEnvVars) preflight_test.go'da korunur — kontrata eklenen her
// yeni değişken buraya da girmek ZORUNDADIR, yoksa bootstrap'lanan
// apply preflight'ta düşer.
//
// Sıralama önemlidir: önce backend kontratı (RequiredEnvVars ile aynı
// sırada), sonra provisioning token'ları — prompt akışı bu sırayı izler.
var BootstrapEnvVars = []BootstrapEnvVar{
	// Backend env kontratı (RequiredEnvVars aynası).
	{Name: "AWS_ACCESS_KEY_ID", Hint: "R2 backend credentials (dashboard-mint R2 access key)"},
	{Name: "AWS_SECRET_ACCESS_KEY", Hint: "R2 backend credentials (dashboard-mint R2 secret key)"},
	{Name: "AWS_ENDPOINT_URL_S3", Hint: "R2 backend endpoint (https://<account_id>.r2.cloudflarestorage.com)"},
	{Name: "AWS_REGION", Hint: "R2 backend region (Cloudflare R2 için sabit 'auto' — promptlanmaz)", Constant: "auto"},
	{Name: "TF_VAR_state_passphrase", Hint: "Tofu state encryption passphrase (paper envelope — kağıt custody)"},
	// Provisioning input'ları: dashboard/console'da insan tarafından
	// mint edilir, TTY'den girilir; diske/store'a yazılmaz (§3.3).
	{Name: "TF_VAR_cloudflare_api_token", Hint: "Cloudflare API token (dashboard-mint; scope-policy dokümanına uygun)"},
	{Name: "TF_VAR_cloudflare_r2_api_token", Hint: "Cloudflare R2 API token (dashboard-mint)"},
	{Name: "TF_VAR_hcloud_token", Hint: "Hetzner Cloud API token (console-mint)"},
	{Name: "TF_VAR_coolify_token", Hint: "Coolify API token (dashboard-mint)"},
}

// PreflightEnv checks that every RequiredEnvVar is set, returning a
// human-readable error listing the missing variables AND a recovery
// snippet the operator can paste into their shell. Returns nil when
// all required vars are present.
//
// lookup is dependency-injected so callers can test specific missing-
// var scenarios without mutating the parent process environment.
//
// This was previously private to cmd/secrets/sync.go (preflightTofuEnv);
// extracted here so both `wapps secrets sync` AND `wapps doctor --for tofu`
// share one implementation and one truth about what tofu needs.
func PreflightEnv(lookup func(string) string) error {
	var missing []RequiredEnvVar
	for _, r := range RequiredEnvVars {
		if lookup(r.Name) == "" {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString("tofu preflight: required environment not set.\n\n")
	b.WriteString("Missing:\n")
	for _, r := range missing {
		fmt.Fprintf(&b, "  - %s (%s)\n", r.Name, r.Hint)
	}
	b.WriteString("\nRecovery (paste into your shell, sourcing your project secrets first):\n\n")
	b.WriteString("  set -a\n")
	b.WriteString("  source ~/.config/<project>/secrets.env\n")
	b.WriteString("  set +a\n")
	b.WriteString("  export AWS_ACCESS_KEY_ID=\"$WAPPS_R2_ACCESS_KEY_ID\"\n")
	b.WriteString("  export AWS_SECRET_ACCESS_KEY=\"$WAPPS_R2_SECRET_ACCESS_KEY\"\n")
	b.WriteString("  export AWS_ENDPOINT_URL_S3=\"$WAPPS_R2_ENDPOINT\"\n")
	b.WriteString("  export AWS_REGION=auto\n")
	b.WriteString("  export TF_VAR_state_passphrase=\"$WAPPS_TOFU_STATE_PASSPHRASE\"")
	return fmt.Errorf("%s", b.String())
}
