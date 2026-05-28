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
