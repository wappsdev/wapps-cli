package secrets

import (
	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// RotateCmd, değer-rotasyon worklist run'larını yöneten üst komuttur (`wapps rotate`).
// Bugün tek verb'ü `skip`'tir (kayıtlı-SKIP kaçış kapısı). Motor tarafı
// (internal/rotation.RunLedger.SkipKey) TAM test-edilmiştir; canlı rotasyon-ledger
// bağlaması rotasyon executor'uyla birlikte gelir.
var RotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Manage value-rotation worklist runs (offboard/migration §8.6)",
}

var rotateSkipReason string

// rotateSkipCmd, bir NEEDS_TRIAGE (veya başka pending) anahtarı ADMIN KARARIYLA
// SKIPPED'e geçiren KAYITLI-SKIP verb'üdür. RunState'in var saydığı kaçış
// kapısıdır: metadata-eksik bir anahtar (ROTATION_METADATA_MISSING) rotasyon
// run'ını bloklar; bir admin `--reason` ile kayıtlı SKIP yazarak triyajı çözer.
// (Server-decrypt pivotu: yerel imza katmanı SİLİNDİ — yetki Worker admin
// API'sinde zorlanır, SPEC §0.2/§4.5.)
var rotateSkipCmd = &cobra.Command{
	Use:   "skip <run-id> <project>/<key> --reason <why>",
	Short: "Recorded admin SKIP of a rotation worklist key (resolves NEEDS_TRIAGE)",
	Long: `Mark a value-rotation worklist key as SKIPPED with a recorded admin attestation.

A key that carries no rotation metadata is flagged NEEDS_TRIAGE and BLOCKS run
completion — it is never swallowed. An admin resolves it here by writing a SKIP
row (canonical attestation, no secret values) recording WHY the key needs no
value rotation (e.g. the value is a public constant, or it rotates at its
origin). Once written, the run reaches terminal.

This is a control-plane admin op: authorization is enforced by the Worker admin
API (write-AUD session + admin verb). The engine transition (internal/rotation
RunLedger.SkipKey) is implemented and tested; the CLI↔live-ledger wiring lands
with the rotation executor.`,
	Args: cobra.ExactArgs(2),
	// Ajan modunda control-plane imza seremonileri reddedilir (presence-admin gerekir).
	Annotations: map[string]string{agentmode.AnnotationKey: agentmode.PolicyRefuseAgent},
	RunE: func(cmd *cobra.Command, args []string) error {
		if rotateSkipReason == "" {
			return clierr.New(clierr.Internal, "rotate skip: --reason is required (a recorded skip must state WHY the key needs no rotation)")
		}
		if agentmode.IsAgent() {
			return clierr.New(clierr.AgentModeRefused, "rotate skip is a presence-admin ceremony; a human must run it in a terminal")
		}
		// Motor hazır (internal/rotation.RunLedger.SkipKey); eksik olan CLI↔canlı
		// rotasyon-ledger bağlaması (rotasyon executor'uyla birlikte gelir).
		// Sessiz no-op yerine net biçimde reddet.
		return clierr.Newf(clierr.NotAvailable,
			"rotate skip (%s %s) is a control-plane admin op; the SKIP engine is ready (internal/rotation) but the CLI↔live rotation-ledger wiring lands with the rotation executor", args[0], args[1])
	},
}

func init() {
	rotateSkipCmd.Flags().StringVar(&rotateSkipReason, "reason", "", "why this key needs no value rotation (recorded in the skip attestation; required)")
	RotateCmd.AddCommand(rotateSkipCmd)
}
