package secrets

import (
	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// RotateCmd, değer-rotasyon worklist run'larını yöneten üst komuttur (`wapps rotate`).
// Bugün tek verb'ü `skip`'tir (§8.5.5.4 imzalı-SKIP kaçış kapısı). Motor tarafı
// (internal/rotation.RunLedger.SkipKey) TAM test-edilmiştir; canlı store yazımı +
// presence-admin donanım imzası bağlaması (CLI↔infra) G9/G11 kapsamındadır.
var RotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Manage value-rotation worklist runs (offboard/migration §8.6)",
}

var rotateSkipReason string

// rotateSkipCmd, bir NEEDS_TRIAGE (veya başka pending) anahtarı, ADMIN İMZASIYLA
// SKIPPED'e geçiren imzalı-SKIP verb'üdür (§8.5.5.4). RunState'in var saydığı kaçış
// kapısıdır: metadata-eksik bir anahtar (ROTATION_METADATA_MISSING) offboard close'u
// bloklar; bir admin `--reason` ile imzalı-SKIP yazarak triyajı çözer.
var rotateSkipCmd = &cobra.Command{
	Use:   "skip <run-id> <project>/<key> --reason <why>",
	Short: "Admin-signed SKIP of a rotation worklist key (resolves NEEDS_TRIAGE) — §8.5.5.4",
	Long: `Mark a value-rotation worklist key as SKIPPED with an admin signature (SPEC §8.5.5.4).

A key that carries no rotation metadata is flagged NEEDS_TRIAGE and BLOCKS offboard
close — the close step never swallows it. An admin resolves it here by writing a
signed SKIP row (canonical attestation + signature, no secret values) recording WHY
the key needs no value rotation (e.g. the value is a public constant, or it rotates
at its origin). Once written, the run reaches terminal and close can proceed.

This is a control-plane admin ceremony: it needs a verified trust head + a presence
admin hardware key + a store write. The engine transition (internal/rotation
RunLedger.SkipKey) is fully implemented and tested; the CLI↔live-infra wiring lands
with the store client (G9/G11).`,
	Args: cobra.ExactArgs(2),
	// Ajan modunda control-plane imza seremonileri reddedilir (presence-admin gerekir).
	Annotations: map[string]string{agentmode.AnnotationKey: agentmode.PolicyRefuseAgent},
	RunE: func(cmd *cobra.Command, args []string) error {
		if rotateSkipReason == "" {
			return clierr.New(clierr.Internal, "rotate skip: --reason is required (a signed skip must record WHY the key needs no rotation)")
		}
		if agentmode.IsAgent() {
			return clierr.New(clierr.AgentModeRefused, "rotate skip is a presence-admin ceremony; a human must run it in a terminal")
		}
		// Motor hazır (internal/rotation.RunLedger.SkipKey); eksik olan CLI↔canlı-infra
		// bağlaması (doğrulanmış trust head'i store'dan çekme + presence-admin donanım
		// imzası + imzalı satırı store'a yazma). Sessiz no-op yerine net biçimde reddet.
		return clierr.Newf(clierr.NotAvailable,
			"rotate skip (%s %s) is a control-plane admin ceremony; the signed-SKIP engine is ready (internal/rotation §8.5.5.4) but the CLI↔live store/hardware-key wiring is pending (G9/G11)", args[0], args[1])
	},
}

func init() {
	rotateSkipCmd.Flags().StringVar(&rotateSkipReason, "reason", "", "why this key needs no value rotation (recorded in the signed skip; required)")
	RotateCmd.AddCommand(rotateSkipCmd)
}
