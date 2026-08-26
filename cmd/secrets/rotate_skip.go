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
	Short: "Manage value-rotation worklist runs (offboard cleanup)",
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
	RunE: func(cmd *cobra.Command, args []string) error {
		if rotateSkipReason == "" {
			return clierr.New(clierr.Internal, "rotate skip: --reason is required (a recorded skip must state WHY the key needs no rotation)")
		}
		// AJAN KAPISI BURADA — ve BURADA OLMAK ZORUNDA.
		//
		// RotateCmd KÖKE mount'lu (cmd/root.go), yani
		// SecretsCmd.PersistentPreRunE bu komut için HİÇ koşmuyor ve
		// agentPolicy tablosu devreye GİRMİYOR. Bu satır silinirse
		// `wapps rotate skip` ajanlara AÇILIR — başka hiçbir şey onu
		// tutmuyor.
		//
		// Burada eskiden yetkili GÖRÜNEN bir
		// `Annotations: {wapps_agent_policy: refuse_agent}` da duruyordu.
		// Annotation ÖLÜYDÜ: `wapps_agent_policy`nin üretim kodunda SIFIR
		// okuyucusu vardı (secretsPreRunE politikayı AYRI bir tablodan
		// alıyor). İki satır yan yana durunca sonraki okuyucu makul ama
		// YANLIŞ bir çıkarım yapardı — "annotation zaten reddediyor, bu
		// kontrol fazladan" — ve gerçekten koruyan satırı silerdi.
		// Annotation kaldırıldı. Bu yorum da yeter değil, çünkü yorumlar
		// silinir: kontrolü ADIYLA ölçen testler
		// cmd/secrets/rotate_skip_test.go ve rust/.../tests/rootmount.rs.
		if agentmode.IsAgent() {
			return clierr.New(clierr.AgentModeRefused, "rotate skip is a presence-admin ceremony; a human must run it in a terminal")
		}
		// Motor hazır (internal/rotation.RunLedger.SkipKey); eksik olan CLI↔canlı
		// rotasyon-ledger bağlaması (rotasyon executor'uyla birlikte gelir).
		// Sessiz no-op yerine net biçimde reddet.
		return clierr.Newf(clierr.ActionUnavailable,
			"rotate skip (%s %s) is a control-plane admin op; the SKIP engine is ready (internal/rotation) but the CLI↔live rotation-ledger wiring lands with the rotation executor", args[0], args[1])
	},
}

func init() {
	rotateSkipCmd.Flags().StringVar(&rotateSkipReason, "reason", "", "why this key needs no value rotation (recorded in the skip attestation; required)")
	RotateCmd.AddCommand(rotateSkipCmd)
}
