package secrets

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/rotation"
)

// Migration + rotasyon CLI verb'leri (SPEC §10 + §8.6, G11). Motor internal/rotation'
// dadır (tipli recipe'ler + resumable worklist run'ları + store-backed rotasyon-run
// ledger'ı + cutover/tombstone — tam test-edilmiş). cutover/rotate CANLI wiring
// gerektirir: DOĞRULANMIŞ bir trust head (Worker'dan çekilip pinlere karşı) → proje
// alıcı kümesi + WorkerStore değer-yazımı + CANLI recipe Executor (gerçek vaulter-db-
// admin/Coolify/CF). Bu bağlama katmanı G11 motorunun ÖTESİNDEDİR (insan-eliyle,
// G14+) → verb'ler mevcut ve gerekli seremoniyi net biçimde yüzeye çıkarır. tombstone
// offline-yapılabilir (passphrase + arşiv yolu) → GERÇEK biçimde bağlanır (gate'li).

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Two-phase legacy→store migration (cutover → rotate → tombstone) — §10",
	Long: `Migrate a legacy secrets/all.enc.age archive into the store (SPEC §10).

Two-phase, per-project, resumable:
  cutover <project>    Phase 1: byte-identical import (per-key DEK envelope +
                       escrow wrap + signed genesis) then roundtrip-verify; flip
                       .wapps.yaml to backend:store; soak >= 1 week.
  rotate <project>     Phase 2: rotate EVERY value via typed recipes (§8.6);
                       TF-origin keys rotate at the origin (mirror-only §8.6.5).
  tombstone <project>  Overwrite the legacy archive with a __MIGRATED__ tombstone
                       so stale checkouts fail loud (§10.2.7).

IRON RULE (§10.5): a value rotated into the store is NEVER written back to a
legacy archive. Only the tombstone may be written, and only the sentinel.`,
}

// migrateCeremony, cutover/rotate/status'un ortak yanıtıdır: G11 motoru (internal/
// rotation) hazır + test-edilmiş; eksik olan CLI↔canlı-infra bağlamasıdır.
func migrateCeremony(name, detail string) error {
	return clierr.Newf(clierr.NotAvailable,
		"%s needs live wiring (%s); the G11 engine is ready + tested in internal/rotation — CLI↔live wiring (verified trust head → recipient set + WorkerStore value-write + live recipe Executor) is human-run (§10, G14+)",
		name, detail)
}

var migrateCutoverCmd = &cobra.Command{
	Use:   "cutover <project>",
	Short: "Phase 1: byte-identical import + roundtrip verify — §10.2",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return migrateCeremony("migrate cutover "+args[0],
			"decrypt the legacy scrypt archive (last passphrase use), re-encrypt each key as a per-key DEK envelope to the verified recipient set (incl backup+escrow), commit a signed genesis, then roundtrip-verify")
	},
}

var migrateRotateCmd = &cobra.Command{
	Use:   "rotate <project>",
	Short: "Phase 2: rotate every value via typed recipes — §10.2/§8.6",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return migrateCeremony("migrate rotate "+args[0],
			"walk the value-rotation worklist (highest blast radius first) via the typed recipes against real Postgres/Coolify/CF, resumable per key")
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status <project>",
	Short: "Report migration state (legacy→cutover→soak→rotate→tombstoned) — §10.1",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return migrateCeremony("migrate status "+args[0],
			"read the per-project migration state + worklist-run ledger from the store")
	},
}

// tombstoneConfirm, tombstone'un yıkıcı legacy-overwrite'ını açan zorunlu bayrak.
var tombstoneConfirm bool

var migrateTombstoneCmd = &cobra.Command{
	Use:   "tombstone <project>",
	Short: "Overwrite the legacy archive with a __MIGRATED__ tombstone — §10.2.7",
	Args:  cobra.ExactArgs(1),
	Long: `Overwrite this repo's legacy secrets/all.enc.age with a tombstone that
decrypts (under the legacy passphrase) to {"__MIGRATED__": …} so any stale
checkout fails LOUD (error ARCHIVE_MIGRATED) instead of silently using dead
values (SPEC §10.2.7).

Run this ONLY after Phase 2 (rotate) completes for the project — once values
are rotated, the legacy archive is stale by construction. The TRUE pre-tombstone
snapshot must first be kept as a git tag (pre-tombstone/<project>), a HUMAN-RUN
step with a recorded deletion date (§10.2.8).

IRON RULE (§10.5): only the __MIGRATED__ sentinel may be written to the legacy
archive; a rotated secret value is refused (IRON_RULE_VIOLATION).

Requires WAPPS_SECRETS_PASSPHRASE and --confirm. Refused in agent mode (retiring
a real archive is a human decision).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		project := args[0]
		// Ajan modunda reddet: gerçek bir arşivi emekliye ayırmak insan kararı.
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		if !tombstoneConfirm {
			return clierr.New(clierr.Internal,
				"refusing to overwrite the legacy archive without --confirm (keep the pre-tombstone git tag first, §10.2.8)")
		}
		passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
		if passphrase == "" {
			return clierr.New(clierr.Internal, "set WAPPS_SECRETS_PASSPHRASE (the legacy passphrase used to seal the tombstone)")
		}
		archivePath := resolveArchivePath()
		if _, err := os.Stat(archivePath); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "legacy archive not found at %s", archivePath)
		}
		pt, err := rotation.BuildTombstonePlaintext(project, time.Now().UTC().Format("2006-01-02"))
		if err != nil {
			return clierr.Wrapf(clierr.Internal, err, "build tombstone")
		}
		// IRON RULE guard'lı legacy-yazım: yalnızca __MIGRATED__ sentinel'i geçer.
		if err := rotation.WriteTombstone(archivePath, pt, passphrase); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "write tombstone")
		}
		fmt.Fprintf(cmd.OutOrStdout(),
			"✓ Tombstoned %s (project %s). Stale checkouts now fail loud (ARCHIVE_MIGRATED).\n"+
				"Next: commit + push the tombstone. Ensure the pre-tombstone/%s git tag exists with a deletion date (§10.2.8).\n",
			archivePath, project, project)
		return nil
	},
}

// rotateValuesCmd, standalone değer-rotasyonu (SPEC §8.6.4: wapps secrets rotate).
// Migration Phase 2 ile AYNI motoru sürer; CANLI wiring aynı biçimde G14+ insan-eliyle.
var rotateValuesCmd = &cobra.Command{
	Use:   "rotate <project>",
	Short: "Rotate values via typed recipes (resumable worklist) — §8.6.4",
	Args:  cobra.ExactArgs(1),
	Long: `Rotate secret values for a project via the typed-recipe worklist engine
(SPEC §8.6.4). One engine, two callers: migration Phase 2 (§10) and offboard
step 3 (§8.5.5). Per-key state machine (PENDING → VALUE_MINTED → STORE_WRITTEN →
CONSUMER_UPDATED → VERIFIED → DONE), resumable, highest blast radius first.

Engine: internal/rotation (typed recipes + store-backed run ledger, tested). The
live executor (real vaulter-db-admin/Coolify/CF) + the WorkerStore value-write are
human-run wiring (G14+).`,
	RunE: func(_ *cobra.Command, args []string) error {
		return migrateCeremony("rotate "+args[0],
			"plan the ordered worklist from the store manifest, then execute recipes against live infra (resumable, per-key)")
	},
}

func init() {
	migrateCmd.AddCommand(migrateCutoverCmd, migrateRotateCmd, migrateStatusCmd, migrateTombstoneCmd)
	migrateTombstoneCmd.Flags().BoolVar(&tombstoneConfirm, "confirm", false, "confirm the destructive legacy-archive overwrite")
	SecretsCmd.AddCommand(migrateCmd, rotateValuesCmd)
}
