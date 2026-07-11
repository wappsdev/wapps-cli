package secrets

// Migration verb'leri (server-decrypt SPEC §7.1 + §8.2). TEK migrasyon yolu
// Path B'dir: legacy git-age arşivi → store (import), rollback için store →
// arşiv geri-yazımı (export). İkisi de insan-eli admin op'larıdır (agent-mode
// fail-closed REFUSED — agentPolicy haritasında YOKLAR) ve round-trip
// doğrulaması yapar. tombstone, tüm projeler soak'ı geçtikten SONRA legacy
// arşivi __MIGRATED__ sentinel'iyle emekliye ayırır (§8.2 adım 8).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/config"
	"github.com/wappsdev/wapps-cli/internal/rotation"
	"github.com/wappsdev/wapps-cli/internal/store"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Legacy git-age archive ↔ store migration (import / export / tombstone) — §8.2",
	Long: `Migrate a legacy secrets/all.enc.age archive into the store, or export it
back for rollback (server-decrypt SPEC §8.2, Path B).

  import <project>     Decrypt the legacy age archive locally, bulk-import all
                       keys into the store in ONE atomic epoch, then round-trip
                       verify (count + value comparison). Values change
                       residence, not exposure — no rotation required.
  export <project>     Rollback step 1 (ORDER MANDATORY): read all current
                       values from the store (audited), rewrite the age
                       archive, verify. Only THEN repoint .wapps.yaml back to
                       backend: legacy-git — writes land in the store during
                       the soak, so the untouched archive is STALE.
  tombstone <project>  After ALL projects soak: overwrite the legacy archive
                       with a __MIGRATED__ tombstone so stale checkouts fail
                       loud (§8.2 step 8).`,
}

var migrateImportCmd = &cobra.Command{
	Use:   "import <project>",
	Short: "Path B cutover: legacy age archive → store, one atomic epoch + verify — §8.2",
	Args:  cobra.ExactArgs(1),
	Long: `Import this repo's legacy secrets/all.enc.age into the store for <project>
(server-decrypt SPEC §8.2, Path B):

 1. decrypt the age archive locally (WAPPS_SECRETS_PASSPHRASE);
 2. bulk-PUT every key via POST /import in ONE atomic epoch (audited one row
    per key, §6.4);
 3. round-trip verify: read the imported keys back and compare values.

Then (human steps): repoint .wapps.yaml to 'backend: store', soak 48 h, mark
the archive read-only. Requires an admin session ('wapps login'); refused in
agent mode (migration is a human ceremony).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Ajan modunda reddet (defense-in-depth; PreRun zaten fail-closed REFUSED).
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		return runMigrateImport(args[0], cmd.OutOrStdout())
	},
}

// runMigrateImport, import'un test-edilebilir çekirdeğidir. Değerler yalnızca
// süreç belleğinde yaşar; stdout'a YALNIZCA anahtar adları/sayıları yazılır.
func runMigrateImport(project string, out io.Writer) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return clierr.New(clierr.Internal, "set WAPPS_SECRETS_PASSPHRASE (the legacy archive passphrase)")
	}
	archivePath := resolveArchivePath()
	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate import: read legacy archive %s", archivePath)
	}
	// Tombstone-guard'lı legacy okuma (__MIGRATED__ → ARCHIVE_MIGRATED, tekrar
	// migrasyon yok).
	vals, err := rotation.LegacyArchiveFromBytes(enc).Values(passphrase)
	if err != nil {
		if errors.Is(err, rotation.ErrArchiveMigrated) {
			return clierr.Wrapf(clierr.ArchiveMigrated, err, "migrate import: archive is tombstoned — migration already ran")
		}
		return clierr.Wrapf(clierr.Internal, err, "migrate import: read legacy archive")
	}
	if len(vals) == 0 {
		return clierr.New(clierr.Internal, "migrate import: legacy archive holds no keys")
	}
	sets := make(map[string]string, len(vals))
	for k, v := range vals {
		sets[k] = string(v)
	}

	st, err := openStore(&config.WappsYAML{Project: project})
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := st.Import(ctx, project, sets, store.WriteOpts{}); err != nil {
		return err
	}

	// Round-trip verify (§8.2): import edilen anahtarları geri oku + karşılaştır.
	res, err := st.Read(ctx, project, sortedKeys(sets))
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate import: round-trip verify read failed (import may have landed — re-run to verify)")
	}
	var bad []string
	for k, want := range sets {
		if got, ok := res.Values[k]; !ok || got != want {
			bad = append(bad, k) // yalnızca AD — değer asla basılmaz
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return clierr.Newf(clierr.Internal, "migrate import: round-trip verify FAILED for %d/%d keys: %v", len(bad), len(sets), bad)
	}

	fmt.Fprintf(out,
		"✓ Imported %d keys into the store for %s (one atomic epoch)\n"+
			"✓ Round-trip verified %d keys\n"+
			"Next (human): repoint .wapps.yaml to 'backend: store', soak 48 h, mark %s read-only (§8.2 step 7).\n",
		len(sets), project, len(sets), archivePath)
	return nil
}

// migrateExportConfirm, export'un yıkıcı arşiv-yeniden-yazımını açan zorunlu bayrak.
var migrateExportConfirm bool

var migrateExportCmd = &cobra.Command{
	Use:   "export <project>",
	Short: "Rollback step 1: store → age archive back-sync + verify — §8.2",
	Args:  cobra.ExactArgs(1),
	Long: `Export-back for rollback (server-decrypt SPEC §8.2 — TWO steps, ORDER
MANDATORY):

 1. THIS verb: read all current values from the store (audited as
    value.read.bulk), rewrite this repo's legacy age archive, verify.
 2. Only then repoint .wapps.yaml back to 'backend: legacy-git'.

Rationale: writes land in the STORE during the soak window, so the untouched
archive is STALE — repointing without export-back silently serves old values.

Refuses a tombstoned archive (archives are never modified after tombstone).
Requires WAPPS_SECRETS_PASSPHRASE and --confirm; refused in agent mode.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		return runMigrateExport(args[0], migrateExportConfirm, cmd.OutOrStdout())
	},
}

// runMigrateExport, export'un test-edilebilir çekirdeğidir.
func runMigrateExport(project string, confirm bool, out io.Writer) error {
	if !confirm {
		return clierr.New(clierr.Internal,
			"refusing to rewrite the legacy archive without --confirm (export-back overwrites the local age archive with the store's current values)")
	}
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return clierr.New(clierr.Internal, "set WAPPS_SECRETS_PASSPHRASE (the legacy archive passphrase to seal the export)")
	}
	archivePath := resolveArchivePath()
	// Tombstone'lanmış arşiv ASLA yeniden yazılmaz (§8.2: "Archives are never
	// modified after tombstone").
	if enc, rerr := os.ReadFile(archivePath); rerr == nil {
		if _, verr := rotation.LegacyArchiveFromBytes(enc).Values(passphrase); errors.Is(verr, rotation.ErrArchiveMigrated) {
			return clierr.Wrapf(clierr.ArchiveMigrated, verr, "migrate export: archive is tombstoned")
		}
	}

	st, err := openStore(&config.WappsYAML{Project: project})
	if err != nil {
		return err
	}
	res, err := st.Read(context.Background(), project, nil)
	if err != nil {
		return err
	}
	if len(res.Values) == 0 {
		return clierr.Newf(clierr.Internal, "migrate export: the store returned no readable keys for %s — nothing to export", project)
	}
	archiveJSON, err := valuesToArchiveJSON(res.Values)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: build archive")
	}
	if err := ageutil.EncryptWriteAtomic(archivePath, archiveJSON, passphrase); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: write archive")
	}

	// Verify: yazılan arşivi geri oku + çöz + karşılaştır (count + değerler).
	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: verify read-back")
	}
	got, err := rotation.LegacyArchiveFromBytes(enc).Values(passphrase)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: verify decrypt")
	}
	var bad []string
	for k, want := range res.Values {
		if string(got[k]) != want {
			bad = append(bad, k) // yalnızca AD
		}
	}
	if len(bad) > 0 || len(got) != len(res.Values) {
		sort.Strings(bad)
		return clierr.Newf(clierr.Internal, "migrate export: verify FAILED (archive %d keys vs store %d; mismatched: %v)", len(got), len(res.Values), bad)
	}

	fmt.Fprintf(out,
		"✓ Exported %d keys from the store (%s) into %s and verified\n"+
			"Next (human): commit the archive, THEN repoint .wapps.yaml to 'backend: legacy-git' (§8.2 rollback order).\n",
		len(res.Values), project, archivePath)
	return nil
}

// tombstoneConfirm, tombstone'un yıkıcı legacy-overwrite'ını açan zorunlu bayrak.
var tombstoneConfirm bool

var migrateTombstoneCmd = &cobra.Command{
	Use:   "tombstone <project>",
	Short: "Overwrite the legacy archive with a __MIGRATED__ tombstone — §8.2 step 8",
	Args:  cobra.ExactArgs(1),
	Long: `Overwrite this repo's legacy secrets/all.enc.age with a tombstone that
decrypts (under the legacy passphrase) to {"__MIGRATED__": …} so any stale
checkout fails LOUD (error ARCHIVE_MIGRATED) instead of silently using dead
values (SPEC §8.2 step 8).

Run this ONLY after every project's post-import soak completes — once traffic
is on the store, the legacy archive is stale by construction. Keep the TRUE
pre-tombstone snapshot as a git tag (pre-tombstone/<project>) first, a
HUMAN-RUN step with a recorded deletion date.

Only the __MIGRATED__ sentinel may be written to the legacy archive by this
flow; a real secret value is refused (guarded writer in internal/rotation).

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
				"refusing to overwrite the legacy archive without --confirm (keep the pre-tombstone git tag first)")
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
		// Sentinel-guard'lı legacy-yazım: yalnızca __MIGRATED__ sentinel'i geçer.
		if err := rotation.WriteTombstone(archivePath, pt, passphrase); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "write tombstone")
		}
		fmt.Fprintf(cmd.OutOrStdout(),
			"✓ Tombstoned %s (project %s). Stale checkouts now fail loud (ARCHIVE_MIGRATED).\n"+
				"Next: commit + push the tombstone. Ensure the pre-tombstone/%s git tag exists with a deletion date.\n",
			archivePath, project, project)
		return nil
	},
}

// rotateValuesCmd, standalone değer-rotasyonu (SPEC §7.1: `wapps secrets rotate`,
// typed recipes + worklist). Motor internal/rotation'da hazır + test-edilmiş;
// CANLI recipe executor'u (gerçek vaulter-db-admin/Coolify/CF) + store yazım
// bağlaması henüz bağlanmadı → sessiz no-op yerine fail loud.
var rotateValuesCmd = &cobra.Command{
	Use:   "rotate <project>",
	Short: "Rotate values via typed recipes (resumable worklist) — §7.1",
	Args:  cobra.ExactArgs(1),
	Long: `Rotate secret values for a project via the typed-recipe worklist engine.
Per-key state machine (PENDING → VALUE_MINTED → STORE_WRITTEN →
CONSUMER_UPDATED → VERIFIED → DONE), resumable, highest blast radius first.
The rotate-plan oracle (§6.3) tells you WHICH keys need rotation.

Engine: internal/rotation (typed recipes + run ledger, tested). The live
executor (real vaulter-db-admin/Coolify/CF) is not wired yet — until then this
verb fails loud instead of pretending to rotate.`,
	RunE: func(_ *cobra.Command, args []string) error {
		return clierr.Newf(clierr.NotAvailable,
			"rotate %s: the worklist engine (internal/rotation) is ready + tested, but the live recipe executor (real vaulter-db-admin/Coolify/CF) and its store write binding are not wired yet — rotate values manually via 'wapps secrets set' + the consumer's own rotation runbook", args[0])
	},
}

func init() {
	migrateCmd.AddCommand(migrateImportCmd, migrateExportCmd, migrateTombstoneCmd)
	migrateExportCmd.Flags().BoolVar(&migrateExportConfirm, "confirm", false, "confirm the destructive legacy-archive rewrite from store values")
	migrateTombstoneCmd.Flags().BoolVar(&tombstoneConfirm, "confirm", false, "confirm the destructive legacy-archive overwrite")
	SecretsCmd.AddCommand(migrateCmd, rotateValuesCmd)
}
