package secrets

// Migration verb'leri (server-decrypt SPEC §7.1 + §8.2). TEK migrasyon yolu
// Path B'dir: legacy git-age arşivi → store (import), rollback için store →
// arşiv geri-yazımı (export). İkisi de insan-eli admin op'larıdır (agent-mode
// fail-closed REFUSED — agentPolicy haritasında YOKLAR) ve round-trip
// doğrulaması yapar. tombstone, tüm projeler soak'ı geçtikten SONRA legacy
// arşivi __MIGRATED__ sentinel'iyle emekliye ayırır (§8.2 adım 8).
//
// Hiçbir verb gizli DEĞER basmaz: stdout'a yalnızca anahtar ADLARI + sayılar
// yazılır (agent-mode + safelog sözleşmesi).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

  import [--project P] [--dry-run]   Decrypt the legacy age archive locally,
                       bulk-import all keys into the store in ONE atomic
                       epoch, round-trip verify, and print a per-key report.
                       Idempotent: a re-run whose values already match the
                       store is a no-op. --dry-run lists what WOULD move
                       without writing anything.
  export [--project P] --out FILE    Rollback step 1 (ORDER MANDATORY): read
                       all current values from the store (audited), write
                       them to a legacy-shaped age archive at FILE, verify.
                       Only THEN repoint .wapps.yaml back to
                       backend: legacy-git — writes land in the store during
                       the soak, so the untouched archive is STALE.
  tombstone [--project P]            After ALL projects soak: overwrite the
                       legacy archive with a __MIGRATED__ tombstone so stale
                       checkouts fail loud (§8.2 step 8).`,
}

// migrateProject, --project bayrağını çözer: bayrak doluysa onu, boşsa geçerli
// .wapps.yaml'daki project'i döner. İkisi de yoksa net hata (migration hedefi
// asla sessizce tahmin edilmez).
func migrateProject(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil {
		return "", err
	}
	if cfg != nil && cfg.Project != "" {
		return cfg.Project, nil
	}
	return "", clierr.New(clierr.Internal,
		"no project resolved — pass --project <p> or run from a repo whose .wapps.yaml declares 'project:'")
}

// migrate import bayrakları.
var (
	migrateImportProject string
	migrateImportDryRun  bool
	migrateImportConfirm bool
)

var migrateImportCmd = &cobra.Command{
	Use:   "import [--project <p>] [--dry-run] [--confirm]",
	Short: "Path B cutover: legacy age archive → store, one atomic epoch + verify — §8.2",
	Args:  cobra.NoArgs,
	Long: `Import this repo's legacy secrets/all.enc.age into the store
(server-decrypt SPEC §8.2, Path B):

 1. decrypt the age archive locally (WAPPS_SECRETS_PASSPHRASE);
 2. compare against the store's current state (idempotency: keys whose value
    already matches are reported unchanged; if EVERYTHING matches the import
    is a no-op — safe to re-run);
 3. bulk-PUT via POST /import in ONE atomic epoch (audited one row per key,
    §6.4);
 4. round-trip verify: read every imported key back and compare;
 5. print a per-key report (names only — values NEVER reach stdout).

--dry-run lists what WOULD move (per-key, with new/existing markers) and
performs NO store writes. No value rotation is required — the values change
residence, not exposure (§8.2).

DESTRUCTIVE RE-RUN GUARD: if existing store keys hold values that DIFFER from
the archive's (e.g. writes landed in the store after the cutover), importing
would silently revert them to the archive's stale values — that path requires
--confirm (same if the store's current state cannot be determined at all).

Then (human steps): repoint .wapps.yaml to 'backend: store', soak 48 h, mark
the archive read-only. Requires an admin session ('wapps login'); refused in
agent mode (migration is a human ceremony).`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Ajan modunda reddet (defense-in-depth; PreRun zaten fail-closed REFUSED).
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		project, err := migrateProject(migrateImportProject)
		if err != nil {
			return err
		}
		return runMigrateImport(project, migrateImportDryRun, migrateImportConfirm, cmd.OutOrStdout())
	},
}

// readLegacyValues, legacy arşivi okur+çözer ve düz-metin değer haritasını döner.
// Tombstone-guard'lıdır (__MIGRATED__ → ARCHIVE_MIGRATED, tekrar migrasyon yok).
func readLegacyValues(archivePath, passphrase string) (map[string]string, error) {
	enc, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "read legacy archive %s", archivePath)
	}
	vals, err := rotation.LegacyArchiveFromBytes(enc).Values(passphrase)
	if err != nil {
		if errors.Is(err, rotation.ErrArchiveMigrated) {
			return nil, clierr.Wrapf(clierr.ArchiveMigrated, err, "archive is tombstoned — migration already ran")
		}
		return nil, clierr.Wrapf(clierr.Internal, err, "read legacy archive")
	}
	out := make(map[string]string, len(vals))
	for k, v := range vals {
		out[k] = string(v)
	}
	return out, nil
}

// runMigrateImport, import'un test-edilebilir çekirdeğidir. Değerler yalnızca
// süreç belleğinde yaşar; stdout'a YALNIZCA anahtar adları/sayıları yazılır.
func runMigrateImport(project string, dryRun, confirm bool, out io.Writer) error {
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return clierr.New(clierr.Internal, "set WAPPS_SECRETS_PASSPHRASE (the legacy archive passphrase)")
	}
	archivePath := resolveArchivePath()
	sets, err := readLegacyValues(archivePath, passphrase)
	if err != nil {
		return fmt.Errorf("migrate import: %w", err)
	}
	if len(sets) == 0 {
		return clierr.New(clierr.Internal, "migrate import: legacy archive holds no keys")
	}
	keys := sortedKeys(sets)

	st, err := openStore(&config.WappsYAML{Project: project})
	if err != nil {
		return err
	}
	ctx := context.Background()

	// Store'un mevcut durumu (idempotency + per-key rapor için). Metadata listesi
	// başarısızsa körlemesine import'a düşeriz — gerçek bir yetki/ağ hatası zaten
	// Import'ta gürültüyle yüzeye çıkar.
	existing := map[string]bool{}
	stateKnown := true
	if kres, kerr := st.Keys(ctx, project); kerr == nil {
		for _, k := range kres.Keys {
			existing[k.KeyName] = true
		}
	} else {
		stateKnown = false
	}

	if dryRun {
		fmt.Fprintf(out, "DRY RUN — %d keys in %s would be imported into the store for %s:\n", len(sets), archivePath, project)
		for _, k := range keys {
			marker := "new"
			switch {
			case !stateKnown:
				marker = "store state unknown"
			case existing[k]:
				marker = "already in store — value would be overwritten with the archive's"
			}
			fmt.Fprintf(out, "  → %s (%s)\n", k, marker)
		}
		fmt.Fprintln(out, "No writes performed (--dry-run).")
		return nil
	}

	// Idempotency ön-okuması: store'da ZATEN var olan anahtarların değerlerini
	// karşılaştır. TÜM anahtarlar mevcut + eşitse import no-op'tur (yeni epoch
	// açılmaz — tekrar koşmak güvenlidir). Eşleşmeyen mevcut anahtarlar
	// "conflicting" sayılır — import onları arşivin (muhtemelen BAYAT)
	// değerlerine geri döndürür, o yol --confirm ister (aşağıda).
	unchanged := map[string]bool{}
	var conflicting []string
	if stateKnown {
		var have []string
		for _, k := range keys {
			if existing[k] {
				have = append(have, k)
			}
		}
		if len(have) > 0 {
			if pres, perr := st.Read(ctx, project, have); perr == nil {
				for _, k := range have {
					if got, ok := pres.Values[k]; ok && got == sets[k] {
						unchanged[k] = true
					} else {
						conflicting = append(conflicting, k)
					}
				}
			} else {
				// Ön-okuma hatası: mevcut anahtarların değerleri DOĞRULANAMADI —
				// hepsi çakışma adayı sayılır (fail-closed; --confirm'siz körlemesine
				// üzerine yazılmaz).
				conflicting = append(conflicting, have...)
			}
		}
	}
	if len(unchanged) == len(sets) {
		for _, k := range keys {
			fmt.Fprintf(out, "  = %s (unchanged)\n", k)
		}
		fmt.Fprintf(out, "✓ Store already holds all %d keys with matching values for %s — nothing to import (idempotent no-op).\n", len(sets), project)
		return nil
	}

	// Yıkıcı re-run guard'ı: store'daki DAHA YENİ değerleri arşivin bayat
	// değerleriyle sessizce ezmek §8.2'nin uyardığı staleness tehlikesinin ta
	// kendisidir (ters yönde) → --confirm zorunlu. Store durumu hiç
	// belirlenemiyorsa da fail-closed davranılır.
	switch {
	case !stateKnown && !confirm:
		return clierr.New(clierr.Internal,
			"migrate import: store state is UNKNOWN (key-metadata list failed) — cannot prove the import will not overwrite newer store values; re-run with --confirm to force")
	case len(conflicting) > 0 && !confirm:
		sort.Strings(conflicting)
		return clierr.Newf(clierr.Internal,
			"migrate import: %d existing store keys hold DIFFERENT values than the archive: %v — importing would revert them to the archive's (possibly stale) values; re-run with --confirm if that is intended", len(conflicting), conflicting)
	}

	if err := st.Import(ctx, project, sets, store.WriteOpts{}); err != nil {
		return err
	}

	// Round-trip verify (§8.2): import edilen anahtarları geri oku + karşılaştır.
	res, err := st.Read(ctx, project, keys)
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

	// Per-key rapor (adlar + durum; değer ASLA). Store durumu bilinmiyorken
	// "new" İDDİA EDİLMEZ — anahtar üzerine yazılmış da olabilir.
	for _, k := range keys {
		switch {
		case unchanged[k]:
			fmt.Fprintf(out, "  = %s (unchanged, verified)\n", k)
		case !stateKnown:
			fmt.Fprintf(out, "  ~ %s (imported — prior store state unknown, verified)\n", k)
		case existing[k]:
			fmt.Fprintf(out, "  ~ %s (updated, verified)\n", k)
		default:
			fmt.Fprintf(out, "  + %s (new, verified)\n", k)
		}
	}
	fmt.Fprintf(out,
		"✓ Imported %d keys into the store for %s (one atomic epoch)\n"+
			"✓ Round-trip verified %d keys\n"+
			"Next (human): repoint .wapps.yaml to 'backend: store', soak 48 h, mark %s read-only (§8.2 step 7).\n",
		len(sets), project, len(sets), archivePath)
	return nil
}

// migrate export bayrakları.
var (
	migrateExportProject string
	migrateExportOut     string
	migrateExportConfirm bool
)

var migrateExportCmd = &cobra.Command{
	Use:   "export [--project <p>] --out <file>",
	Short: "Rollback step 1: store → age archive back-sync + verify — §8.2",
	Args:  cobra.NoArgs,
	Long: `Export-back for rollback (server-decrypt SPEC §8.2 — TWO steps, ORDER
MANDATORY):

 1. THIS verb: read all current values from the store (audited as
    value.read.bulk), write them to a legacy-shaped age archive at --out
    (typically this repo's secrets/all.enc.age), verify by decrypt+compare.
 2. Only then repoint .wapps.yaml back to 'backend: legacy-git'.

Rationale: writes land in the STORE during the soak window, so the untouched
archive is STALE — repointing without export-back silently serves old values.

ROLLBACK-COMPLETENESS (§8.2): GET /keys is filtered to the caller's read
grants on the Worker, so a partially-readable principal would silently write
an INCOMPLETE archive. Export therefore (a) requires a provably complete read
(root admin, or a project-wide 'read' grant whose keys include "*" with no
deny globs) and (b) cross-checks the read set against the keys of the
pre-existing --out archive — any key present before but absent now fails LOUD.

The archive is written 0600 via an atomic temp+rename; values never reach
stdout. Refuses a tombstoned --out target (archives are never modified after
tombstone) and an existing --out that cannot be decrypted at all. Requires
WAPPS_SECRETS_PASSPHRASE and --confirm; refused in agent mode.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		project, err := migrateProject(migrateExportProject)
		if err != nil {
			return err
		}
		return runMigrateExport(project, migrateExportOut, migrateExportConfirm, cmd.OutOrStdout())
	},
}

// runMigrateExport, export'un test-edilebilir çekirdeğidir.
func runMigrateExport(project, outPath string, confirm bool, out io.Writer) error {
	if outPath == "" {
		return clierr.New(clierr.Internal, "migrate export: --out <file> is required (the age-archive path to write, e.g. secrets/all.enc.age)")
	}
	if !confirm {
		return clierr.New(clierr.Internal,
			"refusing to write the rollback archive without --confirm (export-back overwrites --out with the store's current values)")
	}
	passphrase := os.Getenv("WAPPS_SECRETS_PASSPHRASE")
	if passphrase == "" {
		return clierr.New(clierr.Internal, "set WAPPS_SECRETS_PASSPHRASE (the legacy archive passphrase to seal the export)")
	}
	// Mevcut --out arşivi: (a) tombstone ASLA yeniden yazılmaz (§8.2: "Archives
	// are never modified after tombstone"); (b) HİÇ çözülemeyen dosya da ASLA
	// ezilmez — yanlış passphrase'le tombstone guard'ı sessizce delinirdi
	// (fail loud); (c) çözülen arşivin anahtar kümesi rollback-tamlık çapraz
	// kontrolü için saklanır.
	prevKeys := map[string]bool{}
	if enc, rerr := os.ReadFile(outPath); rerr == nil {
		vals, verr := rotation.LegacyArchiveFromBytes(enc).Values(passphrase)
		switch {
		case errors.Is(verr, rotation.ErrArchiveMigrated):
			return clierr.Wrapf(clierr.ArchiveMigrated, verr, "migrate export: %s is tombstoned", outPath)
		case verr != nil:
			return clierr.Wrapf(clierr.Internal, verr,
				"migrate export: existing %s cannot be decrypted with WAPPS_SECRETS_PASSPHRASE — refusing to overwrite a file whose contents (tombstone? foreign archive?) cannot be inspected; fix the passphrase or move the file aside", outPath)
		default:
			for k := range vals {
				prevKeys[k] = true
			}
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return clierr.Wrapf(clierr.Internal, rerr, "migrate export: read existing %s", outPath)
	}

	st, err := openStore(&config.WappsYAML{Project: project})
	if err != nil {
		return err
	}
	ctx := context.Background()

	// Rollback-tamlık kanıtı (§8.2): Worker GET /keys'i read grant'ine FİLTRELER
	// (§4.3.3) — kısmi-okuyan bir principal sessizce eksik arşiv üretirdi.
	if err := exportCompleteReadProof(ctx, st, project); err != nil {
		return err
	}

	res, err := st.Read(ctx, project, nil)
	if err != nil {
		return err
	}
	if len(res.Values) == 0 {
		return clierr.Newf(clierr.Internal, "migrate export: the store returned no readable keys for %s — nothing to export", project)
	}

	// Rollback-tamlık çapraz kontrolü (§8.2): önceki arşivde olup okuma
	// kümesinde OLMAYAN anahtar = policy-filtreli okuma ya da store silmesi —
	// ikisi de sessizce eksik bir rollback arşivi üretir → fail LOUD (arşiv
	// yazılmadan ÖNCE).
	var missing []string
	for k := range prevKeys {
		if _, ok := res.Values[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return clierr.Newf(clierr.Internal,
			"migrate export: NOT rollback-complete — %d keys exist in the current %s but are ABSENT from the store read (%d readable): %v; cause is a policy-filtered read or a store deletion — widen the read grant, or move the old archive aside if the deletions are intentional", len(missing), outPath, len(res.Values), missing)
	}

	archiveJSON, err := valuesToArchiveJSON(res.Values)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: build archive")
	}
	if dir := filepath.Dir(outPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "migrate export: create out dir")
		}
	}
	if err := ageutil.EncryptWriteAtomic(outPath, archiveJSON, passphrase); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: write archive")
	}

	// Verify: yazılan arşivi geri oku + çöz + karşılaştır (count + değerler).
	enc, err := os.ReadFile(outPath)
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
		"✓ Exported %d keys from the store (%s) into %s and verified (read-completeness proven)\n"+
			"Next (human): commit the archive, THEN repoint .wapps.yaml to 'backend: legacy-git' (§8.2 rollback order).\n",
		len(res.Values), project, outPath)
	return nil
}

// storeWhoami, rollback-tamlık kanıtı için opsiyonel store yüzeyidir
// (*store.WorkerStore uygular; testte fake de uygular).
type storeWhoami interface {
	Whoami(ctx context.Context) (*store.WhoamiResult, error)
}

// exportCompleteReadProof, export'un okuma kümesinin TÜM projeyi kapsadığını
// KANITLAR (§8.2 rollback-complete): Worker GET /keys'i principal'ın read
// grant'ine filtrelediği için (§4.3.3) tautolojik "okuduğumu doğruladım"
// yetmez. Kabul edilen kanıt: root admin, ya da projeyi kapsayan + keys'i
// deny-glob'suz "*" içeren + read verb'lü bir grant. Kanıt yoksa fail LOUD —
// eksik bir rollback arşivi sessizce üretilmez.
func exportCompleteReadProof(ctx context.Context, st store.Store, project string) error {
	w, ok := st.(storeWhoami)
	if !ok {
		return clierr.New(clierr.Internal,
			"migrate export: store client cannot prove read completeness (no whoami surface) — refusing to write a possibly-partial rollback archive")
	}
	who, err := w.Whoami(ctx)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "migrate export: whoami (read-completeness proof)")
	}
	if who.IsRootAdmin {
		return nil
	}
	for _, g := range who.Grants {
		if grantCoversProjectReadFully(g, project) {
			return nil
		}
	}
	return clierr.Newf(clierr.Internal,
		"migrate export: principal %q holds no PROJECT-WIDE read grant for %s (keys must include \"*\" with no deny globs) — GET /keys would be policy-filtered and the rollback archive silently INCOMPLETE; run as a root admin or widen the read grant first", who.Principal, project)
}

// grantCoversProjectReadFully, bir kuralın verilen projenin TÜM anahtarlarını
// okumaya yettiğini muhafazakâr biçimde sınar: proje tam ad ya da "*" (Worker
// glob'u burada yeniden UYGULANMAZ — sapma riski yerine false-negative fail
// loud tercih edilir), verbs "read"/"*" içerir, keys deny-glob'suz "*" içerir.
func grantCoversProjectReadFully(g store.Rule, project string) bool {
	projectOK := false
	for _, p := range g.Projects {
		if p == project || p == "*" {
			projectOK = true
			break
		}
	}
	if !projectOK {
		return false
	}
	verbOK := false
	for _, v := range g.Verbs {
		if v == "read" || v == "*" {
			verbOK = true
			break
		}
	}
	if !verbOK {
		return false
	}
	star := false
	for _, k := range g.Keys {
		if strings.HasPrefix(k, "!") {
			return false // aynı kural içi deny-glob → tamlık kanıtı düşer (§4.3)
		}
		if k == "*" {
			star = true
		}
	}
	return star
}

// migrate tombstone bayrakları.
var (
	tombstoneProject string
	tombstoneConfirm bool
)

var migrateTombstoneCmd = &cobra.Command{
	Use:   "tombstone [--project <p>]",
	Short: "Overwrite the legacy archive with a __MIGRATED__ tombstone — §8.2 step 8",
	Args:  cobra.NoArgs,
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
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Ajan modunda reddet: gerçek bir arşivi emekliye ayırmak insan kararı.
		if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
			return err
		}
		project, err := migrateProject(tombstoneProject)
		if err != nil {
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
	migrateImportCmd.Flags().StringVar(&migrateImportProject, "project", "", "target store project (default: .wapps.yaml 'project:')")
	migrateImportCmd.Flags().BoolVar(&migrateImportDryRun, "dry-run", false, "list what would move (per-key) without writing to the store")
	migrateImportCmd.Flags().BoolVar(&migrateImportConfirm, "confirm", false, "confirm overwriting existing store keys whose values differ from the archive's")
	migrateExportCmd.Flags().StringVar(&migrateExportProject, "project", "", "source store project (default: .wapps.yaml 'project:')")
	migrateExportCmd.Flags().StringVar(&migrateExportOut, "out", "", "age-archive file to write (e.g. secrets/all.enc.age)")
	migrateExportCmd.Flags().BoolVar(&migrateExportConfirm, "confirm", false, "confirm the destructive archive write from store values")
	migrateTombstoneCmd.Flags().StringVar(&tombstoneProject, "project", "", "project named in the tombstone sentinel (default: .wapps.yaml 'project:')")
	migrateTombstoneCmd.Flags().BoolVar(&tombstoneConfirm, "confirm", false, "confirm the destructive legacy-archive overwrite")
	SecretsCmd.AddCommand(migrateCmd, rotateValuesCmd)
}
