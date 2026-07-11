package secrets

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/trust"
	"github.com/wappsdev/wapps-cli/internal/witness"
)

// wapps dr — felaket kurtarma verb'leri (SPEC §9.5). dr verify HERHANGİ BİR sırla
// gerekmez (yapı+imza doğrular, private escrow key GEREKMEZ) ve Cloudflare tamamen
// erişilemezken / hava-boşluklu bir snapshot'a karşı çalışabilir. dr restore
// TTY-ONLY bir seremonidir (ajan-modu reddedilir): 2-of-3 Shamir payından escrow
// özel anahtarını yeniden kurar, snapshot'ı uçtan uca doğrular, escrow wrap'lerini
// açar. Canlı B2 read + estate replay İNSAN-elidir; bu araç doğrulama+reconstruct
// çekirdeğini sürer.

// DrCmd, `wapps dr` grup komutudur.
var DrCmd = &cobra.Command{
	Use:   "dr",
	Short: "Disaster recovery: verify / restore the escrow snapshot (§9.5)",
	Long: `Disaster recovery against the NON-Cloudflare, object-locked B2 escrow snapshot
(SPEC §9.5). The escrow subsystem is the answer to two failures: LOSS of Cloudflare
(availability) and LOSS of TRUST in Cloudflare (freeze/rollback). dr verify runs the
full §9.3.2 check suite from LOCAL pins only; dr restore is the true-disaster,
TTY-only ceremony that reconstructs the escrow key from 2-of-3 Shamir shares.`,
}

var (
	drSnapshotDir   string
	drRequireCanary bool
)

var drVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run the §9.3.2 verification suite against the escrow snapshot (read-only)",
	Long: `Run the full §9.3.2 verification suite (writer/roster signatures vs pinned
roots, blob content-addresses, manifest chain continuity, escrow-wrap presence,
audit chain continuity, pointer-event density/consistency) against the B2 escrow
snapshot — or a local air-gapped copy (--snapshot). Uses ONLY local pins; needs
NO escrow private key; runnable with Cloudflare entirely unreachable (§9.5.1).`,
	RunE: runDrVerify,
}

func runDrVerify(cmd *cobra.Command, _ []string) error {
	pins, err := loadLocalPins()
	if err != nil {
		return err
	}
	reader, source, err := resolveEscrowReader()
	if err != nil {
		return err
	}
	cfg := witness.Config{Pins: pins, RequireCanary: drRequireCanary, Now: time.Now}
	res, err := witness.Verify(context.Background(), reader, cfg)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "escrow verification FAILED (%s)", source)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ escrow snapshot VERIFIED (%s)\n", source)
	fmt.Fprintf(out, "  trust head: admin_epoch=%d sha=%s\n", res.TrustHead.AdminEpoch, short(res.TrustHead.TrustSha256))
	projects := make([]string, 0, len(res.ProjectHeads))
	for p := range res.ProjectHeads {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for _, p := range projects {
		h := res.ProjectHeads[p]
		fmt.Fprintf(out, "  %-20s epoch=%d manifest=%s\n", p, h.Epoch, short(h.ManifestSha256))
	}
	return nil
}

var (
	drRestoreProject string
	drRestorePath    string
	drRestoreConfirm bool
	drRestoreShares  []string
)

var drRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "TTY-only DR ceremony: reconstruct a project from escrow (§9.5.2/§9.5.3)",
	Long: `TRUE-disaster restore ceremony (SPEC §9.5.2). TTY-ONLY — REFUSED under agent
mode. Reconstructs the escrow private key from ANY 2-of-3 Shamir shares on an
air-gapped machine, verifies the escrow snapshot end-to-end (dr verify semantics),
then unwraps escrow DEK wraps and reconstructs the project's current pointer from
the append-only representation (§9.5.3). Both paths (A restore-in-place, B full
rebuild) issue an epoch-reset record; the live R2 replay + estate re-provision are
the human half of the ceremony. Every restored value enters the rotation worklist
(§9.5.5).`,
	RunE: runDrRestore,
}

func runDrRestore(cmd *cobra.Command, _ []string) error {
	// TTY-only: ajan-modunda ASLA (§9.5.2). agentmode.PolicyTTY guard'ı.
	if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
		return err
	}
	if drRestoreProject == "" {
		return clierr.New(clierr.Internal, "dr restore: --project is required")
	}
	reason := witness.RestorePathA
	switch drRestorePath {
	case "", "a":
		reason = witness.RestorePathA
	case "b":
		reason = witness.RestorePathB
	default:
		return clierr.Newf(clierr.Internal, "dr restore: --path must be a (restore-in-place) or b (full rebuild)")
	}
	if !drRestoreConfirm {
		return clierr.New(clierr.NotAvailable,
			"dr restore is a destructive TTY ceremony; re-run with --confirm once the air-gapped machine holds ≥2 Shamir shares and the escrow snapshot is reachable (--snapshot or live B2)")
	}
	if len(drRestoreShares) < 2 {
		return clierr.New(clierr.NotAvailable,
			"dr restore needs ≥2 Shamir share files (--share PATH --share PATH); the assembled escrow key is NEVER persisted (§9.1)")
	}

	// Payları oku + escrow özel anahtarını yeniden kur (asla diske yazılmaz).
	shares, err := readShares(drRestoreShares)
	if err != nil {
		return err
	}
	escrowID, err := witness.ReconstructEscrowKey(shares)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "reconstruct escrow key from shares")
	}

	pins, err := loadLocalPins()
	if err != nil {
		return err
	}
	reader, source, err := resolveEscrowReader()
	if err != nil {
		return err
	}
	res, err := witness.Verify(context.Background(), reader, witness.Config{Pins: pins, Now: time.Now})
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "refuse to restore an UNVERIFIED snapshot (%s)", source)
	}
	restored, err := witness.Restore(context.Background(), reader, res, drRestoreProject, escrowID, reason, time.Now())
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "restore %s", drRestoreProject)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ RECONSTRUCTED %s from escrow (%s, %s)\n", restored.Project, source, reason)
	fmt.Fprintf(out, "  current pointer: epoch=%d manifest=%s\n", restored.Current.Epoch, short(restored.Current.ManifestSha256))
	fmt.Fprintf(out, "  recovered %d value(s) into ceremony memory (NEVER printed; all enter the rotation worklist §9.5.5)\n", len(restored.Values))
	resetBody, _ := restored.EpochReset.Marshal()
	fmt.Fprintf(out, "\nepoch-reset record to be signed by ≥M root keys (§9.5.4):\n%s\n", resetBody)
	fmt.Fprintln(out, "\nNEXT (human half): sign the epoch-reset record with ≥M root keys, replay objects into R2, write the reconstructed current pointer, rebuild the D1 index, then rotate every recovered value.")
	return nil
}

var drRepinCmd = &cobra.Command{
	Use:   "repin-genesis",
	Short: "Re-pin a client's genesis trust root from a verified snapshot (§4.10)",
	Long: `Genesis re-pin ceremony (SPEC §4.10 / §9.5.3 Path B quorum-loss break-glass).
Writes a fresh roots.json genesis pin from a verified escrow snapshot's trust head.
TTY-only. Use only under the out-of-band quorum-loss recovery procedure — a
mismatched compiled-vs-local genesis pin otherwise routes to this ceremony
(TRUST_PIN_CONFLICT).`,
	RunE: runDrRepin,
}

func runDrRepin(cmd *cobra.Command, _ []string) error {
	if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
		return err
	}
	pins, err := loadLocalPins()
	if err != nil {
		return err
	}
	reader, source, err := resolveEscrowReader()
	if err != nil {
		return err
	}
	res, err := witness.Verify(context.Background(), reader, witness.Config{Pins: pins, Now: time.Now})
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "refuse to re-pin from an UNVERIFIED snapshot (%s)", source)
	}
	newGenesis := trust.Pin{AdminEpoch: res.TrustHead.AdminEpoch, SHA256: res.TrustHead.TrustSha256}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "verified trust head (%s): admin_epoch=%d sha=%s\n", source, newGenesis.AdminEpoch, newGenesis.SHA256)
	fmt.Fprintln(out, "\nThis re-pin ADVANCES the genesis root of trust — a full re-key event. Confirm out-of-band with ≥M root-key holders, then run:")
	fmt.Fprintf(out, "  wapps secrets trust-repo   # after writing roots.json genesis = {admin_epoch:%d, sha256:%q}\n", newGenesis.AdminEpoch, newGenesis.SHA256)
	return nil
}

var drVerifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "VM hourly cron: verify escrow + publish witness head + alert (§9.3)",
	Long: `The VM (ci.meapps.dev) hourly verifier entry (SPEC §9.3): verify the escrow
snapshot, and on success PUBLISH the per-project witness head + trust head to the
NON-object-locked NON-Cloudflare witness bucket; on failure or staleness ALERT
(Discord, A5). The live B2 read/witness-write keys + the VM cron deploy are
DEFERRED (human/infra); this is the runnable entry the cron invokes.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return clierr.New(clierr.NotAvailable,
			"dr verifier is the VM hourly cron entry (§9.3): it needs the read-only B2 escrow key + the witness-bucket write key + WITNESS_ORIGIN, provisioned on ci.meapps.dev — live B2 buckets + VM cron deploy are DEFERRED (human/infra). The verify+publish+alert core is internal/witness (RunOnce).")
	},
}

// --- yardımcılar ------------------------------------------------------------

// loadLocalPins, YEREL trust pin deposunu (roots.json) yükler; yoksa derlenmiş
// genesis'ten bootstrap eder. dr verify Cloudflare'e ASLA güvenmez (§9.5.1).
func loadLocalPins() (*trust.PinStore, error) {
	path, err := trust.DefaultPinPath()
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "resolve pin path")
	}
	if ps, err := trust.LoadPinStore(path); err == nil {
		return ps, nil
	}
	if g, ok := trust.CompiledGenesis(); ok {
		return trust.NewPinStore(g), nil
	}
	return nil, clierr.New(clierr.SigInvalid, "no trust pins and no compiled genesis (dr verify needs local pins §4)")
}

// resolveEscrowReader, escrow Reader'ını çözer: --snapshot verilirse yerel dizin
// (hava-boşluklu, §9.5.1); aksi halde canlı B2 (env config). Canlı B2 config
// eksikse NotAvailable (canlı B2 DEFERRED). source = insan-okunur kaynak etiketi.
func resolveEscrowReader() (witness.Reader, string, error) {
	if drSnapshotDir != "" {
		if fi, err := os.Stat(drSnapshotDir); err != nil || !fi.IsDir() {
			return nil, "", clierr.Newf(clierr.Internal, "--snapshot %q is not a directory", drSnapshotDir)
		}
		return witness.DirReader{Root: drSnapshotDir}, "snapshot " + drSnapshotDir, nil
	}
	cfg, ok := escrowS3ConfigFromEnv()
	if !ok {
		return nil, "", clierr.New(clierr.NotAvailable,
			"no escrow source: pass --snapshot <dir> for an air-gapped copy, or set B2_ENDPOINT/B2_REGION/B2_BUCKET/B2_READ_KEY_ID/B2_READ_KEY for live B2 (live bucket DEFERRED)")
	}
	return witness.NewS3Store(cfg), "live B2 " + cfg.Bucket, nil
}

// escrowS3ConfigFromEnv, READ-ONLY B2 escrow config'ini env'den çözer (§9.3.1
// read-only key). Herhangi biri eksikse ok=false.
func escrowS3ConfigFromEnv() (witness.S3Config, bool) {
	get := os.Getenv
	cfg := witness.S3Config{
		Endpoint:  get("B2_ENDPOINT"),
		Region:    get("B2_REGION"),
		Bucket:    get("B2_BUCKET"),
		KeyID:     get("B2_READ_KEY_ID"),
		SecretKey: get("B2_READ_KEY"),
	}
	if cfg.Endpoint == "" || cfg.Region == "" || cfg.Bucket == "" || cfg.KeyID == "" || cfg.SecretKey == "" {
		return witness.S3Config{}, false
	}
	return cfg, true
}

// readShares, verilen dosya yollarından Shamir paylarını okur (her dosya bir pay).
func readShares(paths []string) ([][]byte, error) {
	out := make([][]byte, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, clierr.Wrapf(clierr.Internal, err, "read share %s", p)
		}
		out = append(out, decodeShare(b))
	}
	return out, nil
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

func init() {
	drVerifyCmd.Flags().StringVar(&drSnapshotDir, "snapshot", "", "verify a local air-gapped snapshot dir instead of live B2 (§9.5.1)")
	drVerifyCmd.Flags().BoolVar(&drRequireCanary, "require-canary", false, "also require a WAPPS_ESCROW_CANARY entry in every project head (§9.3.2g presence)")

	drRestoreCmd.Flags().StringVar(&drSnapshotDir, "snapshot", "", "restore from a local air-gapped snapshot dir instead of live B2")
	drRestoreCmd.Flags().StringVar(&drRestoreProject, "project", "", "project to reconstruct")
	drRestoreCmd.Flags().StringVar(&drRestorePath, "path", "a", "restore path: a (restore-in-place) | b (full rebuild)")
	drRestoreCmd.Flags().BoolVar(&drRestoreConfirm, "confirm", false, "confirm the destructive TTY restore ceremony")
	drRestoreCmd.Flags().StringArrayVar(&drRestoreShares, "share", nil, "Shamir share file (repeat ≥2; assembled key NEVER persisted)")

	drRepinCmd.Flags().StringVar(&drSnapshotDir, "snapshot", "", "verify a local air-gapped snapshot dir instead of live B2")

	DrCmd.AddCommand(drVerifyCmd, drRestoreCmd, drRepinCmd, drVerifierCmd)
}
