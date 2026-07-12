package secrets

// wapps dr — felaket kurtarma verb'leri (server-decrypt SPEC §8.4).
//
//	dr verify   Ciphertext replikasının (B2 snapshot) yapısal bütünlüğünü doğrular:
//	            current pointer → manifest hash zinciri → blob içerik-adresleri.
//	            Hiçbir sır gerektirmez; Cloudflare tamamen erişilemezken çalışır.
//	dr restore  TTY-ONLY seremoni: ≥2 MASTER_KEK Shamir payı + bir B2 snapshot'ından
//	            MASTER_KEK'i yeniden kurar, per-proje KEK türetir (HKDF §2.3), DEK'leri
//	            açar (WKW1 §2.4), blob'ları çözer (WSB1 §2.1) ve 0600 env dosyası yazar.
//	            Değerler ASLA yazdırılmaz. Sıfır Cloudflare bağımlılığı.
//
// Canlı B2 okuma anahtarlarının provisioning'i insan-elidir; her iki verb de yerel
// (hava-boşluklu) bir snapshot dizininde çalışır (`rclone sync b2:… <dir>` sonrası).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// DrCmd, `wapps dr` grup komutudur.
var DrCmd = &cobra.Command{
	Use:   "dr",
	Short: "Disaster recovery against the B2 ciphertext replica (§8.4)",
	Long: `Disaster recovery against the NON-Cloudflare, append-only B2 replica (SPEC §8.4).
The replica holds ONLY ciphertext + metadata — MASTER_KEK never reaches B2, so the
replica alone yields nothing. dr verify is a structural integrity check; dr restore
is the true-disaster TTY ceremony (Shamir shares + snapshot → plaintext env files).`,
}

// --- snapshot v2 şekilleri (worker/src/manifest.ts paritesi) --------------------

const (
	schemaCurrentPointer = "wapps-secrets/current/v1"
	schemaDataManifest   = "wapps-secrets/data-manifest/v2"
)

type snapshotPointer struct {
	Schema         string `json:"schema"`
	Project        string `json:"project"`
	Epoch          uint64 `json:"epoch"`
	ManifestSha256 string `json:"manifestSha256"`
}

type snapshotWrap struct {
	Recipient string `json:"recipient"`
	Kid       string `json:"kid"`
	Wrap      string `json:"wrap"`
}

type snapshotEntry struct {
	KeyName    string       `json:"keyName"`
	KeyVersion uint64       `json:"keyVersion"`
	BlobHash   string       `json:"blobHash"`
	Wrap       snapshotWrap `json:"wrap"`
}

type snapshotManifest struct {
	Schema  string          `json:"schema"`
	Project string          `json:"project"`
	Epoch   uint64          `json:"epoch"`
	Entries []snapshotEntry `json:"entries"`
}

// loadSnapshotProject, snapshot dizininden bir projenin current head'ini yükler
// ve zincir bütünlüğünü doğrular (pointer→manifest hash, şema, proje eşleşmesi).
func loadSnapshotProject(dir, project string) (*snapshotManifest, *snapshotPointer, error) {
	curRaw, err := os.ReadFile(filepath.Join(dir, "secrets", project, "current"))
	if err != nil {
		return nil, nil, clierr.Wrapf(clierr.Internal, err, "snapshot: read current pointer for %s", project)
	}
	var ptr snapshotPointer
	if err := json.Unmarshal(curRaw, &ptr); err != nil || ptr.Schema != schemaCurrentPointer {
		return nil, nil, clierr.Newf(clierr.Internal, "snapshot: current pointer for %s malformed", project)
	}
	manRaw, err := os.ReadFile(filepath.Join(dir, "secrets", project, "manifests", fmt.Sprintf("%d.json", ptr.Epoch)))
	if err != nil {
		return nil, nil, clierr.Wrapf(clierr.Internal, err, "snapshot: read manifest epoch %d for %s", ptr.Epoch, project)
	}
	sum := sha256.Sum256(manRaw)
	if hex.EncodeToString(sum[:]) != strings.ToLower(ptr.ManifestSha256) {
		return nil, nil, clierr.Newf(clierr.BlobHashMismatch, "snapshot: pointer/manifest hash mismatch for %s (tamper or partial replica)", project)
	}
	var man snapshotManifest
	if err := json.Unmarshal(manRaw, &man); err != nil || man.Schema != schemaDataManifest {
		return nil, nil, clierr.Newf(clierr.Internal, "snapshot: manifest for %s malformed/unsupported schema", project)
	}
	if man.Project != project || man.Epoch != ptr.Epoch {
		return nil, nil, clierr.Newf(clierr.Internal, "snapshot: manifest project/epoch mismatch for %s", project)
	}
	return &man, &ptr, nil
}

// snapshotProjects, snapshot dizinindeki proje adlarını (secrets/<p>/) döner.
func snapshotProjects(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "secrets"))
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "snapshot: list %s/secrets", dir)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// --- dr verify -------------------------------------------------------------------

var drSnapshotDir string

var drVerifyCmd = &cobra.Command{
	Use:   "verify --snapshot <dir>",
	Short: "Structural integrity check of the B2 replica snapshot (read-only, §8.4)",
	Long: `Verify the ciphertext replica: for every project, current pointer → manifest
hash chain, manifest schema, and every referenced blob's content address. Uses NO
secrets and NO Cloudflare — runnable against an air-gapped snapshot copy.
(Live-B2 lag comparison alerts run in the Worker's nightly reconcile, §8.3.)`,
	RunE: runDrVerify,
}

func runDrVerify(cmd *cobra.Command, _ []string) error {
	if drSnapshotDir == "" {
		return clierr.New(clierr.NotAvailable,
			"dr verify runs against a local snapshot copy of the B2 replica: sync it first (rclone/b2 CLI, read-only key) and pass --snapshot <dir>")
	}
	projects, err := snapshotProjects(drSnapshotDir)
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	for _, project := range projects {
		man, ptr, err := loadSnapshotProject(drSnapshotDir, project)
		if err != nil {
			return err
		}
		for _, e := range man.Entries {
			blob, berr := os.ReadFile(filepath.Join(drSnapshotDir, "secrets", project, "blobs", e.BlobHash))
			if berr != nil {
				return clierr.Wrapf(clierr.Internal, berr, "snapshot: blob missing for %s/%s", project, e.KeyName)
			}
			if verr := cryptoid.VerifyBlobHash(blob, e.BlobHash); verr != nil {
				return clierr.Wrapf(clierr.BlobHashMismatch, verr, "snapshot: blob content-address mismatch for %s/%s", project, e.KeyName)
			}
			if e.Wrap.Recipient != cryptoid.WrapRecipient {
				return clierr.Newf(clierr.Internal, "snapshot: unsupported wrap recipient on %s/%s", project, e.KeyName)
			}
		}
		fmt.Fprintf(w, "  %-20s epoch=%d keys=%d manifest=%s\n", project, ptr.Epoch, len(man.Entries), short(ptr.ManifestSha256))
	}
	fmt.Fprintf(w, "✓ snapshot VERIFIED (%d project(s), %s)\n", len(projects), drSnapshotDir)
	return nil
}

// --- dr restore ------------------------------------------------------------------

var (
	drRestoreProject string
	drRestoreOut     string
	drRestoreConfirm bool
	drRestoreShares  []string
)

var drRestoreCmd = &cobra.Command{
	Use:   "restore --project <p> --snapshot <dir> --share <file> --share <file> --out <env-file>",
	Short: "TTY-only DR ceremony: Shamir shares + snapshot → 0600 env file (§8.4)",
	Long: `TRUE-disaster restore (SPEC §8.4). TTY-ONLY — REFUSED under agent mode.
Reconstructs MASTER_KEK from ANY 2-of-3 Shamir share files (hex), verifies the
snapshot chain, derives the project KEK (HKDF §2.3), unwraps every DEK (WKW1 §2.4),
opens every blob (WSB1 §2.1) and writes a 0600 env file. The assembled MASTER_KEK
and the plaintext values are NEVER printed and never persisted beyond --out.
Works with zero Cloudflare availability.`,
	RunE: runDrRestore,
}

func runDrRestore(cmd *cobra.Command, _ []string) error {
	// TTY-only seremoni: ajan modunda ASLA (§7.1 dr restore REFUSED).
	if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
		return err
	}
	if drRestoreProject == "" || drSnapshotDir == "" {
		return clierr.New(clierr.Internal, "dr restore: --project and --snapshot are required")
	}
	if drRestoreOut == "" {
		return clierr.New(clierr.Internal, "dr restore: --out <env-file> is required (values are NEVER printed)")
	}
	if len(drRestoreShares) < 2 {
		return clierr.New(clierr.NotAvailable,
			"dr restore needs ≥2 Shamir share files (--share PATH --share PATH); the assembled MASTER_KEK is NEVER persisted")
	}
	if !drRestoreConfirm {
		return clierr.New(clierr.NotAvailable,
			"dr restore is a disaster ceremony; re-run with --confirm once the air-gapped machine holds ≥2 shares and the snapshot copy")
	}
	return restoreProjectFromSnapshot(cmd.OutOrStdout(), drSnapshotDir, drRestoreProject, drRestoreShares, drRestoreOut)
}

// restoreProjectFromSnapshot, restore seremonisinin çekirdeğidir (guard'lar
// runDrRestore'da): paylar → MASTER_KEK → KEK → DEK → plaintext → 0600 dosya.
func restoreProjectFromSnapshot(w io.Writer, snapshotDir, project string, sharePaths []string, outPath string) error {
	shares, err := readShareFiles(sharePaths)
	if err != nil {
		return err
	}
	master, err := cryptoid.ShamirCombine(shares)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "reconstruct MASTER_KEK from shares")
	}
	if len(master) != 32 {
		return clierr.Newf(clierr.Internal, "reconstructed MASTER_KEK is %d bytes, want 32 (wrong/mismatched shares?)", len(master))
	}
	kid, err := cryptoid.KekKid(master)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "derive kid")
	}

	man, ptr, err := loadSnapshotProject(snapshotDir, project)
	if err != nil {
		return err
	}

	var lines []string
	for _, e := range man.Entries {
		if e.Wrap.Kid != kid {
			return clierr.Newf(clierr.Internal,
				"wrap kid %s on %s does not match the reconstructed key's kid %s — wrong MASTER_KEK generation (older shares? see §2.5 rotation)", e.Wrap.Kid, e.KeyName, kid)
		}
		wrapBytes, derr := base64.StdEncoding.DecodeString(e.Wrap.Wrap)
		if derr != nil {
			return clierr.Newf(clierr.Internal, "wrap for %s not base64", e.KeyName)
		}
		blob, berr := os.ReadFile(filepath.Join(snapshotDir, "secrets", project, "blobs", e.BlobHash))
		if berr != nil {
			return clierr.Wrapf(clierr.Internal, berr, "blob missing for %s", e.KeyName)
		}
		if verr := cryptoid.VerifyBlobHash(blob, e.BlobHash); verr != nil {
			return clierr.Wrapf(clierr.BlobHashMismatch, verr, "blob content-address mismatch for %s", e.KeyName)
		}
		slot := cryptoid.Slot{Project: project, KeyName: e.KeyName, KeyVersion: e.KeyVersion}
		dek, uerr := cryptoid.UnwrapDEKWithKEK(master, project, slot, wrapBytes)
		if uerr != nil {
			return clierr.Wrapf(clierr.Internal, uerr, "DEK unwrap failed for %s (tamper or key mismatch)", e.KeyName)
		}
		pt, oerr := cryptoid.OpenBlob(blob, dek, slot)
		if oerr != nil {
			return clierr.Wrapf(clierr.Internal, oerr, "blob open failed for %s", e.KeyName)
		}
		lines = append(lines, e.KeyName+"="+string(pt))
	}

	if err := writeRestoredEnvFile(outPath, lines); err != nil {
		return err
	}
	fmt.Fprintf(w, "✓ RESTORED %s (epoch %d): %d value(s) → %s (0600; values never printed)\n",
		project, ptr.Epoch, len(lines), outPath)
	fmt.Fprintln(w, "NEXT (human half): re-provision the estate from this file, then ROTATE every restored value (rotate-plan doctrine §2.5).")
	return nil
}

// readShareFiles, hex-kodlu Shamir pay dosyalarını okur (boşluk/yenisatır tolere).
func readShareFiles(paths []string) ([][]byte, error) {
	out := make([][]byte, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, clierr.Wrapf(clierr.Internal, err, "read share %s", p)
		}
		clean := strings.Join(strings.Fields(string(raw)), "")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return nil, clierr.Newf(clierr.Internal, "share %s is not hex", p)
		}
		out = append(out, b)
	}
	return out, nil
}

// writeRestoredEnvFile, KEY=value satırlarını 0600 atomik yazar (asla stdout'a değil).
func writeRestoredEnvFile(path string, lines []string) error {
	tmp := path + ".tmp"
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "write %s", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return clierr.Wrapf(clierr.Internal, err, "finalize %s", path)
	}
	return nil
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

// --- dr split / combine: MASTER_KEK Shamir offline custody (server-decrypt DR) ---
//
// Server-decrypt store'un TEK kök sırrı MASTER_KEK'tir (canlı wrangler Worker secret'ı).
// split, onu N-of-M Shamir payına böler (offline saklamak için); combine, ≥threshold
// paydan geri kurar (kaybolursa `wrangler secret put MASTER_KEK` ile yeniden kurmak için).
// İkisi de TTY-only: MASTER_KEK bir AI oturumundan ASLA geçmemeli.

var (
	drSplitParts     int
	drSplitThreshold int
	drSplitOutDir    string
	drSplitMasterHex string
	drSplitKey       string
)

var drSplitCmd = &cobra.Command{
	Use:   "split",
	Short: "TTY-only: split the store's MASTER_KEK into N-of-M Shamir shares for offline custody",
	Long: `split TAKES the store's MASTER_KEK (64-hex) and writes {--parts} Shamir share
files (hex, 0600) such that ANY {--threshold} reconstruct it (dr combine) and fewer
reveal NOTHING. Move each share to a SEPARATE offline place (paper safe / YubiKey /
trusted person).

MASTER_KEK source (NEVER printed):
  default        reads --key (SECRETSGATE_MASTER_KEK_PROD) from this repo's age archive
                 (needs WAPPS_SECRETS_PASSPHRASE; use -c/--project to point at the archive)
  --master-hex   supply the 64-hex value explicitly

Refused in agent mode — the MASTER_KEK must never reach an AI transcript.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
			return err
		}
		if drSplitOutDir == "" {
			return clierr.New(clierr.Internal, "dr split: --out-dir <dir> is required (0600 share files land there)")
		}
		if drSplitThreshold < 2 || drSplitParts < drSplitThreshold {
			return clierr.Newf(clierr.Internal, "dr split: need parts >= threshold >= 2 (got parts=%d threshold=%d)", drSplitParts, drSplitThreshold)
		}
		masterHex := strings.TrimSpace(drSplitMasterHex)
		if masterHex == "" {
			vals, err := ArchiveValues(drSplitKey)
			if err != nil {
				return clierr.Wrapf(clierr.Internal, err, "read %s from archive", drSplitKey)
			}
			masterHex = strings.TrimSpace(vals[drSplitKey])
			if masterHex == "" {
				return clierr.Newf(clierr.NotAvailable, "dr split: %s not found in the archive — pass --master-hex, or check WAPPS_SECRETS_PASSPHRASE and -c/--project", drSplitKey)
			}
		}
		master, err := hex.DecodeString(masterHex)
		if err != nil || len(master) != 32 {
			return clierr.Newf(clierr.Internal, "dr split: MASTER_KEK must be 64 hex chars (32 bytes)")
		}
		kid, err := cryptoid.KekKid(master)
		if err != nil {
			return clierr.Wrapf(clierr.Internal, err, "derive kid")
		}
		shares, err := cryptoid.ShamirSplit(master, drSplitParts, drSplitThreshold, rand.Reader)
		if err != nil {
			return clierr.Wrapf(clierr.Internal, err, "shamir split")
		}
		// Round-trip sağlaması: ilk {threshold} pay gerçekten MASTER_KEK'e geri dönmeli.
		if back, cerr := cryptoid.ShamirCombine(shares[:drSplitThreshold]); cerr != nil || !bytes.Equal(back, master) {
			return clierr.New(clierr.Internal, "dr split: round-trip check FAILED — shares would not reconstruct (aborted, nothing written)")
		}
		if err := os.MkdirAll(drSplitOutDir, 0o700); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "create out-dir")
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "MASTER_KEK kid: %s  (this is the key these shares reconstruct — verify against the live Worker)\n", kid)
		for i, s := range shares {
			p := filepath.Join(drSplitOutDir, fmt.Sprintf("wapps-master-share-%d-of-%d.hex", i+1, drSplitParts))
			if werr := os.WriteFile(p, []byte(hex.EncodeToString(s)+"\n"), 0o600); werr != nil {
				return clierr.Wrapf(clierr.Internal, werr, "write share %d", i+1)
			}
			fmt.Fprintf(w, "  wrote %s\n", p)
		}
		for i := range master {
			master[i] = 0 // best-effort wipe
		}
		fmt.Fprintf(w, "\n✓ %d shares written (any %d reconstruct). NOW:\n", drSplitParts, drSplitThreshold)
		fmt.Fprintf(w, "  1) move each file to a SEPARATE offline place (paper safe / YubiKey / trusted person)\n")
		fmt.Fprintf(w, "  2) delete %s afterwards. NEVER commit shares to git or store them together.\n", drSplitOutDir)
		return nil
	},
}

var (
	drCombineShares []string
	drCombineOut    string
)

var drCombineCmd = &cobra.Command{
	Use:   "combine",
	Short: "TTY-only: reconstruct MASTER_KEK from >=threshold Shamir shares (to re-set the Worker secret)",
	Long: `combine reads >=threshold hex share files and reconstructs the MASTER_KEK (64-hex),
writing it 0600 to --out (NEVER stdout). Use it to re-provision the store after a loss:

  wapps secrets dr combine --share s1.hex --share s2.hex --out master.hex
  npx wrangler secret put MASTER_KEK < master.hex   # re-set the Worker secret
  rm master.hex

Refused in agent mode.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
			return err
		}
		if len(drCombineShares) < 2 {
			return clierr.New(clierr.NotAvailable, "dr combine needs >=2 --share files")
		}
		if drCombineOut == "" {
			return clierr.New(clierr.Internal, "dr combine: --out <file> is required (the key is NEVER printed)")
		}
		shares, err := readShareFiles(drCombineShares)
		if err != nil {
			return err
		}
		master, err := cryptoid.ShamirCombine(shares)
		if err != nil {
			return clierr.Wrapf(clierr.Internal, err, "reconstruct MASTER_KEK")
		}
		if len(master) != 32 {
			return clierr.Newf(clierr.Internal, "reconstructed MASTER_KEK is %d bytes, want 32 (wrong/mismatched shares?)", len(master))
		}
		kid, err := cryptoid.KekKid(master)
		if err != nil {
			return clierr.Wrapf(clierr.Internal, err, "derive kid")
		}
		if err := os.WriteFile(drCombineOut, []byte(hex.EncodeToString(master)+"\n"), 0o600); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "write %s", drCombineOut)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ MASTER_KEK reconstructed → %s (0600, kid %s)\n", drCombineOut, kid)
		fmt.Fprintf(cmd.OutOrStdout(), "  npx wrangler secret put MASTER_KEK < %s   # then: rm %s\n", drCombineOut, drCombineOut)
		return nil
	},
}

func init() {
	drVerifyCmd.Flags().StringVar(&drSnapshotDir, "snapshot", "", "local (air-gapped) copy of the B2 replica")
	drRestoreCmd.Flags().StringVar(&drSnapshotDir, "snapshot", "", "local (air-gapped) copy of the B2 replica")
	drRestoreCmd.Flags().StringVar(&drRestoreProject, "project", "", "project to reconstruct")
	drRestoreCmd.Flags().StringVar(&drRestoreOut, "out", "", "0600 env file to write the restored values into")
	drRestoreCmd.Flags().BoolVar(&drRestoreConfirm, "confirm", false, "confirm the TTY restore ceremony")
	drRestoreCmd.Flags().StringArrayVar(&drRestoreShares, "share", nil, "MASTER_KEK Shamir share file, hex (repeat ≥2; assembled key NEVER persisted)")

	drSplitCmd.Flags().IntVar(&drSplitParts, "parts", 3, "total Shamir shares to create")
	drSplitCmd.Flags().IntVar(&drSplitThreshold, "threshold", 2, "shares required to reconstruct")
	drSplitCmd.Flags().StringVar(&drSplitOutDir, "out-dir", "", "directory for the 0600 hex share files")
	drSplitCmd.Flags().StringVar(&drSplitMasterHex, "master-hex", "", "supply the MASTER_KEK (64-hex) explicitly instead of reading the archive")
	drSplitCmd.Flags().StringVar(&drSplitKey, "key", "SECRETSGATE_MASTER_KEK_PROD", "archive key holding the MASTER_KEK (unless --master-hex)")
	drCombineCmd.Flags().StringArrayVar(&drCombineShares, "share", nil, "hex Shamir share file (repeat ≥ threshold)")
	drCombineCmd.Flags().StringVar(&drCombineOut, "out", "", "0600 file to write the reconstructed MASTER_KEK hex into")

	DrCmd.AddCommand(drVerifyCmd, drRestoreCmd, drSplitCmd, drCombineCmd)
}
