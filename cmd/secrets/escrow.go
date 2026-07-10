package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"time"

	"fmt"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/trust"
	"github.com/wappsdev/wapps-cli/internal/witness"
)

// wapps escrow — escrow anahtar seremonisi tooling (SPEC §9.1 / §9.7). keygen bir
// X25519 escrow keypair üretir ve özel yarıyı 2-of-3 Shamir ile böler: public
// recipient + 3 pay BİR KEZ gösterilir, birleştirilmiş özel yarı ASLA saklanmaz.
// verify-canary, yeniden kurulan bir anahtarla yayınlanmış canary'yi DECRYPT eder
// (§9.7a end-to-end escrow-liveness kanıtı). Offline seremoni + Shamir custody
// İNSAN'dır (§9.6/G4); bu araç BUNU mümkün kılar. Hepsi TTY-only.

// EscrowCmd, `wapps escrow` grup komutudur.
var EscrowCmd = &cobra.Command{
	Use:   "escrow",
	Short: "Escrow key ceremony tooling: keygen (Shamir 2-of-3) + verify-canary (§9.1/§9.7)",
	Long: `Escrow key ceremony tooling (SPEC §9.1). The escrow recipient is a SINGLE
age X25519 public key whose private half is generated OFFLINE at the root ceremony
and immediately split with Shamir 2-of-3 onto distinct physical media; it must NEVER
exist assembled on any online machine outside a DR ceremony (§9.5). keygen produces
the public recipient + the three shares ONCE; verify-canary is the recurring
end-to-end proof that wrap-at-write actually seals to the escrow key (§9.7a).`,
}

var escrowKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an escrow X25519 keypair + Shamir 2-of-3 split (shown ONCE)",
	Long: `Generate a fresh escrow X25519 keypair and split the 32-byte private scalar
with Shamir 2-of-3 (SPEC §9.1). Prints the PUBLIC recipient (enters the trust roster)
+ the three shares ONCE. The assembled private key is NEVER returned or written —
only the shares. TRANSCRIBE each share to a SEPARATE physical medium in a SEPARATE
location (never co-locate two shares — that collapses 2-of-3 to 1-of-1, §9.6.2).`,
	RunE: runEscrowKeygen,
}

func runEscrowKeygen(cmd *cobra.Command, _ []string) error {
	if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
		return err
	}
	kp, err := witness.GenerateEscrowKeypair(rand.Reader)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "generate escrow keypair")
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Escrow keypair generated (SPEC §9.1). The private half is Shamir 2-of-3 split;")
	fmt.Fprintln(out, "the assembled key was NEVER written and is now gone from memory.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "PUBLIC recipient (add to the trust roster as an escrow enc-key):\n  %s\n", kp.Recipient)
	fmt.Fprintf(out, "  fingerprint: %s\n\n", kp.Fingerprint)
	fmt.Fprintln(out, "SHARES — transcribe each to a SEPARATE medium in a SEPARATE location (§9.6.2).")
	fmt.Fprintln(out, "NEVER co-locate two shares. Shown ONCE:")
	for i, s := range kp.Shares {
		fmt.Fprintf(out, "  share %d/3: %s\n", i+1, encodeShare(s))
	}
	fmt.Fprintln(out, "\nRecord the share map (which share is where) in the offline bootstrap bundle + drill kit (§9.6).")
	return nil
}

var (
	canaryShares    []string
	canaryDEKHex    string
	canaryPlainFile string
	canarySnapshot  string
	canaryProject   string
)

var escrowVerifyCanaryCmd = &cobra.Command{
	Use:   "verify-canary",
	Short: "Decrypt the published escrow canary with a reconstructed key (§9.7a)",
	Long: `Reconstruct the escrow private key from ≥2 Shamir shares and DECRYPT the
published WAPPS_ESCROW_CANARY escrow wrap (SPEC §9.7a) — the recurring end-to-end
proof that wrap-at-write actually seals to the escrow key. The canary DEK + plaintext
are PUBLISHED (non-secret, drill kit §3.5.5); the stored wrap + blob come from the
escrow snapshot (--snapshot dir or live B2). TTY-only; the assembled key is NEVER
persisted.`,
	RunE: runEscrowVerifyCanary,
}

func runEscrowVerifyCanary(cmd *cobra.Command, _ []string) error {
	if err := agentmode.Guard(agentmode.PolicyTTY, agentmode.IsAgent()); err != nil {
		return err
	}
	if len(canaryShares) < 2 {
		return clierr.New(clierr.NotAvailable, "verify-canary needs ≥2 Shamir share files (--share PATH --share PATH)")
	}
	shares, err := readShares(canaryShares)
	if err != nil {
		return err
	}
	escrowID, err := witness.ReconstructEscrowKey(shares)
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "reconstruct escrow key")
	}
	rec := escrowID.Recipient()

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ reconstructed escrow key from %d shares → recipient %s\n", len(shares), rec.String())

	// Canary materyalleri yoksa: reconstruct doğrulaması yeterli (shares gerçek).
	if canaryDEKHex == "" || canaryProject == "" || (canarySnapshot == "") {
		return clierr.New(clierr.NotAvailable,
			"provide --canary-dek <hex32> --project <p> and --snapshot <dir> (or live B2) to DECRYPT the published canary wrap end-to-end (§9.7a). Shares reconstructed OK.")
	}

	dekBytes, err := hex.DecodeString(strings.TrimSpace(canaryDEKHex))
	if err != nil || len(dekBytes) != 32 {
		return clierr.New(clierr.Internal, "--canary-dek must be 32-byte hex")
	}
	var dek cryptoid.DEK
	copy(dek[:], dekBytes)
	var plain []byte
	if canaryPlainFile != "" {
		if plain, err = os.ReadFile(canaryPlainFile); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "read --canary-plaintext")
		}
	}

	// Snapshot'ı doğrula + head canary girdisinin wrap+blob'unu al.
	pins, err := loadLocalPins()
	if err != nil {
		return err
	}
	reader := witness.DirReader{Root: canarySnapshot}
	res, err := witness.Verify(context.Background(), reader, witness.Config{Pins: pins, Now: time.Now})
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "verify snapshot before canary decrypt")
	}
	wrap, blob, version, err := canaryMaterials(reader, res, canaryProject, rec.Fingerprint())
	if err != nil {
		return err
	}
	check := witness.CanaryCheck{
		Project: canaryProject, KeyVersion: version,
		EscrowIdentity: escrowID, EscrowRecipient: rec,
		PublishedDEK: dek, PublishedPlain: plain,
		StoredWrap: wrap, StoredBlob: blob,
	}
	if err := witness.VerifyCanary(check); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "escrow canary DECRYPT FAILED (wrap-at-write not live / forged)")
	}
	fmt.Fprintln(out, "✓ escrow canary DECRYPTED + byte-verified — wrap-at-write is LIVE to the escrow key (§9.7a)")
	return nil
}

// canaryMaterials, doğrulanmış head manifest'inden WAPPS_ESCROW_CANARY girdisinin
// escrow wrap'i (escrowFp'e ait) + blob'u + keyVersion'ını çeker.
func canaryMaterials(reader witness.Reader, res *witness.Result, project, escrowFp string) (wrap, blob []byte, version uint64, err error) {
	head, ok := res.ProjectHeads[project]
	if !ok {
		return nil, nil, 0, clierr.Newf(clierr.Internal, "project %q not in verified snapshot", project)
	}
	raw, err := reader.Get(context.Background(), fmt.Sprintf("secrets/%s/manifests/%d.json", project, head.Epoch))
	if err != nil {
		return nil, nil, 0, clierr.Wrapf(clierr.Internal, err, "read head manifest")
	}
	obj, err := manifest.ParseSignedObject(raw)
	if err != nil {
		return nil, nil, 0, clierr.Wrapf(clierr.Internal, err, "parse head manifest")
	}
	m, err := manifest.ParseManifestBody(obj.Bytes)
	if err != nil {
		return nil, nil, 0, clierr.Wrapf(clierr.Internal, err, "parse head body")
	}
	for _, e := range m.Entries {
		if e.KeyName != witness.CANARY_KEY {
			continue
		}
		for _, w := range e.Wraps {
			if w.Recipient != escrowFp {
				continue
			}
			blobBytes, berr := reader.Get(context.Background(), fmt.Sprintf("secrets/%s/blobs/%s", project, e.BlobHash))
			if berr != nil {
				return nil, nil, 0, clierr.Wrapf(clierr.Internal, berr, "read canary blob")
			}
			return w.Wrap, blobBytes, e.KeyVersion, nil
		}
		return nil, nil, 0, clierr.Newf(clierr.Internal, "%s entry lacks the reconstructed escrow recipient's wrap", witness.CANARY_KEY)
	}
	return nil, nil, 0, clierr.Newf(clierr.Internal, "no %s entry in %s head manifest", witness.CANARY_KEY, project)
}

// --- Shamir pay kodlama (keygen çıktısı ↔ dosya) ----------------------------

// encodeShare, bir Shamir payını hex string'e kodlar (keygen çıktısı).
func encodeShare(s []byte) string { return hex.EncodeToString(s) }

// decodeShare, bir pay dosyasının içeriğini ham baytlara çözer (hex; boşluk/newline
// tolere edilir). Ham (non-hex) girdi de aynen kabul edilir (esneklik).
func decodeShare(b []byte) []byte {
	s := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(s); err == nil {
		return raw
	}
	return b
}

// _ ensure trust import used (loadLocalPins is in dr.go; keep escrow.go self-consistent).
var _ = trust.PinSchema

func init() {
	escrowVerifyCanaryCmd.Flags().StringArrayVar(&canaryShares, "share", nil, "Shamir share file (repeat ≥2)")
	escrowVerifyCanaryCmd.Flags().StringVar(&canaryDEKHex, "canary-dek", "", "published canary DEK (32-byte hex, drill kit §3.5.5)")
	escrowVerifyCanaryCmd.Flags().StringVar(&canaryPlainFile, "canary-plaintext", "", "file with the published canary plaintext")
	escrowVerifyCanaryCmd.Flags().StringVar(&canarySnapshot, "snapshot", "", "escrow snapshot dir holding the stored canary wrap+blob")
	escrowVerifyCanaryCmd.Flags().StringVar(&canaryProject, "project", "", "project whose canary to decrypt")
	EscrowCmd.AddCommand(escrowKeygenCmd, escrowVerifyCanaryCmd)
}
