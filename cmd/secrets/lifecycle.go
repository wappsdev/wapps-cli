package secrets

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// Yaşam döngüsü CLI verb'leri (SPEC §8, G9): enroll / vouch / grant / revoke /
// offboard. Motor internal/lifecycle'dadır (tam test-edilmiş). enroll TTY-only bir
// anahtar-üretim seremonisidir ve CANLI altyapı GEREKTİRMEZ → burada tam işlevsel.
// vouch/grant/revoke/offboard control-plane admin seremonileridir: DOĞRULANMIŞ bir
// trust head'i (Worker'dan çekilip pinlere karşı doğrulanan) + presence-required
// admin DONANIM anahtarı (SE/YubiKey) + store yazımı gerektirir. Bu bağlama katmanı
// (CLI ↔ canlı infra) G9 motorunun ötesindedir; verb'ler yine de mevcuttur,
// ajan-gated'dir ve gerekli seremoniyi net biçimde yüzeye çıkarır.

// --- enroll (tam işlevsel; §8.1.1) ------------------------------------------

var (
	enrollID       string
	enrollType     string
	enrollDevice   string
	enrollAdmin    bool
	enrollJSON     bool
	enrollSoftware bool
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Generate a new identity (X25519 enc + signing key + backup) — §8.1.1",
	Long: `Generate a new principal identity on this machine (SPEC §8.1.1).

Generates (SOFTWARE keys — the hardware SE/YubiKey path is a documented interface
out of scope for this build):
  - an X25519 encryption identity (device),
  - a daily-writer signing key (no-presence),
  - a presence admin signing key (--admin),
  - a paper/steel BACKUP identity whose secret is printed ONCE and never written.

A SOFTWARE identity is persisted to ~/.config/wapps/identity.json (0600) so the
store path can decrypt (§7.1: the CLI decrypts) and sign commits. A software
identity is meant for CI/testing; for HUMANS the hardware SE/YubiKey path is
preferred (the private key never leaves the secure element). Pass --software to
make the software path explicit; it is also the automatic path when no hardware
keygen is available. The backup secret is NEVER written — transcribe it once.

Prints the SHA-256 fingerprints of BOTH key families for a second-channel
fingerprint ceremony (§8.1.2), then an admin vouches (wapps secrets vouch).
This only PRODUCES the identity — a vouched identity has zero access until granted.`,
	RunE: runEnroll,
}

func runEnroll(cmd *cobra.Command, _ []string) error {
	var typ string
	switch enrollType {
	case "", "human":
		typ = registry.TypeHuman
	case "machine":
		typ = registry.TypeMachine
	default:
		return clierr.Newf(clierr.Internal, "unknown --type %q (human|machine)", enrollType)
	}
	if enrollID == "" {
		return clierr.New(clierr.Internal, "--id is required (e.g. human:alice@example.com | machine:tofu-sync-vaulter)")
	}

	eng := lifecycle.New(lifecycle.Config{})
	res, err := eng.Enroll(lifecycle.EnrollRequest{
		IdentityID:   enrollID,
		Type:         typ,
		DeviceName:   enrollDevice,
		IsAdmin:      enrollAdmin,
		AddedAtEpoch: 0,
	})
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "enroll")
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Enrolled %s (%s)\n\n", res.Identity.ID, res.Identity.Type)
	fmt.Fprintln(out, "Fingerprint ceremony (§8.1.2) — verify BOTH families over a SECOND channel:")
	fmt.Fprintln(out, "  encryption pubkey fingerprints:")
	for _, fp := range res.EncFingerprints {
		fmt.Fprintf(out, "    %s\n", fp)
	}
	fmt.Fprintln(out, "  signing pubkey fingerprints:")
	for _, fp := range res.SigningFingerprints {
		fmt.Fprintf(out, "    %s\n", fp)
	}

	// YAZILIM kimliğini yerel 0600 depoya yaz (CI/test; store yolu çözme+imza için
	// bunu yükler). Donanım-resident enc kimliğinde (Identity()==nil) dosya YAZILMAZ —
	// gizli materyal güvenli öğede kalır. Backup gizli yarısı ASLA yazılmaz.
	if res.EncKey.Identity() != nil {
		idPath, perr := saveEnrolledIdentity(res)
		if perr != nil {
			return perr
		}
		fmt.Fprintf(out, "\nSoftware identity persisted to %s (0600).\n", idPath)
		fmt.Fprintln(out, "  This is a SOFTWARE identity for CI/testing; for humans the hardware SE/YubiKey path is preferred.")
	} else {
		fmt.Fprintln(out, "\nHardware identity — the private key stays in the secure element; no local identity file is written.")
	}

	if res.Backup != nil {
		fmt.Fprintln(out, "\nBACKUP identity (§8.3) — TRANSCRIBE to paper/steel NOW; shown ONCE, never written:")
		secret := res.Backup.SecretOnce()
		fmt.Fprintf(out, "  %s\n", secret)
		fmt.Fprintf(out, "  backup recipient: %s\n", res.Backup.Recipient().String())
	}

	if enrollJSON {
		rec, err := json.MarshalIndent(res.Enrollment, "", "  ")
		if err != nil {
			return clierr.Wrapf(clierr.Internal, err, "marshal enrollment record")
		}
		fmt.Fprintf(out, "\nenrollment request (hand to the vouching admin):\n%s\n", rec)
	}

	fmt.Fprintln(out, "\nNext: an admin runs `wapps secrets vouch` after verifying the fingerprints out-of-band.")
	return nil
}

// --- control-plane admin ceremonies (§8.1.3/§8.1.4/§8.5) --------------------

// ceremonyNotWired, canlı trust head + admin donanım imzası + store yazımı
// gerektiren control-plane seremonilerinin ortak yanıtıdır. Motor (§8) hazırdır;
// eksik olan CLI↔canlı-infra bağlamasıdır (Worker'dan doğrulanmış head çekme +
// SE/YubiKey admin imzası). NotAvailable → canlı CF Access oturumu + insan terminal.
func ceremonyNotWired(name, detail string) error {
	return clierr.Newf(clierr.NotAvailable,
		"%s is a control-plane admin ceremony (%s); it needs a verified trust head + a presence admin hardware key + store write — engine ready (internal/lifecycle §8), CLI↔live wiring pending", name, detail)
}

var (
	vouchRequest   string
	grantPrincipal string
	grantProject   string
	grantKeys      string
	offboardPrinc  string
	offboardResume string
)

var vouchCmd = &cobra.Command{
	Use:   "vouch <enrollment-request>",
	Short: "Admit an enrollment into the registry (admin ceremony) — §8.1.3",
	Long: `Admit a vouched identity into the identity registry (SPEC §8.1.3).

An admin verifies the enrollee's BOTH-family fingerprints over a second channel
(§8.1.2), then co-signs a registry trust epoch (1 admin; 2 once N_h>=2 for humans).
A vouched identity has ZERO access until granted.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ceremonyNotWired("vouch", "verify BOTH-family fingerprints out-of-band, then admin-sign a registry epoch")
	},
}

var grantCmd = &cobra.Command{
	Use:   "grant <principal> --project <p> [--keys k1,k2]",
	Short: "Grant a principal access to a project (admin ceremony) — §8.1.4",
	Long: `Grant a principal read access to a project (SPEC §8.1.4).

Co-sign tier: prod = 2 admins once N_h>=2; lab / solo = 1 admin + audit. Updates the
signed trust-manifest grant table, then a manifest-only wrap ADD (§3.8.1) seals each
key's existing DEK to the principal's devices + backup (O(1), zero blob churn).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ceremonyNotWired("grant", "admin-sign a grant epoch (tiered co-sign), then manifest-only wrap ADD")
	},
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <principal> --project <p>",
	Short: "Revoke a principal's grant (admin ceremony) — §8.5.3",
	Long: `Revoke a principal's grant on a project (SPEC §8.5.3 step 1).

Removal is safety-increasing: it shrinks the required wrap-set, which triggers the
rewrap REMOVE path (new DEK + re-encrypt, §3.8.2) — dropping a wrap alone is
cosmetic. Value rotation stays mandatory (§3.8.2 / offboard step 3).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ceremonyNotWired("revoke", "admin-sign a grant-removal epoch, then rewrap REMOVE (new DEK)")
	},
}

var offboardCmd = &cobra.Command{
	Use:   "offboard <principal>",
	Short: "Offboard a principal — 5-step resumable state machine — §8.5",
	Long: `Offboard a principal via the 5-step resumable state machine (SPEC §8.5):

  1 KILL    remove from CF Access + revoke tokens + D1 kill-flag (unilateral)
  2 REWRAP  revoke grants + retire identity, then DEK-rotate every wrap-set to the
            remaining recipients (per-key completion ledger; "fully rotated at N"
            attestation; alarming until 100%)
  3 ROTATE  emit the MANDATORY value-rotation worklist (data for G11; highest blast
            radius first) — this verb PRODUCES it, it does not execute recipes
  4 ESCROW  if the leaver held an escrow share: re-key (new keypair + Shamir 2-of-3)
  5 CLOSE   mark complete only when steps 1-4 are verified

The signed offboard record lives in the store (survives an operator laptop loss);
any OTHER admin can --resume it. The departing principal can never be the only
runner. Engine: internal/lifecycle (§8).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if offboardResume != "" {
			return ceremonyNotWired("offboard --resume", "load the signed record from the store and continue as another admin")
		}
		return ceremonyNotWired("offboard", "open a signed record + run the 5-step resumable state machine")
	},
}

func init() {
	enrollCmd.Flags().StringVar(&enrollID, "id", "", "identity id (human:<email> | machine:<name>)")
	enrollCmd.Flags().StringVar(&enrollType, "type", "human", "identity type (human|machine)")
	enrollCmd.Flags().StringVar(&enrollDevice, "device-name", "", "device label")
	enrollCmd.Flags().BoolVar(&enrollAdmin, "admin", false, "also generate a presence admin signing key")
	enrollCmd.Flags().BoolVar(&enrollJSON, "json", false, "print the enrollment request JSON")
	enrollCmd.Flags().BoolVar(&enrollSoftware, "software", false,
		"generate a SOFTWARE identity persisted to ~/.config/wapps/identity.json (CI/testing; the hardware SE/YubiKey path is preferred for humans)")

	vouchCmd.Flags().StringVar(&vouchRequest, "request", "", "path to the enrollment request JSON")

	grantCmd.Flags().StringVar(&grantPrincipal, "principal", "", "principal id")
	grantCmd.Flags().StringVar(&grantProject, "project", "", "project")
	grantCmd.Flags().StringVar(&grantKeys, "keys", "*", "comma-separated key allowlist (machines)")

	revokeCmd.Flags().StringVar(&grantPrincipal, "principal", "", "principal id")
	revokeCmd.Flags().StringVar(&grantProject, "project", "", "project")

	offboardCmd.Flags().StringVar(&offboardPrinc, "principal", "", "departing principal id")
	offboardCmd.Flags().StringVar(&offboardResume, "resume", "", "resume an open offboard record by id")

	SecretsCmd.AddCommand(enrollCmd, vouchCmd, grantCmd, revokeCmd, offboardCmd)
}
