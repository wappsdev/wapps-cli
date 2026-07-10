package witness

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// Escrow keygen + Shamir birleştirme + canary decrypt — escrow seremonisi tooling
// (SPEC §9.1 / §9.5 / §9.7). Offline anahtar seremonisi + Shamir custody İNSAN'dır
// (§9.6/G4); burada BUNU MÜMKÜN KILAN araç var. Birleştirilmiş özel yarı ASLA
// diske yazılmaz — çağıran shares'i gösterir/transkribe eder ve unutur.

// EscrowKeypair, bir escrow keygen seremonisinin ÇIKTISIDIR: public recipient
// (trust roster'a girer) + 2-of-3 Shamir payları (ayrı fiziksel medyaya, §9.1.1).
// Birleştirilmiş özel skalar burada TUTULMAZ.
type EscrowKeypair struct {
	// Recipient, canonical "age1..." escrow public recipient string'idir.
	Recipient string
	// Fingerprint, recipient'ın §3.7 parmak izi (trust enc-key KeyID'si).
	Fingerprint string
	// Shares, 2-of-3 Shamir payları (her biri ayrı fiziksel medyaya; asla birlikte).
	Shares [][]byte
}

// GenerateEscrowKeypair, taze bir X25519 escrow keypair üretir, özel 32-baytlık
// skaları 2-of-3 Shamir ile böler ve public recipient + payları döner (SPEC §9.1).
// Özel skalar döndürülMEZ ve HİÇBİR yerde saklanmaz — yalnızca payları. rng test
// için enjekte edilebilir (deterministik vektör); üretimde crypto/rand.
func GenerateEscrowKeypair(rng io.Reader) (*EscrowKeypair, error) {
	scalar := make([]byte, 32)
	if _, err := io.ReadFull(rng, scalar); err != nil {
		return nil, fmt.Errorf("witness.GenerateEscrowKeypair: rng: %w", err)
	}
	id, err := cryptoid.NewX25519IdentityFromScalar(scalar)
	if err != nil {
		return nil, fmt.Errorf("witness.GenerateEscrowKeypair: derive identity: %w", err)
	}
	rec := id.Recipient()
	shares, err := cryptoid.ShamirSplit(scalar, 3, 2, rng)
	if err != nil {
		return nil, fmt.Errorf("witness.GenerateEscrowKeypair: shamir split: %w", err)
	}
	// Özel skaları belleği temizle (defence-in-depth; GC yine de tutabilir).
	for i := range scalar {
		scalar[i] = 0
	}
	return &EscrowKeypair{Recipient: rec.String(), Fingerprint: rec.Fingerprint(), Shares: shares}, nil
}

// ReconstructEscrowKey, herhangi 2 (veya 3) Shamir payından escrow özel kimliğini
// yeniden kurar (SPEC §9.5.2a — DR seremonisi / verify-canary). Bu YALNIZCA
// hava-boşluklu bir seremoni makinesinde çağrılmalıdır; kimlik loglanmamalı.
func ReconstructEscrowKey(shares [][]byte) (*cryptoid.X25519Identity, error) {
	scalar, err := cryptoid.ShamirCombine(shares)
	if err != nil {
		return nil, fmt.Errorf("witness.ReconstructEscrowKey: %w", err)
	}
	id, err := cryptoid.NewX25519IdentityFromScalar(scalar)
	if err != nil {
		return nil, fmt.Errorf("witness.ReconstructEscrowKey: %w", err)
	}
	for i := range scalar {
		scalar[i] = 0
	}
	return id, nil
}

// CanaryCheck, verify-canary seremonisinin girdisidir (§9.7a end-to-end liveness):
// yeniden kurulan escrow kimliği + escrow public recipient + YAYINLANMIŞ (non-secret)
// canary DEK/plaintext (drill kit, §3.5.5) + escrow'daki stored wrap + stored blob.
type CanaryCheck struct {
	Project         string
	KeyVersion      uint64
	EscrowIdentity  *cryptoid.X25519Identity
	EscrowRecipient *cryptoid.X25519Recipient
	PublishedDEK    cryptoid.DEK
	PublishedPlain  []byte
	StoredWrap      []byte
	StoredBlob      []byte
}

// VerifyCanary, escrow wrap-at-write'ın CANLI olduğunu uçtan uca kanıtlar
// (§9.7a / §9.3.2g byte-compare + DECRYPT): (1) stored escrow wrap'i yeniden
// kurulan kimlikle DECRYPT et → DEK yayınlanan DEK ile eşleşmeli; (2) wrap'i
// yayınlanan DEK'ten SIFIRDAN yeniden türet → stored wrap ile BYTE-eşleşmeli
// (forge tespiti); (3) blob'u DEK ile aç → plaintext yayınlanan ile eşleşmeli.
func VerifyCanary(c CanaryCheck) error {
	slot := cryptoid.Slot{Project: c.Project, KeyName: CANARY_KEY, KeyVersion: c.KeyVersion}

	// (1) Stored wrap DECRYPT (özel key GEREKİR — DR seremonisi).
	got, err := cryptoid.UnsealDEK(c.StoredWrap, c.EscrowIdentity)
	if err != nil {
		return fmt.Errorf("witness.VerifyCanary: unseal stored escrow wrap: %w", err)
	}
	if subtle.ConstantTimeCompare(got[:], c.PublishedDEK[:]) != 1 {
		return fmt.Errorf("witness.VerifyCanary: unsealed DEK != published DEK")
	}

	// (2) Re-derive byte-compare (forge tespiti — §9.3.2g / ESCROW_WRAP_FORGED).
	if c.EscrowRecipient != nil {
		if err := cryptoid.WrapVerify(c.PublishedDEK, c.EscrowRecipient, slot, c.StoredWrap); err != nil {
			return fmt.Errorf("witness.VerifyCanary: %w: re-derived wrap != stored: %v", ErrCanaryForged, err)
		}
	}

	// (3) Blob DECRYPT → plaintext.
	if c.StoredBlob != nil {
		pt, err := cryptoid.OpenBlob(c.StoredBlob, c.PublishedDEK, slot)
		if err != nil {
			return fmt.Errorf("witness.VerifyCanary: open canary blob: %w", err)
		}
		if subtle.ConstantTimeCompare(pt, c.PublishedPlain) != 1 {
			return fmt.Errorf("witness.VerifyCanary: canary plaintext mismatch")
		}
	}
	return nil
}
