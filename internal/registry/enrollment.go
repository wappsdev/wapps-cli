package registry

import (
	"fmt"
	"sort"
	"time"
)

// SchemaEnrollment, enrollment kaydı şeması (SPEC §4.9).
const SchemaEnrollment = "wapps-enroll/v1"

// EnrollmentRecord, yeni bir kimliği kayda bağlayan seremoninin (SPEC §4.9)
// makine-okunur çıktısıdır. KRİTİK KURAL (§4.9 step 2): kayıt HER İKİ anahtar
// ailesinin — şifreleme pubkey'(ler)i VE imzalama pubkey'(ler)i — parmak izini
// (§3.7) taşır. Voucher bunları KEYS'i taşıyandan FARKLI bir ikinci kanaldan
// doğrular; kesik (truncated) karşılaştırma YASAKTIR (tam digest).
type EnrollmentRecord struct {
	Schema              string    `json:"schema"`
	IdentityID          string    `json:"identity_id"`
	Type                string    `json:"type"`
	EncFingerprints     []string  `json:"enc_fingerprints"`     // §3.7, şifreleme pubkey'leri
	SigningFingerprints []string  `json:"signing_fingerprints"` // §3.7, imzalama pubkey'leri
	CreatedAt           time.Time `json:"created_at"`
}

// NewEnrollmentRecord, bir kimliğin HER İKİ anahtar ailesinin parmak izlerini
// cryptoid §3.7 ile türeterek enrollment kaydı kurar. Her anahtarın key_id'si
// (varsa) türetilen parmak iziyle tutarlı olmalıdır; değilse ErrKeyIDMismatch.
//
// İnsan/makine kimlikleri en az bir imzalama parmak izi taşımalıdır; escrow
// kimlikleri imzalama anahtarı taşımaz (SPEC §4.3), yalnızca şifreleme parmak
// izi üretilir.
func NewEnrollmentRecord(id Identity, createdAt time.Time) (EnrollmentRecord, error) {
	rec := EnrollmentRecord{
		Schema:     SchemaEnrollment,
		IdentityID: id.ID,
		Type:       id.Type,
		CreatedAt:  createdAt,
	}
	for _, ek := range id.EncKeys {
		if ek.Pubkey == "" {
			return EnrollmentRecord{}, fmt.Errorf("registry.NewEnrollmentRecord: %q enc key empty pubkey: %w", id.ID, ErrRegistryInvalid)
		}
		fp := ek.Fingerprint()
		if ek.KeyID != "" && ek.KeyID != fp {
			return EnrollmentRecord{}, fmt.Errorf("registry.NewEnrollmentRecord: %q enc key_id mismatch: %w", id.ID, ErrKeyIDMismatch)
		}
		rec.EncFingerprints = append(rec.EncFingerprints, fp)
	}
	for _, sk := range id.SigningKeys {
		fp, err := sk.Fingerprint()
		if err != nil {
			return EnrollmentRecord{}, fmt.Errorf("registry.NewEnrollmentRecord: %q: %w", id.ID, err)
		}
		if sk.KeyID != "" && sk.KeyID != fp {
			return EnrollmentRecord{}, fmt.Errorf("registry.NewEnrollmentRecord: %q signing key_id mismatch: %w", id.ID, ErrKeyIDMismatch)
		}
		rec.SigningFingerprints = append(rec.SigningFingerprints, fp)
	}
	if len(rec.EncFingerprints) == 0 {
		return EnrollmentRecord{}, fmt.Errorf("registry.NewEnrollmentRecord: %q must fingerprint at least one enc key: %w", id.ID, ErrRegistryInvalid)
	}
	if id.Type != TypeEscrow && len(rec.SigningFingerprints) == 0 {
		return EnrollmentRecord{}, fmt.Errorf("registry.NewEnrollmentRecord: %q must fingerprint at least one signing key: %w", id.ID, ErrRegistryInvalid)
	}
	return rec, nil
}

// MatchesFingerprints, ikinci kanaldan gelen enc + signing parmak izi
// kümelerinin kayıttakilerle TAM ve sıra-bağımsız eşleştiğini doğrular (SPEC
// §4.9 step 4: admin vouch, tam digest). Herhangi bir eksik/fazla/uyumsuz
// parmak izi eşleşmeyi bozar.
func (e EnrollmentRecord) MatchesFingerprints(enc, signing []string) bool {
	return sameSet(e.EncFingerprints, enc) && sameSet(e.SigningFingerprints, signing)
}

// sameSet, iki string diliminin aynı çokluğa (multiset) sahip olduğunu döner.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
