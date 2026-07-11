package lifecycle

import (
	"fmt"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// VouchRequest, bir enrollment'ı kayda kabul eden (registry admission) admin
// seremonisinin girdisidir (SPEC §8.1.3).
type VouchRequest struct {
	// Parent, üzerine yeni registry epoch'unun bindiği doğrulanmış trust head'i.
	Parent *trust.VerifiedEpoch
	// Enrollment, adayın makine-okunur enrollment kaydı (§4.9 step 2).
	Enrollment registry.EnrollmentRecord
	// Identity, kayda eklenecek TAM kimlik (enroll çıktısı).
	Identity registry.Identity
	// SecondChannelEnc/SecondChannelSigning, admin'in KEYS'ten FARKLI bir ikinci
	// kanaldan (yüz yüze / Signal) aldığı parmak izleri (§8.1.2 fingerprint
	// ceremony). Kayıttakilerle TAM eşleşmezse vouch reddedilir.
	SecondChannelEnc     []string
	SecondChannelSigning []string
	// CeremonyConfirmed, admin'in fingerprint-ceremony onay dizesini açıkça
	// yazdığını belirtir (§8.1.2 — onaysız vouch geçersiz, istemci+Worker reddeder).
	CeremonyConfirmed bool
	// VouchedBy, kayda yazılacak kefil admin identity ID'leri (§4.9 step 4).
	VouchedBy []string
	// Signers, vouch'u imzalayan admin presence anahtar(lar)ı. Registry tier:
	// 1 admin (§4.5); N≥2 insanda yeni İNSAN admisyonu 2 admin ile co-sign
	// EDİLMELİDİR (çağıran 2 imza geçirir).
	Signers []cryptoid.SigningKey
}

// Vouch, bir enrollment'ı kayda kabul eder (SPEC §8.1.3): ikinci-kanal fingerprint
// ceremony'sini yaptırır, sonra kimliği ekleyen imzalı bir registry trust epoch'u
// üretir ve PARENT'a karşı DOĞRULAR (co-sign tier + hash-link + monotonluk).
// vouch'lu kimliğin SIFIR erişimi vardır — erişim yalnızca grant ile gelir (§8.1.4).
//
// GÜVENLİK (§8.1.2): fingerprint ceremony, Worker/R2 seviyesinde bir enrollment
// substitution'a karşı savunmadır — admin, KEYS'i taşıyan kanaldan FARKLI bir
// kanaldan aldığı TAM digest'lerle eşleşmeyi doğrulamadan vouch EDEMEZ.
func (e *Engine) Vouch(req VouchRequest) (cryptoid.SignedObject, *trust.VerifiedEpoch, error) {
	if req.Parent == nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Vouch: nil parent")
	}
	if len(req.Signers) == 0 {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Vouch: no admin signer")
	}
	// (1) Fingerprint ceremony onayı ZORUNLU (§8.1.2).
	if !req.CeremonyConfirmed {
		return cryptoid.SignedObject{}, nil, ErrCeremonyNotConfirmed
	}
	// (2) İkinci-kanal parmak izleri kayıtla TAM eşleşmeli (truncated karşılaştırma
	// YASAK — MatchesFingerprints tam, sıra-bağımsız çokluk eşitliği yapar, §4.9).
	if !req.Enrollment.MatchesFingerprints(req.SecondChannelEnc, req.SecondChannelSigning) {
		return cryptoid.SignedObject{}, nil, ErrFingerprintMismatch
	}
	// (3) Enrollment kaydı, eklenecek kimliğin parmak izlerini gerçekten tanımlamalı
	// (kayıt ↔ kimlik tutarlılığı — yanlış kimlik enjeksiyonuna karşı).
	idRec, err := registry.NewEnrollmentRecord(req.Identity, req.Enrollment.CreatedAt)
	if err != nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Vouch: %w", err)
	}
	if !idRec.MatchesFingerprints(req.Enrollment.EncFingerprints, req.Enrollment.SigningFingerprints) {
		return cryptoid.SignedObject{}, nil, ErrFingerprintMismatch
	}

	admitted := req.Identity
	admitted.VouchedBy = append([]string(nil), req.VouchedBy...)

	// (4) Registry epoch: kimliği ekle (admins[] DEĞİŞMEZ — vouch'lu kimlik admin
	// değildir; yeni admin admisyonu ayrı bir roster seremonisidir §4.5). Değişmez
	// paylaşımını önlemek için YENİ Identities dilimi atanır.
	obj, next, err := e.buildTrustEpoch(req.Parent, trust.ChangeRegistry, func(child *trust.TrustManifest) {
		ids := make([]registry.Identity, 0, len(req.Parent.Manifest.Identities)+1)
		ids = append(ids, req.Parent.Manifest.Identities...)
		ids = append(ids, admitted)
		child.Identities = ids
	}, req.Signers...)
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	return obj, next, nil
}
