package trust

import "fmt"

// SignerClass, bir güven epoch'unu imzalamaya yetkili anahtar sınıfıdır (SPEC
// §4.5 step 4). daily ve automation sınıfları HİÇBİR güven epoch'unda geçerli
// DEĞİLDİR — bunlar bu tablonun dışındadır.
type SignerClass string

const (
	// ClassRoot: offline Ed25519 kök anahtarları (roster + epoch_reset).
	ClassRoot SignerClass = "root"
	// ClassAdmin: insan presence-required ECDSA P-256 admin anahtarları
	// (grant / registry / policy).
	ClassAdmin SignerClass = "admin"
)

// ProjectClass, bir grant'ın hedeflediği projenin hassasiyet sınıfıdır (SPEC
// §4.5 step 4): prod grant'ları N_h≥2'de 2 admin gerektirir, lab grant'ları 1
// admin + audit.
type ProjectClass string

const (
	ProjectNone ProjectClass = ""     // grant dışı sınıflar için ilgisiz
	ProjectProd ProjectClass = "prod" // en katı: N_h≥2'de 2 admin
	ProjectLab  ProjectClass = "lab"  // 1 admin + audit
)

// ProjectClassifier, bir proje adını prod/lab sınıfına eşler. Grant epoch'larının
// katmanını (tier) belirlemek için doğrulayıcıya verilir.
type ProjectClassifier func(project string) ProjectClass

// Requirement, bir güven epoch'unun kabulü için gereken imza politikasıdır —
// SAF, test edilebilir mantık (SPEC §4.5 step 4, §4.6, §4.7 katmanlı co-sign).
type Requirement struct {
	// Class, gereken imzalayan anahtar sınıfı.
	Class SignerClass
	// Threshold, gereken FARKLI geçerli imza sayısı.
	Threshold int
	// DistinctHuman true ise, Threshold FARKLI admin İNSAN sayısıdır (prod grant,
	// N_h≥2) — aynı insanın iki anahtarı bir sayılır.
	DistinctHuman bool
	// AuditRequired, kabulün zorunlu bir audit satırı ürettiğini belirtir (§6);
	// doğrulamanın kendisini etkilemez, çağırana bilgi verir.
	AuditRequired bool
}

// RequiredSigners, bir güven epoch'unun co-sign gereksinimini SAF bir fonksiyon
// olarak döndürür (SPEC §4.5/§4.6/§4.7). Bu, N=1→N≥3 geçişinin katmanlı
// politikasının test edilebilir çekirdeğidir:
//
//   - roster / epoch_reset → ClassRoot, eşik = imzalayan epoch'un (E) quorum.m'i
//     (FARKLI kök anahtarlar; kökler solo'da tek insanda olabilir).
//   - grant + prod        → ClassAdmin, N_h<2 iken 1 imza; N_h≥2 iken 2 FARKLI
//     admin İNSAN imzası + audit (bootstrap_solo durumundan BAĞIMSIZ, §4.7 step 4).
//   - grant + lab         → ClassAdmin, 1 admin imzası + audit.
//   - registry / policy   → ClassAdmin, 1 admin imzası + audit.
//
// parentM, imzalayan (önceki) epoch'un quorum.m değeridir; root-class eşiği
// buradan gelir. nAdminHumans önceki epoch'un durumudur — prod grant katmanı
// "otomatik" olarak N_h≥2 anında sertleşir (§4.7 step 4), solo=true olsa bile.
// bootstrapSolo parametre olarak korunur (roster değişmez denetimleri kullanır)
// ama prod grant eşiğini ARTIK etkilemez.
func RequiredSigners(changeClass string, proj ProjectClass, parentM int, bootstrapSolo bool, nAdminHumans int) (Requirement, error) {
	switch changeClass {
	case ChangeRoster, ChangeEpochReset:
		return Requirement{Class: ClassRoot, Threshold: parentM}, nil
	case ChangeGrant:
		switch proj {
		case ProjectProd:
			// §4.7 step 4: bir verified epoch N_h ≥ 2 admin insana ULAŞTIĞI AN,
			// prod-proje grant'ları 2 FARKLI admin presence imzası gerektirir —
			// bootstrap_solo hâlâ true olsa BİLE (solo=true & N_h=2 §4.7 geçişinde
			// ULAŞILABİLİR bir verified durumdur; tek admin orada prod grant
			// yetkilendiremez). Katman yalnızca N_h'ye bakar.
			thr := 1
			if nAdminHumans >= 2 {
				thr = 2
			}
			return Requirement{
				Class:         ClassAdmin,
				Threshold:     thr,
				DistinctHuman: thr >= 2,
				AuditRequired: true,
			}, nil
		case ProjectLab:
			return Requirement{Class: ClassAdmin, Threshold: 1, AuditRequired: true}, nil
		default:
			return Requirement{}, fmt.Errorf("trust.RequiredSigners: grant epoch needs a prod/lab project class: %w", ErrTrustChainBroken)
		}
	case ChangeRegistry, ChangePolicy:
		return Requirement{Class: ClassAdmin, Threshold: 1, AuditRequired: true}, nil
	default:
		return Requirement{}, fmt.Errorf("trust.RequiredSigners: %q: %w", changeClass, ErrUnknownChangeClass)
	}
}
