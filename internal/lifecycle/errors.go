package lifecycle

import "errors"

// Yaşam döngüsü motoru hata sözleşmesi (SPEC §8). Bunlar SAF motor sentinel'leri;
// CLI yüzeyi bunları internal/clierr kodlarına (CONTROL_PLANE_REQUIRED,
// IDENTITY_NOT_ENROLLED, SIG_INVALID, ...) eşler. Hiçbiri ASLA gizli değer/anahtar
// materyali taşımaz (§3.10 iki numaralı kural).
var (
	// ErrFingerprintMismatch: ikinci-kanal parmak izleri kayıt/enrollment ile TAM
	// eşleşmiyor (§8.1.2 fingerprint ceremony). Vouch reddedilir.
	ErrFingerprintMismatch = errors.New("lifecycle: FINGERPRINT_MISMATCH")

	// ErrCeremonyNotConfirmed: admin, fingerprint-ceremony onay bayrağını set
	// etmeden vouch etmeye çalıştı (§8.1.2 — onaysız vouch geçersiz).
	ErrCeremonyNotConfirmed = errors.New("lifecycle: CEREMONY_NOT_CONFIRMED")

	// ErrDepartingRunner: offboard/rewrap'i AYRILAN prensibin KENDİSİ çalıştırmaya
	// çalışıyor — asla tek çalıştırıcı ayrılan olamaz (§8.5, ≥2 admin kuralı).
	ErrDepartingRunner = errors.New("lifecycle: DEPARTING_RUNNER_FORBIDDEN")

	// ErrStepOutOfOrder: offboard adımları sırayla yürütülmeli (§8.5.1).
	ErrStepOutOfOrder = errors.New("lifecycle: STEP_OUT_OF_ORDER")

	// ErrNotAReader: verilen okuyucu kimliği mevcut bir DEK wrap'ini açamıyor —
	// rewrap için MEVCUT kalan bir okuyucu gerekir (§3.8.1/§8.5.3).
	ErrNotAReader = errors.New("lifecycle: READER_CANNOT_UNWRAP")

	// ErrRotationMetadataMissing: bir anahtar §8.6.2 rotasyon metadatası taşımıyor;
	// worklist bunu insan-triyajı gerektiren bir girdi olarak işaretler (§8.5.5).
	ErrRotationMetadataMissing = errors.New("lifecycle: ROTATION_METADATA_MISSING")

	// ErrRecordClosed: kapanmış (closed) bir offboard kaydı değişmezdir (§8.5.7).
	ErrRecordClosed = errors.New("lifecycle: OFFBOARD_RECORD_CLOSED")

	// ErrRecordNotFound: verilen record_id RecordStore'da yok.
	ErrRecordNotFound = errors.New("lifecycle: OFFBOARD_RECORD_NOT_FOUND")

	// ErrCASConflict: bir data-manifest CAS yazımı yarışı kaybetti (epoch conflict).
	ErrCASConflict = errors.New("lifecycle: CAS_CONFLICT")

	// ErrRecordRollback: bir offboard kaydı CAS yazımı MONOTONİK olmayan bir seq ile
	// reddedildi (§8.5.1 anti-rollback): yeni seq mevcut store seq'ini geçmiyor —
	// eski geçerli-imzalı bir envelope'un yeni bir kaydın üzerine yazılması engellenir.
	ErrRecordRollback = errors.New("lifecycle: OFFBOARD_RECORD_ROLLBACK")

	// ErrEscrowRekeyRequired: ayrılan bir escrow-share sahibiydi; escrow re-key
	// (§8.5.4) çalıştırılmadan offboard kapatılamaz.
	ErrEscrowRekeyRequired = errors.New("lifecycle: ESCROW_REKEY_REQUIRED")

	// ErrRotationPending: offboard kapatılamaz çünkü değer-rotasyon worklist
	// run'ları henüz TERMİNAL değil (§8.5.5.4/§8.5.7). Bu motor rotasyonu YÜRÜTMEZ
	// (G11 tüketir); ledger tüm run'ların DONE/imzalı-SKIPPED olduğunu bildirene
	// kadar kayıt "awaiting rotation" durumunda kalır — sahte "all_steps_verified"
	// attestation'ı ASLA basılmaz.
	ErrRotationPending = errors.New("lifecycle: ROTATION_PENDING")

	// ErrRotationTriageRequired: değer-rotasyon worklist'inde rotasyon-metadata'sı
	// eksik (ROTATION_METADATA_MISSING, §8.5.5.1) bir giriş var; insan triyajı
	// yapılmadan offboard KAPATILAMAZ (close bu girdileri swallow ETMEZ).
	ErrRotationTriageRequired = errors.New("lifecycle: ROTATION_TRIAGE_REQUIRED")

	// ErrRunnerIdentityMismatch: caller'ın iddia ettiği runnerID, offboard adımını
	// imzalayan anahtarın SAHİBİ aktif admin kimliğiyle uyuşmuyor — çalıştırıcı
	// kriptografik olarak bağlanır, caller'ın verdiği stringe güvenilmez (§8.5).
	ErrRunnerIdentityMismatch = errors.New("lifecycle: RUNNER_IDENTITY_MISMATCH")

	// ErrDeviceOffboardUnsupported: cihaz-kapsamlı offboard (§8.2: tek cihazı
	// kaldır, insan kalır) bu motorda henüz UYGULANMADI. scope.Devices dolu iken
	// tüm-kimlik kaldırma footgun'ını önlemek için açıkça reddedilir (izlenen
	// takip işi = gerçek cihaz-kapsamı desteği).
	ErrDeviceOffboardUnsupported = errors.New("lifecycle: DEVICE_OFFBOARD_UNSUPPORTED")

	// ErrScopeIncomplete: offboard scope'u (scope.Projects), ayrılan prensibin
	// GERÇEKTEN grant taşıdığı projelerin bir ÜST KÜMESİ değil — imzalı trust
	// manifest'inin grant tablosuna göre prensibin okuyabildiği en az bir proje
	// scope DIŞINDA (§8.5.3/§8.5.6 dürüstlük şartı). rewrap-REMOVE + değer-rotasyon
	// yalnızca scope.Projects üzerinde çalışır; eksik bir proje, ayrılan prensibin o
	// projedeki GÜNCEL değerleri hâlâ çözebilmesi demektir (forward-secrecy boşluğu).
	// Bu yüzden rewrap'e BAŞLAMADAN VE close'a İZİN VERMEDEN önce fail-closed reddet —
	// eksik-kapsamlı bir offboard sahte "all_steps_verified" attestation'ı üretemez.
	ErrScopeIncomplete = errors.New("lifecycle: OFFBOARD_SCOPE_INCOMPLETE")

	// ErrHardwareNotWired: donanım (SE/YubiKey) anahtar üretimi bu motorda
	// desteklenmez — arayüz sağlanır, gerçek plugin yolu G-account/donanım kapsamı.
	ErrHardwareNotWired = errors.New("lifecycle: HARDWARE_KEYGEN_NOT_WIRED")
)
