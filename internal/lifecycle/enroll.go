package lifecycle

import (
	"fmt"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// machineRotateWindow, makine kimliklerinin zorunlu rotate_by penceresidir
// (SPEC §8.4 / §4.3): enrolled_at + 90 gün.
const machineRotateWindow = 90 * 24 * time.Hour

// EnrollRequest, bir enroll seremonisinin girdisidir (SPEC §8.1.1).
type EnrollRequest struct {
	// IdentityID, tam kimlik ID'si: "human:<email>" | "machine:<name>".
	IdentityID string
	// Type, registry.TypeHuman | registry.TypeMachine.
	Type string
	// DeviceName, cihaz etiketi (kayıt/enrollment kaydı için; insan cihaz-add).
	DeviceName string
	// IsAdmin (yalnızca insan): ek bir presence-required admin imzalama anahtarı
	// üretilir (§8.1.1 step 3).
	IsAdmin bool
	// AddedAtEpoch, enc anahtarlarının kayda eklendiği admin_epoch (§4.3).
	AddedAtEpoch uint64
}

// EnrollResult, bir enroll seremonisinin çıktısıdır. Kimlik + enrollment kaydı
// VOUCH'a girer; Backup gizli yarısı YALNIZCA BİR KEZ (SecretOnce) alınır; private
// handle'lar (yazılım yolunda) çağıranın donanıma/CI'ya kurması içindir.
type EnrollResult struct {
	// Identity, kayda eklenecek doğrulanmış kimlik (HER İKİ anahtar ailesi dolu).
	Identity registry.Identity
	// Enrollment, HER İKİ anahtar ailesinin parmak izini taşıyan makine-okunur
	// enrollment kaydı (§4.9 step 2) — ikinci-kanal fingerprint ceremony girdisi.
	Enrollment registry.EnrollmentRecord
	// Backup, insan yedek kimliği (§8.3); makine için nil. Gizli yarı SecretOnce
	// ile bir kez transkribe edilir, asla diske yazılmaz.
	Backup *BackupIdentity
	// EncFingerprints/SigningFingerprints, terminale basılacak §3.7 parmak izleri
	// (§8.1.1: enroll HER İKİ aileyi de fingerprint'ler).
	EncFingerprints     []string
	SigningFingerprints []string

	// --- private handle'lar (yazılım yolu; donanımda gizli materyal HW'de kalır) ---
	EncKey EncKeyHandle        // device enc handle
	Daily  cryptoid.SigningKey // daily / automation writer
	Admin  cryptoid.SigningKey // presence admin (insan+IsAdmin), aksi halde nil
}

// Enroll, bir prensibin kimliğini üretir (SPEC §8.1.1). Anahtarlar cfg.Keygen ile
// üretilir (varsayılan SoftwareKeygen — CI/test; donanım yolu HardwareKeygen
// arayüzüyle bağlanır ve motor kapsamı DIŞINDADIR). HER İKİ anahtar ailesi
// fingerprint'lenir; insan için backup kimliği aynı seremonide üretilir ve gizli
// yarısı yalnızca bir kez alınabilir. Bu YALNIZCA kimliği ÜRETİR — kayda EKLEME
// (registry admission) VOUCH'un işidir (§8.1.3): vouch'suz bir kimliğin sıfır
// erişimi vardır.
func (e *Engine) Enroll(req EnrollRequest) (*EnrollResult, error) {
	if req.IdentityID == "" {
		return nil, fmt.Errorf("lifecycle.Enroll: empty identity id")
	}
	switch req.Type {
	case registry.TypeHuman:
		return e.enrollHuman(req)
	case registry.TypeMachine:
		return e.enrollMachine(req)
	default:
		return nil, fmt.Errorf("lifecycle.Enroll: unsupported identity type %q", req.Type)
	}
}

func (e *Engine) enrollHuman(req EnrollRequest) (*EnrollResult, error) {
	kg := e.cfg.Keygen
	// 1) X25519 şifreleme kimliği (device).
	enc, err := kg.EncIdentity()
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: enc identity: %w", err)
	}
	// 2) daily-writer imzalama anahtarı (no-presence; ajan yazımları için).
	daily, err := kg.SigningKey(registry.SignClassDaily)
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: daily key: %w", err)
	}
	// 3) admin presence anahtarı (opsiyonel).
	var admin cryptoid.SigningKey
	if req.IsAdmin {
		admin, err = kg.SigningKey(registry.SignClassAdmin)
		if err != nil {
			return nil, fmt.Errorf("lifecycle.Enroll: admin key: %w", err)
		}
	}
	// 4) backup kimliği (§8.3): bellekte üret, gizli yarı asla persist edilmez.
	backup, err := GenerateBackupIdentity()
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: backup identity: %w", err)
	}

	signing := make([]registry.SigningKey, 0, 2)
	if admin != nil {
		signing = append(signing, registry.NewSigningKeyEntry(admin, registry.SignClassAdmin, kg.Media()))
	}
	signing = append(signing, registry.NewSigningKeyEntry(daily, registry.SignClassDaily, kg.Media()))

	id := registry.Identity{
		ID:         req.IdentityID,
		Type:       registry.TypeHuman,
		Status:     registry.StatusActive,
		EnrolledAt: e.now(),
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(enc.Recipient(), registry.EncClassDevice, kg.Media(), req.AddedAtEpoch),
			registry.NewEncKeyEntry(backup.Recipient(), registry.EncClassBackup, "paper-steel", req.AddedAtEpoch),
		},
		SigningKeys: signing,
	}
	return e.finishEnroll(id, enc, daily, admin, backup)
}

func (e *Engine) enrollMachine(req EnrollRequest) (*EnrollResult, error) {
	kg := e.cfg.Keygen
	enc, err := kg.EncIdentity()
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: machine enc identity: %w", err)
	}
	// Makine yazarı: automation Ed25519 imzalama anahtarı (§8.4).
	auto, err := kg.SigningKey(registry.SignClassAutomation)
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: automation key: %w", err)
	}
	enrolledAt := e.now()
	rotateBy := enrolledAt.Add(machineRotateWindow)
	id := registry.Identity{
		ID:         req.IdentityID,
		Type:       registry.TypeMachine,
		Status:     registry.StatusActive,
		EnrolledAt: enrolledAt,
		RotateBy:   &rotateBy, // ZORUNLU (§4.3 makine değişmezi)
		EncKeys: []registry.EncKey{
			registry.NewEncKeyEntry(enc.Recipient(), registry.EncClassDevice, kg.Media(), req.AddedAtEpoch),
		},
		SigningKeys: []registry.SigningKey{
			registry.NewSigningKeyEntry(auto, registry.SignClassAutomation, kg.Media()),
		},
	}
	// Makinelerin backup'ı yoktur.
	return e.finishEnroll(id, enc, auto, nil, nil)
}

// finishEnroll, kimliği yapısal olarak doğrular, enrollment kaydını (HER İKİ
// aileyi fingerprint'leyerek) kurar ve sonucu toplar.
func (e *Engine) finishEnroll(id registry.Identity, enc EncKeyHandle, writer, admin cryptoid.SigningKey, backup *BackupIdentity) (*EnrollResult, error) {
	// Yapısal değişmez kontrolü (§4.3): insan device+backup+daily, makine rotate_by.
	snap := &registry.Snapshot{Schema: registry.SchemaRegistry, Identities: []registry.Identity{id}}
	if err := snap.Validate(); err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: %w", err)
	}
	rec, err := registry.NewEnrollmentRecord(id, e.now())
	if err != nil {
		return nil, fmt.Errorf("lifecycle.Enroll: %w", err)
	}
	return &EnrollResult{
		Identity:            id,
		Enrollment:          rec,
		Backup:              backup,
		EncFingerprints:     append([]string(nil), rec.EncFingerprints...),
		SigningFingerprints: append([]string(nil), rec.SigningFingerprints...),
		EncKey:              enc,
		Daily:               writer,
		Admin:               admin,
	}, nil
}
