// Package rotation, rotasyon-yürütme motorudur (server-decrypt SPEC §7.1
// `wapps secrets rotate` + §6.3 rotate-plan oracle'ının tüketicisi): tipli
// recipe'ler, per-key durum makineli resumable worklist run'ları ve
// rotasyon-run ledger'ı. Ayrıca Path B migrasyonunun legacy-arşiv yüzeyini
// taşır: salt-okunur LegacyArchive (legacy.go) + __MIGRATED__ tombstone
// yazıcısı (tombstone.go) — SPEC §8.2.
//
// KATMANLAMA (kod tekrarı YOK):
//   - internal/store: plaintext v2 istemcisi (üretim değer-yazımı; burada
//     ValueStore port'u). Worker düz-metin döner (§2.7) — istemcide yerel
//     unwrap/kimlik kriptosu YOKTUR.
//   - internal/ageutil: LEGACY simetrik-scrypt Decrypt/Encrypt (eski
//     all.enc.age okuma + tombstone/export yazımı).
//
// KAPSAM DIŞI (DEFER, insan-eliyle/prod): CANLI recipe yürütmesi (gerçek
// Postgres/Coolify/CF) — Executor STUB'u net TODO taşır; canlı store yazım
// bağlaması. Bunlar aşağıda net biçimde işaretlenir.
package rotation

import (
	"context"
	"errors"
	"time"
)

// Rotasyon motoru hata sözleşmesi. Hiçbiri ASLA gizli değer/anahtar taşımaz.
var (
	// ErrUnknownRecipe: worklist girdisinin recipe tipi kayıtlı değil (§8.6.1).
	ErrUnknownRecipe = errors.New("rotation: UNKNOWN_RECIPE")

	// ErrConfirmationRequired: manuel recipe (cf-manual/provider-manual)
	// CONSUMER_UPDATED'te DURAKLAR ve insan onay token'ı bekler (§8.6.4). Otomatik
	// yürütme YOK — recipe yalnızca talimat üretir.
	ErrConfirmationRequired = errors.New("rotation: CONFIRMATION_REQUIRED")

	// ErrLiveExecutionNotWired: gerçek-Executor STUB'u — CANLI yürütme (prod
	// Postgres/Coolify/CF) insan-eliyle koşulur (DEFER). Mock Executor testte sürer.
	ErrLiveExecutionNotWired = errors.New("rotation: LIVE_EXECUTION_NOT_WIRED")

	// ErrNeedsTriage: worklist girdisinin rotasyon-metadata'sı eksik
	// (ROTATION_METADATA_MISSING, §8.5.5.1) → rotate edilemez, insan triyajı gerekir;
	// run TERMİNAL olamaz (offboard close'u bloklar).
	ErrNeedsTriage = errors.New("rotation: NEEDS_TRIAGE")

	// ErrTFOriginMirrorOnly: origin:"tofu" bir anahtar store-tarafı value-mint ile
	// döndürülemez (§8.6.5, mirror-only) — origin'de (tofu/DB) döndürülüp sync'lenir.
	ErrTFOriginMirrorOnly = errors.New("rotation: TF_ORIGIN_MIRROR_ONLY")

	// ErrIronRuleViolation: store'a rotate edilen bir değer legacy arşive geri
	// yazılmaya çalışıldı — IRON RULE (§10.5): ASLA. Yalnızca __MIGRATED__ tombstone
	// legacy'e yazılabilir.
	ErrIronRuleViolation = errors.New("rotation: IRON_RULE_VIOLATION")

	// ErrArchiveMigrated: legacy arşiv bir __MIGRATED__ tombstone taşıyor — bayat
	// checkout GÜRÜLTÜLÜ başarısız olmalı (SPEC §8.2 adım 8), store'a yönlendirilir.
	ErrArchiveMigrated = errors.New("rotation: ARCHIVE_MIGRATED")
)

// Request, tek bir anahtarın rotasyon bağlamıdır — recipe'lerin girdisi.
type Request struct {
	Project  string
	Key      string
	OldValue []byte            // mevcut değer (recipe isterse); nil olabilir
	Params   map[string]string // §8.6.2 recipe_params (coolify_app_uuid, env_name, kid, ...)
	Confirm  string            // manuel recipe insan onay token'ı (cf/provider); boşsa DURAKLAR
	Exec     Executor          // yan-etkili adımlar (mock/stub/canlı)
	Now      func() time.Time
}

func (r Request) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Recipe, tek bir tipli rotasyon reçetesidir (SPEC §8.6.1). Her rotatable anahtar
// TAM BİR recipe tipi bildirir. Store-first (§8.6.1): motor Rotate ile taze değeri
// üretir, ONU store'a yazar (STORE_WRITTEN), SONRA Apply ile tüketici-tarafını sürer.
type Recipe interface {
	// Type, recipe tipi ("db-role/phase1", "coolify-env/start", ...).
	Type() string
	// Manual, insan-onaylı bir recipe mi (cf-manual/provider-manual) — bunlar
	// CONSUMER_UPDATED'te duraklar ve onay token'ı ister (agent-mode reddeder).
	Manual() bool
	// Rotate, anahtar için TAZE bir değer üretir (VALUE_MINTED). Task sözleşmesi
	// Rotate(ctx, key, oldVal) → (newVal, error): key+oldVal req içinde taşınır.
	Rotate(ctx context.Context, req Request) (newVal []byte, err error)
	// Apply, tüketici-tarafı değişikliği Executor ile sürer (CONSUMER_UPDATED) —
	// motor newVal'ı store'a YAZDIKTAN sonra. Manuel recipe req.Confirm yoksa
	// ErrConfirmationRequired döner ve HİÇBİR otomatik yürütme yapmaz.
	Apply(ctx context.Context, req Request, newVal []byte) error
	// Verify, recipe'in doğrulama probe'unu çalıştırır (VERIFIED). Başarısızsa run
	// DONE'a ULAŞAMAZ (§8.6.4).
	Verify(ctx context.Context, req Request, newVal []byte) error
	// Instructions, manuel recipe'ler için insan checklist'ini döner (değer içermez).
	Instructions(req Request) string
}

// Executor, recipe'lerin sürdüğü yan-etkili adımlardır. MockExecutor testte adım
// sırasını (phase1-first, gateway-last; env-sonra-start) kaydeder; StubExecutor
// (gerçek-yürütme yer-tutucusu) her adımda ErrLiveExecutionNotWired döner — CANLI
// yürütme prod/hesaba karşı İNSAN-ELİYLE koşulur (DEFER).
type Executor interface {
	// MintSecret, verilen türde (db-password/token/worker-secret) taze bir gizli
	// değer üretir.
	MintSecret(ctx context.Context, kind string, params map[string]string) ([]byte, error)
	// AlterDBRole, Postgres rol parolasını vaulter-db-admin job'u üzerinden döndürür;
	// adminsvc-sınıfı roller için DESUPER_PHASE=phase1 semantiğini onurlandırır (§10.4).
	AlterDBRole(ctx context.Context, params map[string]string, newSecret []byte) error
	// PushCoolifyEnv, yeni değeri Coolify app env'ine yazar (base64 PATCH, §10.4).
	PushCoolifyEnv(ctx context.Context, params map[string]string, newSecret []byte) error
	// RestartCoolifyApp, uygulamayı yeniden başlatır/redeploy eder — env değişikliği
	// ZORUNLU /start olmadan etki etmez (Coolify v4 davranışı, §8.6.1).
	RestartCoolifyApp(ctx context.Context, params map[string]string) error
	// SetWorkerSecret, bir CF Worker secret'ını ayarlar (dual-kid rotasyonu §9).
	SetWorkerSecret(ctx context.Context, params map[string]string, newSecret []byte, kid string) error
	// Probe, recipe'in doğrulama probe'unu koşar (deploy-verification smoke, §10.4.3).
	Probe(ctx context.Context, probe string, params map[string]string) error
}
