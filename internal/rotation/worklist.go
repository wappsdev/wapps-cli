package rotation

// Worklist veri tipleri — ZK build'inde internal/lifecycle'da yaşıyordu; pivot
// lifecycle seremonilerini SİLDİ (SPEC §0.2), per-key rotasyon durumu ise KEPT
// (SPEC §6.3: rotate-plan çıktısı bu worklist'e yazılır ve `wapps secrets
// rotate` mevcut recipe'lerle tamamlar). Bu dosya o KEPT alt kümenin yeni evidir.

import (
	"time"
)

// Blast-radius katmanları, azalan öncelik. Worklist bu sıraya göre üretilir:
// en yüksek blast-radius ÖNCE. Metadata'sı olmayan anahtarlar TRİYAJ gerektirir
// ve en önce (blocker) listelenir (ROTATION_METADATA_MISSING).
const (
	TierPlatformAnchor = "platform-anchor"
	TierProdShared     = "prod-shared"
	TierProdSingle     = "prod-single"
	TierStagingLab     = "staging-lab"
	TierDev            = "dev"
	TierUnknown        = "unknown" // rotasyon metadata'sı eksik → triyaj
)

// WorklistEntry, değer-rotasyon worklist'inin bir girdisidir — rotasyon
// motorunun tükettiği VERİ. Motor recipe'leri worklist'ten yürütür.
type WorklistEntry struct {
	Project             string   `json:"project"`
	Key                 string   `json:"key"`
	Recipe              string   `json:"recipe,omitempty"` // tipli recipe (metadata'dan)
	Origin              string   `json:"origin,omitempty"` // tofu | static
	BlastTier           string   `json:"blast_tier"`
	OrderingConstraints []string `json:"ordering_constraints,omitempty"`
	NeedsTriage         bool     `json:"needs_triage"` // rotasyon metadata'sı eksik
	State               string   `json:"state"`        // her zaman "PENDING" — worklist veridir
}

// Worklist, bir offboard adım-3 (SPEC §6.2) veya migration değer-rotasyon
// worklist'idir. Entries EN YÜKSEK BLAST-RADIUS ÖNCE sıralıdır.
type Worklist struct {
	Schema    string          `json:"schema"`
	RunID     string          `json:"run_id"`
	RecordID  string          `json:"record_id,omitempty"`
	Principal string          `json:"principal"`
	Reason    string          `json:"reason"`
	CreatedAt time.Time       `json:"created_at"`
	Entries   []WorklistEntry `json:"entries"`
}

// WorklistSchema, worklist şeması.
const WorklistSchema = "wapps.offboard.worklist/1"

// Değer kökeni (origin): tofu-kökenli anahtarlar store'da MIRROR-ONLY'dir —
// rotasyon origin'de yapılır, değer `wapps secrets sync` ile akar.
const (
	OriginTofu   = "tofu"
	OriginStatic = "static"
)

// RotationRunLedger, rotasyon-yürütme motorunun bir worklist run'ının
// tamamlanma durumunu bildirdiği porttur (offboard close bunu tüketir).
type RotationRunLedger interface {
	// RunState, verilen worklist run'ının yürütme durumunu döner.
	RunState(runID string) (RotationRunState, error)
}

// RotationRunState, bir değer-rotasyon worklist run'ının yürütme durumudur.
type RotationRunState struct {
	RunID string
	// Complete, run'daki HER girişin TERMİNAL (DONE veya admin-imzalı SKIPPED)
	// olduğunu bildirir. false → hâlâ yürütülmeyi bekleyen giriş var.
	Complete bool
	// NeedsTriage, run'da rotasyon-metadata'sı eksik bir giriş kaldığını bildirir.
	NeedsTriage bool
	// Pending, henüz terminal olmayan giriş sayısı (-1 = bilinmiyor).
	Pending int
	// MirrorOnly, TERMİNAL-origin-notu olarak sayılan (MIRROR_ONLY_ORIGIN) giriş
	// sayısıdır: bu anahtarlar store'da rotate EDİLMEZ — değer origin'de (tofu/DB)
	// döner + `wapps secrets sync` ile akar. Complete hesabında terminal sayılırlar.
	MirrorOnly int
}
