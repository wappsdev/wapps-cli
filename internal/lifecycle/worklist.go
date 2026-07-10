package lifecycle

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// Blast-radius katmanları (SPEC §8.6.3), azalan öncelik. Worklist bu sıraya göre
// üretilir: en yüksek blast-radius ÖNCE. Metadata'sı olmayan anahtarlar TRİYAJ
// gerektirir ve en önce (blocker) listelenir (§8.5.5 ROTATION_METADATA_MISSING).
const (
	TierPlatformAnchor = "platform-anchor"
	TierProdShared     = "prod-shared"
	TierProdSingle     = "prod-single"
	TierStagingLab     = "staging-lab"
	TierDev            = "dev"
	TierUnknown        = "unknown" // rotasyon metadata'sı eksik → triyaj
)

// tierOrdinal, bir katmanın sıralama ordinal'i (küçük = önce). Metadata eksikliği
// (-1) HER ŞEYDEN önce gelir çünkü rotasyonu bloklar ve insan triyajı gerektirir.
func tierOrdinal(tier string) int {
	switch tier {
	case TierUnknown:
		return -1
	case TierPlatformAnchor:
		return 0
	case TierProdShared:
		return 1
	case TierProdSingle:
		return 2
	case TierStagingLab:
		return 3
	case TierDev:
		return 4
	default:
		return 5
	}
}

// WorklistEntry, değer-rotasyon worklist'inin bir girdisidir — G11 rotasyon
// motorunun tükettiği VERİ (SPEC §8.5.5/§8.6). Bu motor recipe'leri ÇALIŞTIRMAZ,
// yalnızca worklist'i üretir.
type WorklistEntry struct {
	Project             string   `json:"project"`
	Key                 string   `json:"key"`
	Recipe              string   `json:"recipe,omitempty"` // §8.6.1 tipli recipe (metadata'dan)
	Origin              string   `json:"origin,omitempty"` // tofu | static (§8.6.2)
	BlastTier           string   `json:"blast_tier"`       // §8.6.3 katman
	OrderingConstraints []string `json:"ordering_constraints,omitempty"`
	NeedsTriage         bool     `json:"needs_triage"` // rotasyon metadata'sı eksik (§8.5.5)
	State               string   `json:"state"`        // her zaman "PENDING" — worklist veridir, G11 yürütür
}

// Worklist, bir offboard step 3 (veya migration Phase 2) değer-rotasyon
// worklist'idir (SPEC §8.5.5). Entries EN YÜKSEK BLAST-RADIUS ÖNCE sıralıdır.
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

// WorklistRequest, worklist üretiminin girdisidir.
type WorklistRequest struct {
	Principal string
	Reason    string
	Projects  []string // ayrılan prensibin grant'lı olduğu projeler (offboard scope)
	RunID     string
	RecordID  string
}

// rotationMetaDoc, manifest girdisinin opsiyonel rotation metadata objesidir
// (§8.6.2). Worker bunu ASLA yorumlamaz; motor worklist üretmek için okur.
type rotationMetaDoc struct {
	Recipe              string   `json:"recipe"`
	Origin              string   `json:"origin"`
	BlastTier           string   `json:"blast_tier"`
	OrderingConstraints []string `json:"ordering_constraints"`
}

// EmitWorklist, ayrılan prensibin OKUYABİLECEĞİ her projedeki her anahtarı kapsayan
// bir değer-rotasyon worklist'i ÜRETİR (SPEC §8.5.5, honesty clause §8.5.6: insan
// offboard'ı = grant'lı her projedeki her değeri döndürmek). Sıra: en yüksek
// blast-radius önce (§8.6.3). Metadata'sı olmayan anahtarlar NeedsTriage ile en
// önce listelenir. Bu VERİDİR — recipe'ler burada ÇALIŞTIRILMAZ (G11).
func (e *Engine) EmitWorklist(req WorklistRequest) (*Worklist, error) {
	wl := &Worklist{
		Schema:    WorklistSchema,
		RunID:     req.RunID,
		RecordID:  req.RecordID,
		Principal: req.Principal,
		Reason:    req.Reason,
		CreatedAt: e.now(),
	}
	for _, project := range req.Projects {
		wrapper, _, _, _, ok, err := e.cfg.Data.CurrentManifest(project)
		if err != nil {
			return nil, fmt.Errorf("lifecycle.EmitWorklist: fetch %q: %w", project, err)
		}
		if !ok {
			continue // proje henüz veri taşımıyor
		}
		obj, perr := manifest.ParseSignedObject(wrapper)
		if perr != nil {
			return nil, fmt.Errorf("lifecycle.EmitWorklist: parse %q: %w", project, perr)
		}
		man, merr := manifest.ParseManifestBody(obj.Bytes)
		if merr != nil {
			return nil, fmt.Errorf("lifecycle.EmitWorklist: body %q: %w", project, merr)
		}
		for _, en := range man.Entries {
			wl.Entries = append(wl.Entries, worklistEntryFor(project, en))
		}
	}
	// Sırala: katman ordinal (en yüksek blast önce) → proje → anahtar (deterministik).
	sort.SliceStable(wl.Entries, func(i, j int) bool {
		a, b := wl.Entries[i], wl.Entries[j]
		if oa, ob := tierOrdinal(a.BlastTier), tierOrdinal(b.BlastTier); oa != ob {
			return oa < ob
		}
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Key < b.Key
	})
	return wl, nil
}

// worklistEntryFor, bir manifest girdisinden bir worklist girdisi kurar; rotasyon
// metadata'sı yoksa NeedsTriage + TierUnknown (§8.5.5 ROTATION_METADATA_MISSING).
func worklistEntryFor(project string, en manifest.KeyEntry) WorklistEntry {
	entry := WorklistEntry{Project: project, Key: en.KeyName, State: "PENDING"}
	if en.Rotation == nil {
		entry.NeedsTriage = true
		entry.BlastTier = TierUnknown
		return entry
	}
	raw := en.Rotation.Raw()
	if len(raw) == 0 || string(raw) == "null" {
		entry.NeedsTriage = true
		entry.BlastTier = TierUnknown
		return entry
	}
	var doc rotationMetaDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.BlastTier == "" {
		entry.NeedsTriage = true
		entry.BlastTier = TierUnknown
		return entry
	}
	entry.Recipe = doc.Recipe
	entry.Origin = doc.Origin
	entry.BlastTier = doc.BlastTier
	entry.OrderingConstraints = doc.OrderingConstraints
	return entry
}
