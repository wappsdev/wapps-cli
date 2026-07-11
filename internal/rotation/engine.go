package rotation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
)

// ValueStore, store-first değer-yazımı port'udur (yeni değer tüketici-tarafı
// değişiklikten ÖNCE wapps-secrets'a yazılır). ÜRETİM: internal/store v2
// plaintext istemcisi üzerinden PUT/Import (SPEC §7.4 — imza/wrap katmanı
// YOK, Worker düz-metin alır). Canlı wiring DEFER; burada test için
// MemValueStore, prod için StubValueStore.
type ValueStore interface {
	// WriteValue, yeni değeri store'a yazar ve yeni sürümü döner (store-first).
	WriteValue(ctx context.Context, project, key string, newVal []byte) (version uint64, err error)
	// ReadValue, store-first yazılmış SON değeri + sürümü geri okur (resume:
	// STORE_WRITTEN'a ulaşmış bir anahtar re-mint EDİLMEZ, mevcut değer kullanılır
	// §8.6.4). found=false → anahtar henüz store'a yazılmamış.
	ReadValue(ctx context.Context, project, key string) (val []byte, version uint64, found bool, err error)
}

// StubValueStore, üretim değer-yazımının YER-TUTUCUSUDUR (DEFER): gerçek yol
// internal/store v2 istemcisiyle plaintext PUT/Import'tur (canlı oturum/
// service-token gerekir). Her çağrı ErrLiveExecutionNotWired.
type StubValueStore struct{}

func (StubValueStore) WriteValue(context.Context, string, string, []byte) (uint64, error) {
	return 0, ErrLiveExecutionNotWired
}

func (StubValueStore) ReadValue(context.Context, string, string) ([]byte, uint64, bool, error) {
	return nil, 0, false, ErrLiveExecutionNotWired
}

var _ ValueStore = StubValueStore{}

// MemValueStore, ValueStore'un bellek-içi test uygulamasıdır: yazımları SIRAYLA
// kaydeder (store-first iddiaları için), per-key sürümü artırır ve resume re-fetch
// için SON değeri saklar (ReadValue). Writes kaydı yalnızca uzunluk+sürüm taşır
// (ordering iddiaları); latest, STORE_WRITTEN resume'unun re-mint YERİNE okuduğu
// değerdir (test store).
type MemValueStore struct {
	mu       sync.Mutex
	versions map[string]uint64
	latest   map[string][]byte
	Writes   []ValueWrite
}

// ValueWrite, MemValueStore'a yapılan tek bir yazımın kaydıdır.
type ValueWrite struct {
	Project string
	Key     string
	Version uint64
	ValLen  int
}

// NewMemValueStore, boş bir bellek-içi değer-store'u kurar.
func NewMemValueStore() *MemValueStore {
	return &MemValueStore{versions: map[string]uint64{}, latest: map[string][]byte{}}
}

func (m *MemValueStore) WriteValue(_ context.Context, project, key string, newVal []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := stateKey(project, key)
	m.versions[k]++
	v := m.versions[k]
	m.latest[k] = append([]byte(nil), newVal...)
	m.Writes = append(m.Writes, ValueWrite{Project: project, Key: key, Version: v, ValLen: len(newVal)})
	return v, nil
}

// ReadValue, en son store-first yazılmış değeri + sürümü geri okur (resume: re-mint
// YERİNE). found=false → anahtar henüz hiç yazılmamış.
func (m *MemValueStore) ReadValue(_ context.Context, project, key string) ([]byte, uint64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := stateKey(project, key)
	v, ok := m.latest[k]
	if !ok {
		return nil, 0, false, nil
	}
	return append([]byte(nil), v...), m.versions[k], true, nil
}

// Version, bir anahtarın mevcut store sürümünü döner (0 = hiç yazılmamış).
func (m *MemValueStore) Version(project, key string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.versions[stateKey(project, key)]
}

// WroteBefore, project/key yazımının belirli bir global sıradan önce olup olmadığını
// (store-first iddiaları) bilmek için yazım index'ini döner (-1 = yok).
func (m *MemValueStore) WriteIndex(project, key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, w := range m.Writes {
		if w.Project == project && w.Key == key {
			return i
		}
	}
	return -1
}

// --- Engine -----------------------------------------------------------------

// Engine, rotasyon-yürütme motorudur: bir worklist'i (offboard step 3 VEYA migration
// Phase 2) tipli recipe'lerle yürütür, per-key durumu ledger'a sürer, idempotent
// resume eder. Migration motoru + offboard motoru TEK bu motoru çağırır (SPEC §8.6).
type Engine struct {
	ledger  *RunLedger
	values  ValueStore
	recipes map[string]Recipe
	now     func() time.Time
}

// Config, Engine bağımlılıkları.
type Config struct {
	Ledger  *RunLedger
	Values  ValueStore        // nil → StubValueStore (canlı wiring pending)
	Recipes map[string]Recipe // nil → DefaultRecipes()
	Now     func() time.Time
}

// NewEngine, verilen config'le bir motor kurar.
func NewEngine(cfg Config) *Engine {
	if cfg.Values == nil {
		cfg.Values = StubValueStore{}
	}
	if cfg.Recipes == nil {
		cfg.Recipes = DefaultRecipes()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{ledger: cfg.Ledger, values: cfg.Values, recipes: cfg.Recipes, now: cfg.Now}
}

// Ledger, motorun ledger'ını dışa açar (CLI/test).
func (e *Engine) Ledger() *RunLedger { return e.ledger }

// RunReport, bir Run çağrısının özetidir.
type RunReport struct {
	RunID      string
	Done       int
	Skipped    int
	Triaged    int      // metadata-eksik (blocker)
	MirrorOnly []string // origin:"tofu" — store-tarafı mint reddedildi (§8.6.5)
	Paused     []string // manuel onay bekleyen anahtarlar (project/key)
	Processed  int      // bu çağrıda ilerletilen (skip edilmeyen) girdi
}

// Confirmations, manuel recipe'ler (cf-manual/provider-manual) için per-key insan
// onay token'larını Run'a taşır (§8.6.4 tamamlanma tarafı). İnsan-attestasyonu
// ZORUNLU: token yalnızca gerçek bir insan TTY'sinden gelebilir — IsAgent true iken
// token verilirse Run AGENT_MODE_REFUSED ile reddeder (agent/CI onay ÜRETEMEZ).
type Confirmations struct {
	// IsAgent, çağıranın ajan/CI bağlamında olup olmadığıdır (agentmode.IsAgent()).
	IsAgent bool
	// Tokens, stateKey(project,key) → insan-onay token'ı.
	Tokens map[string]string
}

// token, verilen anahtar için onay token'ını döner (yoksa ""). nil-güvenli.
func (c *Confirmations) token(project, key string) string {
	if c == nil {
		return ""
	}
	return c.Tokens[stateKey(project, key)]
}

// runError, bir girdide durup resume'a bırakan hata + kalıcılaştırma.
func (e *Engine) fail(runID string, en entryCtx, by, state, note string) error {
	_ = e.ledger.Record(runID, en.Project, en.Key, StateFailed, by, map[string]any{"at_state": state, "note": note})
	return fmt.Errorf("rotation.Run: %s @%s: %s", en.Key, state, note)
}

type entryCtx struct {
	Project string
	Key     string
}

// Run, worklist'i yürütür (SPEC §8.6.4). İDEMPOTENT + RESUMABLE: her girdi ledger'daki
// EN SON durumundan devralınır — DONE/SKIPPED atlanır, aksi halde durum makinesi
// PENDING'den (idempotent recipe'lerle) yeniden sürülür. Girdiler blast-tier +
// ordering_constraints (phase1-first/gateway-last) TOPOLOJİSİNE göre sıralanır.
// Manuel recipe onay yoksa DURAKLAR (Paused'a eklenir); metadata-eksik girdi
// TRİYAJ ile bloklanır ve rotate EDİLMEZ.
func (e *Engine) Run(ctx context.Context, wl *Worklist, exec Executor, by string, confirms *Confirmations) (RunReport, error) {
	rep := RunReport{RunID: wl.RunID}
	// Onay token'ı YALNIZCA insan TTY'sinden gelebilir: ajan/CI modunda token
	// verilirse yapısal reddet (AGENT_MODE_REFUSED) — hiçbir plan/side-effect'ten önce.
	if confirms != nil && confirms.IsAgent && len(confirms.Tokens) > 0 {
		return rep, agentmode.Guard(agentmode.PolicyTTY, true)
	}
	if err := e.ledger.EnsurePlan(wl); err != nil {
		return rep, err
	}
	states, err := e.ledger.LatestStates(wl.RunID)
	if err != nil {
		return rep, err
	}
	// FurthestProgress: resume, her anahtarı KAYITLI en ileri durumdan devralır
	// (FAILED bir satır ilerlemeyi geri almaz) — PENDING'den DEĞİL (§8.6.4).
	progress, err := e.ledger.FurthestProgress(wl.RunID)
	if err != nil {
		return rep, err
	}

	entries := orderEntries(wl.Entries)
	for _, en := range entries {
		ec := entryCtx{Project: en.Project, Key: en.Key}
		prev := states[stateKey(en.Project, en.Key)]

		// Terminal → resume atlar.
		if prev == StateDone {
			rep.Done++
			continue
		}
		if prev == StateSkipped {
			rep.Skipped++
			continue
		}

		// Metadata-eksik → TRİYAJ (blocker). Rotate ETMEZ; run terminal olamaz.
		if en.NeedsTriage {
			if prev != StateNeedsTriage {
				_ = e.ledger.Record(wl.RunID, en.Project, en.Key, StateNeedsTriage, by,
					map[string]any{"reason": "ROTATION_METADATA_MISSING"})
			}
			rep.Triaged++
			continue
		}

		// origin:"tofu" → MIRROR-ONLY (§8.6.5): store-tarafı value-mint REDDEDİLİR.
		// Değer origin'de (tofu/DB recipe → tofu apply → sync) döndürülür; bu motor
		// onu MİNT ETMEZ. Non-terminal → run, sync landing'e kadar pending kalır.
		if en.Origin == OriginTofu {
			if prev != StateMirrorOnly {
				_ = e.ledger.Record(wl.RunID, en.Project, en.Key, StateMirrorOnly, by,
					map[string]any{"reason": "TF_ORIGIN_MIRROR_ONLY", "rotate_at": "origin (tofu apply → sync)"})
			}
			rep.MirrorOnly = append(rep.MirrorOnly, en.Project+"/"+en.Key)
			continue
		}

		recipe, ok := e.recipes[en.Recipe]
		if !ok {
			return rep, e.fail(wl.RunID, ec, by, prev, fmt.Sprintf("unknown recipe %q: %v", en.Recipe, ErrUnknownRecipe))
		}
		req := Request{
			Project: en.Project, Key: en.Key,
			Params: entryParams(en), Exec: exec, Now: e.now,
			Confirm: confirms.token(en.Project, en.Key),
		}

		resumeFrom := progress[stateKey(en.Project, en.Key)]
		paused, perr := e.driveKey(ctx, wl.RunID, recipe, req, by, resumeFrom)
		if perr != nil {
			return rep, perr
		}
		if paused {
			rep.Paused = append(rep.Paused, en.Project+"/"+en.Key)
			rep.Processed++
			continue
		}
		rep.Done++
		rep.Processed++
	}
	return rep, nil
}

// driveKey, tek bir anahtarın durum makinesini yürütür (VALUE_MINTED → STORE_WRITTEN
// → CONSUMER_UPDATED → VERIFIED → DONE), her geçişi ledger'a yazar. RESUME (§8.6.4):
// anahtar KAYITLI en ileri durumundan (resumeFrom) devralınır, PENDING'den DEĞİL —
// STORE_WRITTEN'a ulaşmış bir anahtar YENİDEN mint/store-write EDİLMEZ (aksi halde
// canlı executor'la ikinci bir kimlik-bilgisi basılır, ikinci ALTER ROLE/env-PATCH
// koşulur, yeni store sürümü yazılır); saklanan değer geri okunur. CONSUMER_UPDATED'a
// ulaşmışsa Apply ATLANIR; yalnızca kalan Verify (+DONE) koşar. Manuel recipe onay
// yoksa CONSUMER_UPDATED'da DURAKLAR (paused=true) — resume onay token'ıyla ilerletir.
// Hata durumunda FAILED yazılır ve yayılır (resume).
func (e *Engine) driveKey(ctx context.Context, runID string, recipe Recipe, req Request, by, resumeFrom string) (paused bool, err error) {
	ec := entryCtx{Project: req.Project, Key: req.Key}

	var newVal []byte
	var version uint64

	if !recipe.Manual() && reachedState(resumeFrom, StateStoreWritten) {
		// RESUME: değer zaten store'a yazılmış → re-mint/re-write ETME, geri oku.
		// Manuel recipe'ler store'a yazmaz → bu yol yalnızca oto-recipe'ler içindir.
		val, ver, found, rerr := e.values.ReadValue(ctx, req.Project, req.Key)
		if rerr != nil {
			return false, e.fail(runID, ec, by, StateStoreWritten, "resume read stored value: "+rerr.Error())
		}
		if !found {
			return false, e.fail(runID, ec, by, StateStoreWritten, "resume: stored value missing")
		}
		newVal, version = val, ver
	} else {
		// 1) VALUE_MINTED — taze değer üret (henüz store'a yazılmadı → re-mint güvenli).
		var rerr error
		newVal, rerr = recipe.Rotate(ctx, req)
		if rerr != nil {
			return false, e.fail(runID, ec, by, StateValueMinted, rerr.Error())
		}
		if !recipe.Manual() && len(newVal) == 0 {
			return false, e.fail(runID, ec, by, StateValueMinted, "recipe minted empty value")
		}
		_ = e.ledger.Record(runID, req.Project, req.Key, StateValueMinted, by,
			map[string]any{"recipe": recipe.Type(), "val_len": len(newVal)})

		// 2) STORE_WRITTEN (store-first §8.6.1) — manuel recipe'ler için değer insan
		// tarafından set edilir; motor placeholder yazmaz (skip store-write, onayı bekle).
		if !recipe.Manual() {
			var werr error
			version, werr = e.values.WriteValue(ctx, req.Project, req.Key, newVal)
			if werr != nil {
				return false, e.fail(runID, ec, by, StateStoreWritten, werr.Error())
			}
			_ = e.ledger.Record(runID, req.Project, req.Key, StateStoreWritten, by,
				map[string]any{"version": version})
		}
	}

	// 3) CONSUMER_UPDATED — Apply (resume: zaten ulaşıldıysa ATLA; manuel: onay yoksa DURAKLA).
	if !reachedState(resumeFrom, StateConsumerUpdated) {
		if aerr := recipe.Apply(ctx, req, newVal); aerr != nil {
			if recipe.Manual() && errors.Is(aerr, ErrConfirmationRequired) {
				// DURAKLA: insan-attestasyonu bekleniyor (§8.6.4). FAILED değil — non-
				// terminal VALUE_MINTED'ta kalır, resume onayla ilerletir.
				return true, nil
			}
			return false, e.fail(runID, ec, by, StateConsumerUpdated, aerr.Error())
		}
		_ = e.ledger.Record(runID, req.Project, req.Key, StateConsumerUpdated, by,
			map[string]any{"manual": recipe.Manual()})
	}

	// 4) VERIFIED — (resume: zaten doğrulanmışsa ATLA).
	if !reachedState(resumeFrom, StateVerified) {
		if verr := recipe.Verify(ctx, req, newVal); verr != nil {
			return false, e.fail(runID, ec, by, StateVerified, verr.Error())
		}
		_ = e.ledger.Record(runID, req.Project, req.Key, StateVerified, by, nil)
	}

	// 5) DONE + rotasyon-metadata done-kriteri (§10.2.6).
	_ = e.ledger.Record(runID, req.Project, req.Key, StateDone, by, map[string]any{
		"recipe":          recipe.Type(),
		"rotated_at":      req.now().Format(time.RFC3339),
		"worklist_run_id": runID,
		"verified":        req.Params["verify"],
		"key_version":     version,
	})
	return false, nil
}

// entryParams, worklist girdisinden recipe params'ını kurar (project/key +
// ordering ipuçları; canlı params recipe_params'tan gelir — burada temel).
func entryParams(en WorklistEntry) map[string]string {
	p := map[string]string{"project": en.Project, "key": en.Key}
	if len(en.OrderingConstraints) > 0 {
		p["ordering"] = joinConstraints(en.OrderingConstraints)
	}
	return p
}

func joinConstraints(cs []string) string {
	out := ""
	for i, c := range cs {
		if i > 0 {
			out += ","
		}
		out += c
	}
	return out
}

// orderEntries, worklist girdilerini blast-tier + ordering_constraints topolojisine
// göre sıralar (SPEC §8.6.3): en yüksek blast önce; tier içinde phase1-first ÖNCE,
// gateway-last SONRA; sonra proje + anahtar (deterministik). EmitWorklist
// yalnızca tier→proje→anahtar sıralar; ordering-topolojisini G11 motoru uygular.
func orderEntries(in []WorklistEntry) []WorklistEntry {
	out := make([]WorklistEntry, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ta, tb := tierOrdinal(a.BlastTier), tierOrdinal(b.BlastTier); ta != tb {
			return ta < tb
		}
		if ca, cb := constraintRank(a.OrderingConstraints), constraintRank(b.OrderingConstraints); ca != cb {
			return ca < cb
		}
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Key < b.Key
	})
	return out
}

// tierOrdinal, blast-tier sıralama ordinal'i (SPEC §8.6.3; lifecycle sabitleri).
// Metadata eksikliği (unknown/triage) HER ŞEYDEN önce (blocker).
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

// constraintRank, ordering_constraints'i tier-içi sıraya çevirir: phase1-first ÖNCE
// (0), kısıtsız (1), gateway-last SONRA (2). vaulter Phase 2: migrator → phase1 →
// servisler → gateway LAST (§10.4.3).
func constraintRank(cs []string) int {
	first, last := false, false
	for _, c := range cs {
		switch c {
		case "phase1-first", "migrator-first":
			first = true
		case "gateway-last":
			last = true
		}
	}
	switch {
	case first:
		return 0
	case last:
		return 2
	default:
		return 1
	}
}
