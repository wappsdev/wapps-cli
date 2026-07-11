package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// PinSchema, yerel pin deposu şeması (SPEC §4.4).
const PinSchema = "wapps-pins/v1"

// Pin, bir güven epoch'unun {admin_epoch, sha256} referansıdır (SPEC §4.4).
// VerifiedAt yalnızca last_verified için doldurulur; genesis'te boştur.
type Pin struct {
	AdminEpoch uint64     `json:"admin_epoch"`
	SHA256     string     `json:"sha256"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// PinStore, her istemcinin taşıdığı iki pin'dir (SPEC §4.4): derlenmiş/ilk
// genesis pin'i ve monotonik last-verified yüksek-su-işareti. Yerel konum:
// ~/.config/wapps/roots.json (XDG_CONFIG_HOME onurlandırılır).
type PinStore struct {
	Schema       string `json:"schema"`
	Genesis      Pin    `json:"genesis"`
	LastVerified Pin    `json:"last_verified"`
}

// --- Derlenmiş (compiled-in) genesis pin — sürüm binary'sine gömülür ---
//
// Sürüm binary'leri genesis hash'ini TAŞIR (SPEC §4.4). Bu değerler:
//   - Sürümde -ldflags ile gömülür:
//     -X github.com/wappsdev/wapps-cli/internal/trust.compiledGenesisSHA256=<hex>
//   - Programatik olarak SetCompiledGenesis ile enjekte edilir (araç/test).
//
// Boşsa (geliştirme derlemesi) CompiledGenesis ok=false döner; istemci o zaman
// yalnızca roots.json'a dayanır ve derlenmiş-vs-yerel çakışması aranmaz.
var (
	compiledGenesisSHA256 = ""
	compiledGenesisEpoch  = ""
)

// SetCompiledGenesis, derlenmiş genesis pin'ini programatik olarak enjekte eder
// (araç gömme/test). -ldflags string enjeksiyonuna alternatiftir.
func SetCompiledGenesis(p Pin) {
	compiledGenesisSHA256 = p.SHA256
	compiledGenesisEpoch = fmt.Sprintf("%d", p.AdminEpoch)
}

// CompiledGenesis, gömülü genesis pin'ini döner. ok=false ise gömülü pin yok
// (geliştirme derlemesi).
func CompiledGenesis() (Pin, bool) {
	if compiledGenesisSHA256 == "" {
		return Pin{}, false
	}
	epoch := GenesisEpoch
	if compiledGenesisEpoch != "" {
		var e uint64
		if _, err := fmt.Sscanf(compiledGenesisEpoch, "%d", &e); err == nil && e > 0 {
			epoch = e
		}
	}
	return Pin{AdminEpoch: epoch, SHA256: compiledGenesisSHA256}, true
}

// DefaultPinPath, ~/.config/wapps/roots.json döner (XDG_CONFIG_HOME onurlandırılır),
// internal/projects.DefaultPath ile aynı stil.
func DefaultPinPath() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps", "roots.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("trust: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "wapps", "roots.json"), nil
}

// LoadPinStore, roots.json'u okur ve ayrıştırır. Dosya yoksa os.ErrNotExist
// sarmalayan bir hata döner (çağıran derlenmiş genesis'e düşer, §4.4).
func LoadPinStore(path string) (*PinStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("trust.LoadPinStore: %s: %w", path, err)
		}
		return nil, fmt.Errorf("trust.LoadPinStore: read %s: %w", path, err)
	}
	var p PinStore
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("trust.LoadPinStore: parse %s: %w", path, err)
	}
	if p.Schema != PinSchema {
		return nil, fmt.Errorf("trust.LoadPinStore: %q: %w", p.Schema, ErrUnsupportedSchema)
	}
	return &p, nil
}

// Save, pin deposunu ATOMİK olarak (temp + fsync + rename) 0600 modunda yazar
// (SPEC §4.4 — mevcut wapps-cli dosya-yazma disiplini, ageutil.WriteFileAtomic).
func (p *PinStore) Save(path string) error {
	if p.Schema == "" {
		p.Schema = PinSchema
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("trust.PinStore.Save: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("trust.PinStore.Save: mkdir: %w", err)
	}
	return ageutil.WriteFileAtomic(path, raw, 0o600)
}

// AdvanceLastVerified, last_verified pin'ini yeni bir epoch'a ilerletir. Pin
// MONOTONİKTİR (SPEC §4.4): admin_epoch ASLA azalamaz. Azaltacak her yol
// TRUST_DOWNGRADE ile hard-fail eder. Aynı epoch'a farklı bir hash yazmak da
// bir çakışmadır ve reddedilir.
func (p *PinStore) AdvanceLastVerified(newPin Pin) error {
	if newPin.AdminEpoch < p.LastVerified.AdminEpoch {
		return fmt.Errorf("trust.AdvanceLastVerified: %d < pinned %d: %w",
			newPin.AdminEpoch, p.LastVerified.AdminEpoch, ErrTrustDowngrade)
	}
	if newPin.AdminEpoch == p.LastVerified.AdminEpoch &&
		p.LastVerified.SHA256 != "" && newPin.SHA256 != p.LastVerified.SHA256 {
		return fmt.Errorf("trust.AdvanceLastVerified: epoch %d hash conflict: %w",
			newPin.AdminEpoch, ErrTrustDowngrade)
	}
	if newPin.VerifiedAt == nil {
		now := time.Now().UTC()
		newPin.VerifiedAt = &now
	}
	p.LastVerified = newPin
	return nil
}

// CheckGenesisAgainstCompiled, derlenmiş genesis pin'i ile yerel roots.json
// genesis pin'inin uyuştuğunu doğrular (SPEC §4.4). Uyuşmazsa TRUST_PIN_CONFLICT
// — sessizce birini tercih ETMEZ; kullanıcıyı re-pin seremonisine (§4.10)
// yönlendirir. Derlenmiş pin yoksa (geliştirme derlemesi) kontrol atlanır.
func (p *PinStore) CheckGenesisAgainstCompiled() error {
	compiled, ok := CompiledGenesis()
	if !ok {
		return nil
	}
	if compiled.AdminEpoch != p.Genesis.AdminEpoch || compiled.SHA256 != p.Genesis.SHA256 {
		return fmt.Errorf("trust.CheckGenesisAgainstCompiled: compiled genesis != roots.json genesis: %w", ErrTrustPinConflict)
	}
	return nil
}

// ResolveGenesis, etkin genesis pin'ini çözer (SPEC §4.4): roots.json varsa ondan
// (derlenmiş pin ile çakışma kontrol edilir), yoksa derlenmiş genesis'e düşer.
// Hiçbiri yoksa TRUST_PIN_MISSING.
func ResolveGenesis(path string) (Pin, error) {
	store, err := LoadPinStore(path)
	if err == nil {
		if cerr := store.CheckGenesisAgainstCompiled(); cerr != nil {
			return Pin{}, cerr
		}
		if store.Genesis.SHA256 == "" {
			return Pin{}, fmt.Errorf("trust.ResolveGenesis: roots.json has empty genesis: %w", ErrTrustPinMissing)
		}
		return store.Genesis, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Pin{}, err
	}
	// roots.json yok → derlenmiş genesis'e düş (§4.4).
	if compiled, ok := CompiledGenesis(); ok {
		return compiled, nil
	}
	return Pin{}, fmt.Errorf("trust.ResolveGenesis: no roots.json and no compiled genesis: %w", ErrTrustPinMissing)
}

// NewPinStore, verilen genesis pin'iyle taze bir pin deposu kurar; last_verified
// başlangıçta genesis'e eşitlenir (henüz yürünmüş bir zincir yok).
func NewPinStore(genesis Pin) *PinStore {
	return &PinStore{
		Schema:       PinSchema,
		Genesis:      genesis,
		LastVerified: genesis,
	}
}
