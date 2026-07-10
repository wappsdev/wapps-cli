package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// Epoch pin'leri PER-PROJE, forward-only ve monotoniktir (SPEC §7.3.2 rule 4):
// ~/.config/wapps/ altında roots.json'ın yanında tutulur. Sunulan/önbelleklenen
// epoch yerel pin'in ALTINDAYSA EPOCH_DOWNGRADE (rollback saldırısı) — asla
// "yardımsever" kabul edilmez.

const epochPinSchema = "wapps-epoch-pins/v1"

// epochPins, proje → son doğrulanmış data epoch pin'i.
type epochPins struct {
	Schema string            `json:"schema"`
	Pins   map[string]uint64 `json:"pins"`
}

// DefaultEpochPinPath, ~/.config/wapps/epochs.json döner (XDG onurlandırılır).
func DefaultEpochPinPath() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps", "epochs.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("store: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "wapps", "epochs.json"), nil
}

func loadEpochPins(path string) (*epochPins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &epochPins{Schema: epochPinSchema, Pins: map[string]uint64{}}, nil
		}
		return nil, fmt.Errorf("store.loadEpochPins: %w", err)
	}
	var p epochPins
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("store.loadEpochPins: parse: %w", err)
	}
	if p.Pins == nil {
		p.Pins = map[string]uint64{}
	}
	return &p, nil
}

func (p *epochPins) save(path string) error {
	if p.Schema == "" {
		p.Schema = epochPinSchema
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("store.epochPins.save: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("store.epochPins.save: mkdir: %w", err)
	}
	return ageutil.WriteFileAtomic(path, raw, 0o600)
}

// epochPinPath, config'teki yolu veya varsayılanı döner.
func (w *WorkerStore) epochPinPath() (string, error) {
	if w.cfg.EpochPinPath != "" {
		return w.cfg.EpochPinPath, nil
	}
	return DefaultEpochPinPath()
}

// pinnedEpoch, bir projenin son doğrulanmış epoch pin'ini döner (yoksa 0).
func (w *WorkerStore) pinnedEpoch(project string) (uint64, error) {
	path, err := w.epochPinPath()
	if err != nil {
		return 0, err
	}
	p, err := loadEpochPins(path)
	if err != nil {
		return 0, err
	}
	return p.Pins[project], nil
}

// checkAndAdvanceEpochPin, sunulan epoch'un yerel pin'e karşı monotonluğunu
// zorlar (SPEC §7.3.2 rule 3/4). served < pinned → EPOCH_DOWNGRADE (hard fail).
// served ≥ pinned → pin ilerletilir ve kaydedilir (forward-only). Bir
// epoch_reset kaydı bu kuralın TEK istisnasıdır (§9.5) — G8'de kurulmaz.
func (w *WorkerStore) checkAndAdvanceEpochPin(project string, served uint64) error {
	path, err := w.epochPinPath()
	if err != nil {
		return err
	}
	p, err := loadEpochPins(path)
	if err != nil {
		return err
	}
	pinned := p.Pins[project]
	if served < pinned {
		return clierr.Newf(clierr.EpochDowngrade, "served epoch %d < pinned %d for %q", served, pinned, project)
	}
	if served > pinned {
		p.Pins[project] = served
		if err := p.save(path); err != nil {
			return clierr.Wrapf(clierr.Internal, err, "persist epoch pin")
		}
	}
	return nil
}
