// Package binding, repo→proje bağlama pin'lerini yönetir (SPEC §7.7). Bir
// repo'daki .wapps.yaml bir proje ADI verir, ama repo içindeki bir dosya
// saldırgan-yazılabilir içeriktir (confused-deputy dikişi, §2 dikiş 4). Bu
// yüzden bağlama, GÜVENİLEN home-dir'de pinlenir — repo'da DEĞİL:
// ~/.config/wapps/repo-pins.json.
//
//   - İLK İNSAN KULLANIMINDA (TTY) CLI bağlamayı pinler: (repo remote/parmak
//     izi) → proje.
//   - Pinlenmemiş bir bağlamaya çarpan bir AJAN (veya non-TTY) BINDING_UNPINNED
//     ile başarısız olmalı — asla pinleyemez, asla pinsiz ilerleyemez.
//   - Pinli bir repo'nun .wapps.yaml'ı daha sonra FARKLI bir proje isimlerse,
//     tüm modlarda hard fail (re-pin bir insanın trust-repo çalıştırmasını ister).
package binding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// Schema, pin deposu şemasıdır.
const Schema = "wapps-repo-pins/v1"

// Hata sözleşmesi.
var (
	// ErrUnpinned: bağlama hiç pinlenmemiş (BINDING_UNPINNED).
	ErrUnpinned = errors.New("binding: BINDING_UNPINNED")
	// ErrMismatch: pinli bağlama farklı bir proje isimliyor (re-pin gerekir).
	ErrMismatch = errors.New("binding: BINDING_MISMATCH")
)

// Pin, tek bir repo→proje bağlamasıdır.
type Pin struct {
	Repo    string `json:"repo"`    // insan-okunur repo kimliği (remote URL veya yol)
	Project string `json:"project"` // pinlenmiş proje
	Backend string `json:"backend"` // "store" (bağlama yalnızca store için anlamlı)
}

// Store, home-dir pin deposudur; repo parmak iziyle anahtarlanır.
type Store struct {
	Schema string         `json:"schema"`
	Pins   map[string]Pin `json:"pins"` // fingerprint → Pin
}

// DefaultPath, ~/.config/wapps/repo-pins.json döner (XDG_CONFIG_HOME onurlandırılır).
func DefaultPath() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps", "repo-pins.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("binding: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "wapps", "repo-pins.json"), nil
}

// Fingerprint, bir repo bağlamasının kararlı parmak izini döner. Öncelik repo
// remote URL'idir (birden çok checkout aynı pini paylaşır); yoksa mutlak repo
// yoluna düşülür. Parmak izi, kimliğin SHA-256 hex'idir — pin deposu anahtarı.
func Fingerprint(repoIdentity string) string {
	sum := sha256.Sum256([]byte(repoIdentity))
	return hex.EncodeToString(sum[:])
}

// Load, pin deposunu okur. Dosya yoksa BOŞ bir depo döner (ilk kullanım) —
// os.ErrNotExist bir hata sayılmaz.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{Schema: Schema, Pins: map[string]Pin{}}, nil
		}
		return nil, fmt.Errorf("binding.Load: read %s: %w", path, err)
	}
	var s Store
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("binding.Load: parse %s: %w", path, err)
	}
	if s.Schema != Schema {
		return nil, fmt.Errorf("binding.Load: unexpected schema %q", s.Schema)
	}
	if s.Pins == nil {
		s.Pins = map[string]Pin{}
	}
	return &s, nil
}

// Save, pin deposunu ATOMİK olarak 0600 modunda yazar.
func (s *Store) Save(path string) error {
	if s.Schema == "" {
		s.Schema = Schema
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("binding.Store.Save: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("binding.Store.Save: mkdir: %w", err)
	}
	return ageutil.WriteFileAtomic(path, raw, 0o600)
}

// Check, bir repo parmak izi + .wapps.yaml'ın verdiği proje için bağlamayı
// doğrular:
//   - pin yok        → ErrUnpinned (ajan durur, insan trust-repo ile pinler)
//   - pin var, eşleşir → nil
//   - pin var, farklı → ErrMismatch (re-pin bir insan ister)
func (s *Store) Check(fingerprint, project string) error {
	pin, ok := s.Pins[fingerprint]
	if !ok {
		return fmt.Errorf("binding.Check: no pin for repo: %w", ErrUnpinned)
	}
	if pin.Project != project {
		return fmt.Errorf("binding.Check: pinned %q but .wapps.yaml says %q: %w", pin.Project, project, ErrMismatch)
	}
	return nil
}

// Pin, bir bağlamayı pinler (yalnızca insan/TTY yolundan çağrılır). Aynı repo
// için farklı bir projeye üzerine yazmak açık bir re-pin'dir ve serbesttir.
func (s *Store) Pin(fingerprint string, p Pin) {
	if s.Pins == nil {
		s.Pins = map[string]Pin{}
	}
	s.Pins[fingerprint] = p
}
