// Package cache, wapps-secrets istemcisinin YEREL CIPHERTEXT-ONLY önbelleğini
// sağlar (SPEC §7.3.3). Konum: ~/.config/wapps/cache/<project>.json (mode 0600).
//
// Önbellek YALNIZCA public/ciphertext materyal tutar: zırhlı DEK wrap'leri + blob
// ciphertext'i, imzalı manifest sarmalayıcısı, doğrulanmış trust zinciri, ETag/
// revision, fetched_at ve liveness receipt. DÜZ METİN ASLA yazılmaz; GİZLİ KİMLİK
// (X25519 private) ASLA diske gitmez. Çevrimdışı okuma fallback'i budur (§7.3.4):
// istemci önbelleği pinlere karşı yeniden-doğrular, sonra bellek-içi kimlikle çözer.
package cache

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// Schema, önbellek girdisi şemasıdır.
const Schema = "wapps-cache/v1"

// Entry, tek bir projenin önbelleklenmiş, doğrulanmış anlık görüntüsüdür
// (ciphertext-only). Blobs, içerik-adresli ciphertext blob'larıdır (hash → bayt).
type Entry struct {
	Schema  string `json:"schema"`
	Project string `json:"project"`
	Epoch   uint64 `json:"epoch"`

	// ManifestWrapper, imzalı data-manifest sarmalayıcısının TAM depolanan
	// baytlarıdır (JSON'da base64). Çevrimdışı yazar-imza yeniden doğrulaması için.
	ManifestWrapper []byte `json:"manifest_wrapper"`
	// ETag, manifests/current'ın döndürdüğü ETag'dır (= manifest obje hash'i).
	// Conditional GET'te If-None-Match olarak kullanılır (§7.3.2).
	ETag string `json:"etag"`

	// Blobs, hash → ciphertext blob bayt (JSON'da base64). Yalnızca granted/
	// profile anahtarlarının blob'ları (blast-radius minimizasyonu §2/§7.3.3).
	Blobs map[string][]byte `json:"blobs"`

	// TrustChain, genesis→head imzalı trust sarmalayıcılarıdır (her epoch bir
	// eleman). Çevrimdışı VerifyRosterChain(pin, chain) yeniden doğrulaması için.
	TrustChain [][]byte `json:"trust_chain"`
	// TrustEpoch/TrustSHA256, doğrulanmış trust head referansı (metadata/tutarlılık).
	TrustEpoch  uint64 `json:"trust_epoch"`
	TrustSHA256 string `json:"trust_sha256"`

	// Receipt, en son liveness receipt'i (ham JSON; §6.6). Deploy-intent
	// tazelik değerlendirmesi çevrimiçi yenilenir, bu yalnızca metadata/teşhis.
	Receipt json.RawMessage `json:"receipt,omitempty"`

	// FetchedAt, bu anlık görüntünün ağdan alındığı an (UTC). Önbellek yaşı
	// (cache_age) ve dev-staleness penceresi (§7.3.4) buradan hesaplanır.
	FetchedAt time.Time `json:"fetched_at"`
}

// Age, önbellek girdisinin yaşını döner.
func (e *Entry) Age() time.Duration { return time.Since(e.FetchedAt) }

// DefaultDir, ~/.config/wapps/cache döner (XDG_CONFIG_HOME onurlandırılır),
// trust/projects paketleriyle aynı stil.
func DefaultDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps", "cache"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cache: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "wapps", "cache"), nil
}

// PathFor, bir projenin önbellek dosyası yolunu döner: <dir>/<project>.json.
func PathFor(dir, project string) string {
	return filepath.Join(dir, project+".json")
}

// Load, bir projenin önbellek girdisini okur. Dosya yoksa os.ErrNotExist
// sarmalayan bir hata döner (çağıran çevrimiçi-first yola düşer).
func Load(path string) (*Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cache.Load: %s: %w", path, err)
	}
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("cache.Load: parse %s: %w", path, err)
	}
	if e.Schema != Schema {
		return nil, fmt.Errorf("cache.Load: unexpected schema %q", e.Schema)
	}
	return &e, nil
}

// Save, önbellek girdisini ATOMİK olarak (temp + fsync + rename) 0600 modunda
// yazar (mevcut ageutil.WriteFileAtomic disiplini). Düz metin/kimlik ASLA
// yazılmaz — bu tip yapısal olarak yalnızca ciphertext/public materyal taşır.
func (e *Entry) Save(path string) error {
	if e.Schema == "" {
		e.Schema = Schema
	}
	if e.FetchedAt.IsZero() {
		e.FetchedAt = time.Now().UTC()
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("cache.Entry.Save: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cache.Entry.Save: mkdir: %w", err)
	}
	return ageutil.WriteFileAtomic(path, raw, 0o600)
}
