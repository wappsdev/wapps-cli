// Package store, wapps-secrets istemcisinin TEK okuma/yazma soyutlamasıdır
// (server-decrypt SPEC §7.4): verb'ler asla HTTP/R2 detayı bilmez.
//
// v2 pivotu (SPEC §0/§2.7): zarf kriptosu SUNUCUDA koşar. Worker plaintext
// DÖNER (POST /read) ve plaintext ALIR (PUT/import) — kanal TLS + CF Access.
// İstemcide KEK/unwrap/imza doğrulaması YOKTUR; kalan istemci-tarafı kontroller:
//   - epoch pin tripwire (epochpin.go, §7.4): served epoch < pinned → EPOCH_DOWNGRADE;
//   - makine-okunur hata eşlemesi (§7.5, clierr);
//   - değerler YALNIZCA süreç belleğinde — diske plaintext/ciphertext cache YAZILMAZ.
//
// Çevrimdışı çalışmaz: taşıma hatası = NETWORK_REQUIRED (§1.5, kabul edilmiş).
package store

import (
	"context"
	"net/http"
	"time"
)

// Store, verb'lerin kullandığı v2 istemci arayüzüdür (SPEC §7.4).
type Store interface {
	// Keys, projenin OKUNABİLİR anahtar metadata'sını döner (GET /keys —
	// liste Worker'da principal'ın read grant'ına filtrelenir, §4.3.3).
	Keys(ctx context.Context, project string) (*KeysResult, error)
	// Read, istenen anahtarların PLAINTEXT değerlerini döner (POST /read,
	// all-or-nothing §7.6). keys boş → önce Keys ile okunabilir küme çözülür.
	Read(ctx context.Context, project string, keys []string) (*ReadResult, error)
	// Set, tek bir anahtarı yazar (PUT /keys/{KEY}).
	Set(ctx context.Context, project, key, value string, opts WriteOpts) error
	// Import, birden çok anahtarı TEK atomik epoch'ta yazar (POST /import).
	Import(ctx context.Context, project string, values map[string]string, opts WriteOpts) error
	// Delete, bir anahtarı siler (DELETE /keys/{KEY}; silme = manifest'te yokluk).
	Delete(ctx context.Context, project, key string) error
}

// KeyInfo, bir anahtarın metadata'sı (ASLA değer).
type KeyInfo struct {
	KeyName    string `json:"keyName"`
	KeyVersion uint64 `json:"keyVersion"`
}

// KeysResult, GET /keys yanıtı.
type KeysResult struct {
	Project string    `json:"project"`
	Epoch   uint64    `json:"epoch"`
	Keys    []KeyInfo `json:"keys"`
}

// ReadResult, POST /read yanıtı: plaintext değerler yalnızca süreç belleğinde.
type ReadResult struct {
	Epoch  uint64            `json:"epoch"`
	Values map[string]string `json:"values"`
}

// WriteOpts, yazımların bilgilendirici etiketlerini taşır (§6.4 — ASLA authz girdisi).
type WriteOpts struct {
	// RotationID, doluysa X-Wapps-Rotation header'ı gönderilir (audit: rotate.step).
	RotationID string
	// Sync, true ise X-Wapps-Intent: sync gönderilir (audit: key.sync).
	Sync bool
}

// WhoamiResult, GET /v1/whoami yanıtıdır (principal + gruplar + efektif grant'ler).
type WhoamiResult struct {
	Principal     string   `json:"principal"`
	Kind          string   `json:"kind"`
	Email         string   `json:"email"`
	CommonName    string   `json:"common_name"`
	Groups        []string `json:"groups"`
	PolicyVersion uint64   `json:"policy_version"`
	Grants        []Rule   `json:"grants"`
	IsRootAdmin   bool     `json:"is_root_admin"`
}

// Rule, policy.json kural şekli (§4.2) — CLI görünümü (policy show/lint + whoami).
type Rule struct {
	Group    string   `json:"group,omitempty"`
	Service  string   `json:"service,omitempty"`
	Aud      string   `json:"aud,omitempty"`
	Projects []string `json:"projects"`
	Keys     []string `json:"keys"`
	Verbs    []string `json:"verbs"`
}

// PolicyDoc, policy.json doküman şekli (§4.2).
type PolicyDoc struct {
	Schema  string `json:"schema"`
	Version uint64 `json:"version"`
	Rules   []Rule `json:"rules"`
}

// PolicyResult, GET /v1/policy yanıtı.
type PolicyResult struct {
	Version uint64    `json:"version"`
	SHA256  string    `json:"sha256"`
	Policy  PolicyDoc `json:"policy"`
}

// RotatePlanItem, rotate-plan oracle'ının bir satırı (§6.3).
type RotatePlanItem struct {
	Project  string `json:"project"`
	Key      string `json:"key"`
	LastRead string `json:"last_read"`
	Reads    uint64 `json:"reads"`
}

// RotatePlanResult, GET /v1/admin/rotate-plan yanıtı.
type RotatePlanResult struct {
	Identity    string           `json:"identity"`
	GeneratedAt string           `json:"generated_at"`
	Items       []RotatePlanItem `json:"items"`
}

// Config, bir WorkerStore'un bağımlılıklarıdır. Dış kenarlar (HTTP, saat, pin
// yolu) enjekte edilebilir — store tam test-edilebilir.
type Config struct {
	// BaseURL, secrets-gate Worker kökü (örn. https://gw.meapps.dev).
	BaseURL string
	// Doer, HTTP taşıması; nil ise http.DefaultClient.
	Doer httpDoer
	// Auth, her isteğe oturum/service-token header'larını ekler (SPEC §7.2/§5).
	// Hata dönerse istek ağ'a HİÇ çıkmaz (örn. SESSION_EXPIRED).
	Auth func(*http.Request) error
	// EpochPinPath, per-proje DATA epoch pin dosyası. Boşsa DefaultEpochPinPath().
	EpochPinPath string
	// Now, saat (test için). Boşsa time.Now.
	Now func() time.Time
}

// WorkerStore, Store'u secrets-gate Worker v2 HTTP sözleşmesi üzerinden uygular.
type WorkerStore struct {
	cfg Config
}

// New, verilen config'le bir WorkerStore kurar; boş alanlara üretim
// varsayılanları uygulanır.
func New(cfg Config) *WorkerStore {
	if cfg.Doer == nil {
		cfg.Doer = http.DefaultClient
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &WorkerStore{cfg: cfg}
}

// arayüz uyumluluğu.
var _ Store = (*WorkerStore)(nil)

// httpDoer, enjekte edilebilir HTTP taşımasıdır (üretimde *http.Client; testte
// httptest sunucusu).
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}
