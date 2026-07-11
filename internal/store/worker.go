package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/intent"
)

// Config, bir WorkerStore'un bağımlılıklarıdır. Tüm dış kenarlar (HTTP, saat,
// disk yolları) enjekte edilebilir — bu yüzden store tam test-edilebilir.
type Config struct {
	// BaseURL, secrets-gate Worker kökü (örn. https://secrets.meapps.dev).
	BaseURL string
	// Doer, HTTP taşıması; nil ise http.DefaultClient.
	Doer httpDoer
	// Auth, her isteğe oturum/token header'ı ekler (CF Access JWT veya minted
	// Bearer). nil olabilir (test/anonim). Hata dönerse istek yapılmaz.
	Auth func(*http.Request) error
	// PinPath, trust pin deposu (roots.json). Boşsa trust.DefaultPinPath().
	PinPath string
	// CacheDir, ciphertext önbellek dizini. Boşsa cache.DefaultDir().
	CacheDir string
	// EpochPinPath, per-proje DATA epoch pin dosyası. Boşsa DefaultEpochPinPath().
	EpochPinPath string
	// Witness, deploy-intent escrow-tanık çapraz kontrolü için tanık origin'idir
	// (§7.3.4/§9.3). nil ise deploy fail-closed (WITNESS_NOT_WIRED) — G10 gerçek
	// non-CF origin'i enjekte eder. dev intent'i ETKİLEMEZ.
	Witness intent.Witness
	// Now, saat (test için). Boşsa time.Now.
	Now func() time.Time
}

// WorkerStore, Store'u secrets-gate Worker HTTP sözleşmesi üzerinden uygular.
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

func (w *WorkerStore) now() time.Time { return w.cfg.Now() }

// errOffline, taşıma katmanında (bağlantı hatası/timeout) Worker'a
// ulaşılamadığını işaret eder. Fetch bunu çevrimdışı fallback'e, Commit'i
// OFFLINE_WRITE_BLOCKED'e çevirir.
var errOffline = errors.New("store: worker unreachable")

// httpResp, bir Worker yanıtının çözülmüş halidir.
type httpResp struct {
	status int
	body   []byte
	etag   string
	header http.Header
}

// do, bir Worker isteği yapar. Taşıma hatası → errOffline. Aksi halde gövde
// tamamen okunur (Worker yanıtları küçük: manifest ≤1MB, blob ≤64KB).
func (w *WorkerStore) do(ctx context.Context, method, path string, ifNoneMatch string, body []byte, headers map[string]string) (*httpResp, error) {
	u, err := url.JoinPath(w.cfg.BaseURL, path)
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "bad worker path")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "build request")
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", `"`+ifNoneMatch+`"`)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if w.cfg.Auth != nil {
		if err := w.cfg.Auth(req); err != nil {
			return nil, err
		}
	}
	resp, err := w.cfg.Doer.Do(req)
	if err != nil {
		return nil, errOffline
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB güvenlik tavanı
	if err != nil {
		return nil, errOffline
	}
	etag := trimETag(resp.Header.Get("ETag"))
	return &httpResp{status: resp.StatusCode, body: raw, etag: etag, header: resp.Header}, nil
}

// trimETag, W/ ve çift-tırnakları soyar.
func trimETag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "W/")
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// workerError, Worker'ın makine-okunur hata gövdesidir ({error, message, ...}).
type workerError struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
	// EPOCH_CONFLICT detay alanları (§6.2).
	CurrentEpoch       uint64 `json:"current_epoch"`
	CurrentManifestSHA string `json:"current_manifest_sha256"`
	Reason             string `json:"reason"`
}

// parseWorkerError, gövdeyi güvenle çözer (parse edilemezse boş — ham HTML
// transcript'e taşınmaz).
func parseWorkerError(body []byte) workerError {
	var we workerError
	_ = json.Unmarshal(body, &we)
	return we
}

// mapHTTPError, bir non-2xx/304 Worker yanıtını CLI hata sözleşmesine (§7.5)
// eşler. Ham gövde ASLA yayılmaz — yalnızca kod + kısa mesaj.
func mapHTTPError(r *httpResp, ctxMsg string) error {
	we := parseWorkerError(r.body)
	switch r.status {
	case http.StatusUnauthorized: // 401
		return clierr.Newf(clierr.AuthExpired, "%s: worker rejected session (%s)", ctxMsg, safeCode(we.Error))
	case http.StatusForbidden: // 403
		switch we.Error {
		case "MACHINE_TOKEN_REQUIRED", "TOKEN_EXPIRED", "TOKEN_REVOKED":
			return clierr.Newf(clierr.AuthExpired, "%s: machine token invalid (%s)", ctxMsg, safeCode(we.Error))
		default:
			return clierr.Newf(clierr.GrantDenied, "%s: %s", ctxMsg, safeCode(we.Error))
		}
	case http.StatusNotFound: // 404
		return clierr.Newf(clierr.Internal, "%s: not found (%s)", ctxMsg, safeCode(we.Error))
	case http.StatusConflict: // 409 — TRUST_EPOCH_STALE vb.
		return clierr.Newf(clierr.CASConflict, "%s: %s", ctxMsg, safeCode(we.Error))
	case http.StatusPreconditionFailed: // 412 — EPOCH_CONFLICT (commit'te özel ele alınır)
		return clierr.Newf(clierr.CASConflict, "%s: epoch conflict", ctxMsg)
	case http.StatusRequestEntityTooLarge: // 413
		return clierr.Newf(clierr.BlobTooLarge, "%s: %s", ctxMsg, safeCode(we.Error))
	case http.StatusUnprocessableEntity: // 422
		if we.Error == "ESCROW_WRAP_MISSING" {
			return clierr.Newf(clierr.EscrowWrapMissing, "%s", ctxMsg)
		}
		return clierr.Newf(clierr.Internal, "%s: %s", ctxMsg, safeCode(we.Error))
	case http.StatusTooManyRequests: // 429
		return clierr.Newf(clierr.RateLimited, "%s: rate limited (retry after %ds)", ctxMsg, r.retryAfter())
	case http.StatusServiceUnavailable: // 503
		return clierr.Newf(clierr.Internal, "%s: service misconfigured (%s)", ctxMsg, safeCode(we.Error))
	default:
		return clierr.Newf(clierr.Internal, "%s: unexpected status %d", ctxMsg, r.status)
	}
}

// retryAfter, Retry-After header'ını (veya gövde retry_after) döner; yoksa 60.
func (r *httpResp) retryAfter() int {
	if v := r.header.Get("Retry-After"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	if we := parseWorkerError(r.body); we.RetryAfter > 0 {
		return we.RetryAfter
	}
	return 60
}

// safeCode, bir Worker hata kodunu güvenli (kısa, alfanumerik) bir dizeye
// indirger — ham gövde/HTML sızmaz.
func safeCode(code string) string {
	if code == "" {
		return "unknown"
	}
	if len(code) > 48 {
		code = code[:48]
	}
	// Yalnızca güvenli karakterler.
	out := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}
