package store

// worker.go, WorkerStore'un HTTP taşıması + v2 rota implementasyonlarıdır
// (SPEC §7.4/§7.6). Ham Worker gövdesi ASLA transcript'e yayılmaz — hatalar
// clierr sözleşmesine eşlenir (§7.5), yalnızca kod + kısa mesaj taşınır.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/intent"
)

// httpResp, bir Worker yanıtının çözülmüş halidir.
type httpResp struct {
	status int
	body   []byte
	header http.Header
}

// do, bir Worker isteği yapar. Taşıma hatası → NETWORK_REQUIRED (çevrimdışı mod
// YOK, §1.5). Gövde tamamen okunur (Worker yanıtları küçük; 2 MB güvenlik tavanı).
func (w *WorkerStore) do(ctx context.Context, method, path string, body []byte, headers map[string]string) (*httpResp, error) {
	// Query string'i path'ten ayır: url.JoinPath '?' karakterini yol segmenti
	// olarak escape ederdi.
	rawQuery := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, rawQuery = path[:i], path[i+1:]
	}
	u, err := url.JoinPath(w.cfg.BaseURL, path)
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "bad worker path")
	}
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "build request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
		return nil, clierr.Wrapf(clierr.NetworkRequired, err, "secrets gate unreachable")
	}
	defer resp.Body.Close()
	// Worker'ın per-request RESPONSE_MAX'i (16 MB) ile HİZALI: tam o kadar + 1 okuruz.
	// Body sınırı AŞARSA sessiz truncate (malformed JSON) yerine AÇIK hata döneriz —
	// Worker zaten >RESPONSE_MAX'te 413 verir, bu son bir emniyet (gerçek sır projeleri
	// « 16 MB).
	const maxBody = 16 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, clierr.Wrapf(clierr.NetworkRequired, err, "secrets gate response truncated")
	}
	if len(raw) > maxBody {
		return nil, clierr.Newf(clierr.NotAvailable, "secrets gate response exceeds %d bytes; request fewer keys", maxBody)
	}
	return &httpResp{status: resp.StatusCode, body: raw, header: resp.Header}, nil
}

// workerError, Worker'ın makine-okunur hata gövdesidir ({error, message, ...detail}).
type workerError struct {
	Error      string `json:"error"`
	RetryAfter int    `json:"retry_after"`
	// GRANT_DENIED / read-path detay alanları (§4.3.4/§7.6).
	Key       string `json:"key"`
	Dimension string `json:"dimension"`
	// POLICY_INVALID / POLICY_CONFLICT detayları (§4.4/§4.1).
	RuleIndex      *int   `json:"rule_index"`
	CurrentVersion uint64 `json:"current_version"`
}

// parseWorkerError, gövdeyi güvenle çözer (parse edilemezse boş — ham HTML
// transcript'e taşınmaz).
func parseWorkerError(body []byte) workerError {
	var we workerError
	_ = json.Unmarshal(body, &we)
	return we
}

// mapHTTPError, bir non-2xx Worker yanıtını CLI hata sözleşmesine (§7.5) eşler.
// Ham gövde ASLA yayılmaz — yalnızca kod + kısa alanlar.
func mapHTTPError(r *httpResp, ctxMsg string) error {
	we := parseWorkerError(r.body)
	switch r.status {
	case http.StatusUnauthorized: // 401 — kenar/Worker oturumu reddetti
		return clierr.Newf(clierr.SessionExpired, "%s: gate rejected the session (%s)", ctxMsg, safeCode(we.Error))
	case http.StatusForbidden: // 403
		switch we.Error {
		case "MACHINE_TOKEN_REQUIRED", "TOKEN_EXPIRED", "TOKEN_REVOKED", "TOKEN_SCOPE_EXCEEDED":
			return clierr.Newf(clierr.SessionExpired, "%s: machine token invalid (%s)", ctxMsg, safeCode(we.Error))
		default:
			if we.Key != "" {
				return clierr.Newf(clierr.GrantDenied, "%s: denied on key %s (dimension %s)", ctxMsg, safeCode(we.Key), safeCode(we.Dimension)).
					WithRecovery("ask an admin to extend policy.json (wapps secrets policy set)")
			}
			return clierr.Newf(clierr.GrantDenied, "%s: %s (dimension %s)", ctxMsg, safeCode(we.Error), safeCode(we.Dimension)).
				WithRecovery("ask an admin to extend policy.json (wapps secrets policy set)")
		}
	case http.StatusNotFound: // 404
		if we.Key != "" {
			return clierr.Newf(clierr.NotFound, "%s: key %s not found", ctxMsg, safeCode(we.Key))
		}
		return clierr.Newf(clierr.NotFound, "%s: not found (%s)", ctxMsg, safeCode(we.Error))
	case http.StatusConflict: // 409 — MIGRATION_FREEZE vb.
		return clierr.Newf(clierr.CASConflict, "%s: %s", ctxMsg, safeCode(we.Error))
	case http.StatusPreconditionFailed: // 412 — EPOCH_CONFLICT | POLICY_CONFLICT
		if we.Error == "POLICY_CONFLICT" {
			return clierr.Newf(clierr.PolicyConflict, "%s: policy version conflict (current %d)", ctxMsg, we.CurrentVersion)
		}
		return clierr.Newf(clierr.CASConflict, "%s: epoch conflict", ctxMsg)
	case http.StatusRequestEntityTooLarge: // 413 — VALUE_TOO_LARGE (per-değer 64KB) VE
		// RESPONSE_TOO_LARGE (agregat bulk-read yanıtı) aynı statüyü paylaşır → koda göre ayır.
		if we.Error == "RESPONSE_TOO_LARGE" {
			return clierr.Newf(clierr.NotAvailable, "%s: read response too large; request fewer keys", ctxMsg)
		}
		return clierr.Newf(clierr.BlobTooLarge, "%s: %s", ctxMsg, safeCode(we.Error))
	case http.StatusUnprocessableEntity: // 422
		if we.Error == "POLICY_INVALID" {
			idx := "?"
			if we.RuleIndex != nil {
				idx = fmt.Sprintf("%d", *we.RuleIndex)
			}
			return clierr.Newf(clierr.PolicyInvalid, "%s: policy invalid (rule index %s)", ctxMsg, idx)
		}
		return clierr.Newf(clierr.Internal, "%s: %s", ctxMsg, safeCode(we.Error))
	case http.StatusTooManyRequests: // 429
		return clierr.Newf(clierr.RateLimited, "%s: rate limited (retry after %ds)", ctxMsg, r.retryAfter())
	case http.StatusServiceUnavailable: // 503 — fail-closed sınıfı (§7.5)
		switch we.Error {
		case "AUDIT_UNAVAILABLE":
			return clierr.Newf(clierr.AuditUnavailable, "%s: audit ledger unavailable — plaintext refused", ctxMsg)
		case "IDENTITY_UNAVAILABLE":
			return clierr.Newf(clierr.IdentityUnavailable, "%s: identity/groups unresolvable", ctxMsg)
		default:
			return clierr.Newf(clierr.ServiceMisconfig, "%s: %s", ctxMsg, safeCode(we.Error))
		}
	default:
		if r.status == http.StatusBadRequest {
			return clierr.Newf(clierr.Internal, "%s: bad request (%s)", ctxMsg, safeCode(we.Error))
		}
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

// safeCode, bir Worker hata kodunu/alanını güvenli (kısa, alfanumerik) bir
// dizeye indirger — ham gövde/HTML sızmaz.
func safeCode(code string) string {
	if code == "" {
		return "unknown"
	}
	if len(code) > 48 {
		code = code[:48]
	}
	out := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// decodeJSON, 200 gövdesini hedefe çözer; bozuk gövde Internal (fail-closed).
func decodeJSON(body []byte, dst any, ctxMsg string) error {
	if err := json.Unmarshal(body, dst); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "%s: malformed gate response", ctxMsg)
	}
	return nil
}

// --- Metadata + okuma (§7.6) --------------------------------------------------

// Keys, GET /v1/projects/{p}/keys — okunabilir anahtar listesi (filtreli, §4.3.3).
func (w *WorkerStore) Keys(ctx context.Context, project string) (*KeysResult, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/projects/"+url.PathEscape(project)+"/keys", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "list "+project)
	}
	var out KeysResult
	if err := decodeJSON(r.body, &out, "list "+project); err != nil {
		return nil, err
	}
	if err := w.checkAndAdvanceEpochPin(project, out.Epoch); err != nil {
		return nil, err
	}
	return &out, nil
}

// Read, POST /v1/projects/{p}/read — PLAINTEXT bulk read (all-or-nothing, tek epoch §7.6).
// keys boş → önce Keys ile principal'ın okunabilir kümesi çözülür; küme boşsa boş sonuç
// döner. Yanıt, Worker'ın per-request RESPONSE_MAX bandıyla (aşağıdaki transport limitiyle
// HİZALI) sınırlıdır; onu aşan patolojik-büyük bir read-all 413 RESPONSE_TOO_LARGE alır
// (gerçek sır projeleri « bu sınır). Bu tek-istek şekli tek-epoch atomikliğini korur.
func (w *WorkerStore) Read(ctx context.Context, project string, keys []string) (*ReadResult, error) {
	if len(keys) == 0 {
		kr, err := w.Keys(ctx, project)
		if err != nil {
			return nil, err
		}
		for _, k := range kr.Keys {
			keys = append(keys, k.KeyName)
		}
		if len(keys) == 0 {
			return &ReadResult{Epoch: kr.Epoch, Values: map[string]string{}}, nil
		}
	}
	sort.Strings(keys)
	body, err := json.Marshal(map[string][]string{"keys": keys})
	if err != nil {
		return nil, clierr.Wrapf(clierr.Internal, err, "encode read request")
	}
	r, err := w.do(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(project)+"/read", body, nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "read "+project)
	}
	var out ReadResult
	if err := decodeJSON(r.body, &out, "read "+project); err != nil {
		return nil, err
	}
	if out.Values == nil {
		out.Values = map[string]string{}
	}
	if err := w.checkAndAdvanceEpochPin(project, out.Epoch); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Yazımlar (§7.6; writer DO serileştirir, epoch+1) ---------------------------

// writeHeaders, bilgilendirici yazım etiketlerini kurar (§6.4).
func writeHeaders(opts WriteOpts) map[string]string {
	h := map[string]string{}
	if opts.RotationID != "" {
		h[intent.HeaderRotation] = opts.RotationID
	}
	if opts.Sync {
		h[intent.HeaderIntent] = intent.IntentSync
	}
	return h
}

// Set, PUT /v1/projects/{p}/keys/{KEY} — tek anahtar yazımı.
func (w *WorkerStore) Set(ctx context.Context, project, key, value string, opts WriteOpts) error {
	body, err := json.Marshal(map[string]string{"value": value})
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "encode set request")
	}
	r, err := w.do(ctx, http.MethodPut,
		"/v1/projects/"+url.PathEscape(project)+"/keys/"+url.PathEscape(key), body, writeHeaders(opts))
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return mapHTTPError(r, "set "+key)
	}
	return nil
}

// Import, POST /v1/projects/{p}/import — bulk atomik yazım (tek epoch).
func (w *WorkerStore) Import(ctx context.Context, project string, values map[string]string, opts WriteOpts) error {
	if len(values) == 0 {
		return clierr.New(clierr.Internal, "import: no values")
	}
	body, err := json.Marshal(map[string]any{"values": values})
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "encode import request")
	}
	r, err := w.do(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(project)+"/import", body, writeHeaders(opts))
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return mapHTTPError(r, "import "+project)
	}
	return nil
}

// Delete, DELETE /v1/projects/{p}/keys/{KEY}.
func (w *WorkerStore) Delete(ctx context.Context, project, key string) error {
	r, err := w.do(ctx, http.MethodDelete,
		"/v1/projects/"+url.PathEscape(project)+"/keys/"+url.PathEscape(key), nil, nil)
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return mapHTTPError(r, "delete "+key)
	}
	return nil
}

// --- Oturum / kontrol düzlemi (§7.2/§7.3/§6.3) ---------------------------------

// Whoami, GET /v1/whoami — principal + gruplar + efektif grant'ler.
func (w *WorkerStore) Whoami(ctx context.Context) (*WhoamiResult, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/whoami", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "whoami")
	}
	var out WhoamiResult
	if err := decodeJSON(r.body, &out, "whoami"); err != nil {
		return nil, err
	}
	return &out, nil
}

// PolicyGet, GET /v1/policy (admin verb + write-AUD oturumu, §7.6).
func (w *WorkerStore) PolicyGet(ctx context.Context) (*PolicyResult, error) {
	r, err := w.do(ctx, http.MethodGet, "/v1/policy", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "policy show")
	}
	var out PolicyResult
	if err := decodeJSON(r.body, &out, "policy show"); err != nil {
		return nil, err
	}
	return &out, nil
}

// PolicyPut, PUT /v1/policy — CAS'lı policy yazımı (version = current+1, §4.1).
func (w *WorkerStore) PolicyPut(ctx context.Context, doc PolicyDoc) (version uint64, sha256 string, err error) {
	body, merr := json.Marshal(doc)
	if merr != nil {
		return 0, "", clierr.Wrapf(clierr.Internal, merr, "encode policy")
	}
	r, err := w.do(ctx, http.MethodPut, "/v1/policy", body, nil)
	if err != nil {
		return 0, "", err
	}
	if r.status != http.StatusOK {
		return 0, "", mapHTTPError(r, "policy set")
	}
	var out struct {
		Version uint64 `json:"version"`
		SHA256  string `json:"sha256"`
	}
	if err := decodeJSON(r.body, &out, "policy set"); err != nil {
		return 0, "", err
	}
	return out.Version, out.SHA256, nil
}

// RotatePlan, GET /v1/admin/rotate-plan — audit-ledger rotate-set oracle (§6.3).
func (w *WorkerStore) RotatePlan(ctx context.Context, identity, since string, assumePolicy bool) (*RotatePlanResult, error) {
	q := url.Values{}
	q.Set("identity", identity)
	if since != "" {
		q.Set("since", since)
	}
	if assumePolicy {
		q.Set("assume_policy", "1")
	}
	r, err := w.do(ctx, http.MethodGet, "/v1/admin/rotate-plan?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, mapHTTPError(r, "rotate-plan")
	}
	var out RotatePlanResult
	if err := decodeJSON(r.body, &out, "rotate-plan"); err != nil {
		return nil, err
	}
	return &out, nil
}

// TokenMint, POST /v1/token — opsiyonel mint katmanı (§5.3; yalnızca service
// principal). Dönen minted token ASLA loglanmaz; çağıran CI adımına iletir.
func (w *WorkerStore) TokenMint(ctx context.Context, project string, keys, verbs []string, ttlSeconds int) (token string, expiresAt int64, err error) {
	req := map[string]any{
		"project": project,
		"scope":   map[string]any{"keys": keys, "verbs": verbs},
	}
	if ttlSeconds > 0 {
		req["ttl_seconds"] = ttlSeconds
	}
	body, merr := json.Marshal(req)
	if merr != nil {
		return "", 0, clierr.Wrapf(clierr.Internal, merr, "encode token request")
	}
	r, err := w.do(ctx, http.MethodPost, "/v1/token", body, nil)
	if err != nil {
		return "", 0, err
	}
	if r.status != http.StatusOK {
		if r.status == http.StatusBadRequest {
			return "", 0, clierr.Newf(clierr.TokenExchangeFailed, "token exchange rejected (%s)", safeCode(parseWorkerError(r.body).Error))
		}
		return "", 0, mapHTTPError(r, "token exchange")
	}
	var out struct {
		Token string `json:"token"`
		Exp   int64  `json:"exp"`
	}
	if err := decodeJSON(r.body, &out, "token exchange"); err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(out.Token) == "" {
		return "", 0, clierr.New(clierr.TokenExchangeFailed, "gate returned an empty token")
	}
	return out.Token, out.Exp, nil
}
