// Package clierr, wapps-secrets CLI'nın makine-okunur hata sözleşmesini sağlar
// (SPEC §7.5). Her CLI hatası stderr'e TEK bir JSON satırı yayar:
//
//	{"error":"<CODE>","message":"<cümle>","recovery":"<tam komut>","retryable":false}
//
// Her reddin KENDİ tam kurtarma komutunu isimlendirmesi normatiftir. Kodlar,
// katman registry'lerinin (kripto §3.10, trust §4.11, storage §5.7, Worker §6,
// lifecycle §8) birleşimidir; burada CLI-yüzeyi kod kümesi tanımlanır.
//
// GÜVENLİK: mesaj/kurtarma metni ASLA bir gizli DEĞER, wrap veya DEK içermez.
// Dışarıdan gelen (Worker/HTML/hata gövdesi) metin ham geçirilmez —
// internal/safelog ile sanitize edilir ve kısaltılır (ham HTML/error body asla).
package clierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wappsdev/wapps-cli/internal/safelog"
)

// Code, kapalı-küme CLI hata kodudur (SPEC §7.5 tablosu + katman registry'leri).
type Code string

// SPEC §7.5 normatif CLI kod kümesi (+ sıkça köprülenen katman kodları).
const (
	BindingUnpinned      Code = "BINDING_UNPINNED"
	AgentModeRefused     Code = "AGENT_MODE_REFUSED"
	EpochDowngrade       Code = "EPOCH_DOWNGRADE"
	CASConflict          Code = "CAS_CONFLICT"
	GrantDenied          Code = "GRANT_DENIED"
	RateLimited          Code = "RATE_LIMITED"
	BlobHashMismatch     Code = "BLOB_HASH_MISMATCH"
	ControlPlaneRequired Code = "CONTROL_PLANE_REQUIRED"
	BreakGlassRefused    Code = "BREAK_GLASS_REFUSED"
	LegacyArchiveRetired Code = "LEGACY_ARCHIVE_RETIRED"
	LegacyWriteBlocked   Code = "LEGACY_WRITE_BLOCKED"
	ArchiveMigrated      Code = "ARCHIVE_MIGRATED"
	TokenExchangeFailed  Code = "TOKEN_EXCHANGE_FAILED"
	BlobTooLarge         Code = "BLOB_TOO_LARGE"
	NotAvailable         Code = "NOT_AVAILABLE"
	Internal             Code = "INTERNAL"

	// Server-decrypt v2 kodları (SPEC §7.5 registry). ZK-only kodlar
	// (SIG_INVALID, WITNESS_*, CACHE_STALE, OFFLINE_WRITE_BLOCKED, IDENTITY_MISSING,
	// STALE_RECEIPT, WRITER_NOT_ALLOWED, ESCROW_WRAP_MISSING, AUTH_EXPIRED)
	// alt sistemleriyle birlikte SİLİNDİ (SPEC §0.2/§7.5 dropped satırı).
	SessionExpired      Code = "SESSION_EXPIRED"
	NetworkRequired     Code = "NETWORK_REQUIRED"
	NotFound            Code = "NOT_FOUND"
	PolicyInvalid       Code = "POLICY_INVALID"
	PolicyConflict      Code = "POLICY_CONFLICT"
	AuditUnavailable    Code = "AUDIT_UNAVAILABLE"
	IdentityUnavailable Code = "IDENTITY_UNAVAILABLE"
	ServiceMisconfig    Code = "SERVICE_MISCONFIGURED"
)

// spec, bir kodun varsayılan kurtarma metnini ve retryable bayrağını tutar
// (SPEC §7.5 tablosu, normatif metinler). Verb'ler ek bağlam ekleyebilir.
type spec struct {
	recovery  string
	retryable bool
}

// registry, kod → normatif kurtarma/retryable eşlemesidir.
var registry = map[Code]spec{
	BindingUnpinned:      {"run wapps secrets trust-repo in a terminal", false},
	AgentModeRefused:     {"use exec/apply; a human can run get in a terminal", false},
	EpochDowngrade:       {"possible rollback attack; verify with wapps secrets status and contact the admin; do not force", false},
	CASConflict:          {"re-run the original command; conflicting writers are shown above", true},
	GrantDenied:          {"ask an admin to extend policy.json (wapps secrets policy set) or fix the Google group membership", false},
	RateLimited:          {"wait for the Retry-After window and retry", true},
	BlobHashMismatch:     {"integrity failure — do not proceed; run wapps doctor and contact the admin", false},
	ControlPlaneRequired: {"this is an admin ceremony: a human must run it in a terminal (write-AUD session)", false},
	BreakGlassRefused:    {"a human must run this in a terminal (double-confirm required)", false},
	LegacyArchiveRetired: {"this project migrated to the store; pull latest .wapps.yaml and use wapps secrets set", false},
	LegacyWriteBlocked:   {"this project reads from the store; use wapps secrets set", false},
	ArchiveMigrated:      {"run wapps secrets exec in this repo; the git archive is retired", false},
	TokenExchangeFailed:  {"verify the pipeline's CF Access service-token pair; an admin can re-issue it at the edge", false},
	BlobTooLarge:         {"store a pointer/reference instead; the store caps values at 64KB", false},
	NotAvailable:         {"this action needs a live Cloudflare Access session; run it from a human terminal", false},
	Internal:             {"run wapps doctor; if it persists contact the admin", false},

	// Server-decrypt v2 kurtarma metinleri (SPEC §7.2/§7.4/§7.5).
	SessionExpired:      {"run wapps login in a terminal (CI uses CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET)", false},
	NetworkRequired:     {"reconnect and retry; the store has no offline mode (values are server-decrypted)", true},
	NotFound:            {"check the key/project name with wapps secrets list", false},
	PolicyInvalid:       {"fix the policy file (see the named rule index) and re-run wapps secrets policy lint", false},
	PolicyConflict:      {"another admin updated the policy; re-run policy show, rebase your edit, retry", true},
	AuditUnavailable:    {"the audit ledger is down — plaintext is refused fail-closed; retry shortly", true},
	IdentityUnavailable: {"identity/groups unresolvable at the edge; retry shortly", true},
	ServiceMisconfig:    {"the secrets gate is misconfigured; contact the admin (alert A8 fired)", false},
}

// Error, makine-okunur bir CLI hatasıdır. Emit tam JSON zarfı üretir; Error()
// insan-okunur özet döner. wrapped, errors.Is/As için orijinal hatadır (mesaj
// gizli değer içermemelidir; safelog ile sanitize edilerek yazılır).
type Error struct {
	Code      Code
	Message   string
	Recovery  string // boşsa registry'den doldurulur
	Retryable bool
	wrapped   error
}

// Error, insan-okunur özet döner.
func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap, errors.Is/As zincirlemesi için sarılmış hatayı döner.
func (e *Error) Unwrap() error { return e.wrapped }

// New, verilen kod + insan mesajıyla bir CLI hatası kurar; kurtarma/retryable
// registry'den varsayılır.
func New(code Code, message string) *Error {
	s := registry[code]
	return &Error{Code: code, Message: message, Recovery: s.recovery, Retryable: s.retryable}
}

// Newf, printf-stilli bir CLI hatası kurar (safelog.Sprintf ile — Wrap'lı
// argümanlar [REDACTED] olur).
func Newf(code Code, format string, args ...interface{}) *Error {
	return New(code, safelog.Sprintf(format, args...))
}

// Wrapf, alttaki bir hatayı bir CLI koduna sarar; alttaki mesaj sanitize
// edilerek eklenir (dış HTML/error body/değer sızıntısına karşı).
func Wrapf(code Code, err error, format string, args ...interface{}) *Error {
	e := Newf(code, format, args...)
	e.wrapped = err
	return e
}

// WithRecovery, kurtarma metnini override eder (ör. CAS çakışmasında yazarları
// isimlendirmek için). Zincirleme için *Error döner.
func (e *Error) WithRecovery(recovery string) *Error {
	e.Recovery = recovery
	return e
}

// envelope, stderr'e yazılan tek-satır JSON şeklidir (SPEC §7.5).
type envelope struct {
	Error     Code   `json:"error"`
	Message   string `json:"message"`
	Recovery  string `json:"recovery"`
	Retryable bool   `json:"retryable"`
}

// maxMessageLen, mesaj/kurtarma metninin üst sınırı — dış hata gövdelerinin
// (HTML sayfası vb.) transcript'e taşınmasını engeller.
const maxMessageLen = 400

// Emit, verilen hatayı SPEC §7.5 zarfı olarak w'ye (stderr) TEK satır JSON
// yazar. *Error değilse Internal koduna sarılır. Mesaj/kurtarma sanitize edilir
// (safelog.RedactPatterns) ve kısaltılır — ham HTML/error body ASLA yazılmaz.
func Emit(w io.Writer, err error) {
	if err == nil {
		return
	}
	var e *Error
	if !errors.As(err, &e) {
		e = Wrapf(Internal, err, "%s", err.Error())
	}
	recovery := e.Recovery
	if recovery == "" {
		recovery = registry[e.Code].recovery
	}
	env := envelope{
		Error:     e.Code,
		Message:   clip(safelog.RedactPatterns(e.Message)),
		Recovery:  clip(safelog.RedactPatterns(recovery)),
		Retryable: e.Retryable,
	}
	raw, merr := json.Marshal(env)
	if merr != nil {
		// Marshal edilemezse bile bir kod satırı yaz (asla ham gövde değil).
		fmt.Fprintf(w, `{"error":%q,"message":"error serialization failed","recovery":"","retryable":false}`+"\n", e.Code)
		return
	}
	// json.Marshal newline eklemez; tek satır + '\n'.
	fmt.Fprintln(w, string(raw))
}

// clip, tek satıra indirger ve maxMessageLen'e kısaltır.
func clip(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxMessageLen {
		return s[:maxMessageLen] + "…"
	}
	return s
}

// Is, bir hatanın belirli bir CLI koduna sahip olup olmadığını döner (test/verb
// akış kontrolü için).
func Is(err error, code Code) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}
