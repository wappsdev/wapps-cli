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
	AuthExpired          Code = "AUTH_EXPIRED"
	OfflineWriteBlocked  Code = "OFFLINE_WRITE_BLOCKED"
	StaleReceipt         Code = "STALE_RECEIPT"
	WitnessContradiction Code = "WITNESS_CONTRADICTION"
	WitnessUnreachable   Code = "WITNESS_UNREACHABLE"
	WitnessNotWired      Code = "WITNESS_NOT_WIRED"
	WriterNotAllowed     Code = "WRITER_NOT_ALLOWED"
	TFOriginMirrorOnly   Code = "TF_ORIGIN_MIRROR_ONLY"
	EpochDowngrade       Code = "EPOCH_DOWNGRADE"
	CacheStale           Code = "CACHE_STALE"
	CASConflict          Code = "CAS_CONFLICT"
	GrantDenied          Code = "GRANT_DENIED"
	RateLimited          Code = "RATE_LIMITED"
	IdentityMissing      Code = "IDENTITY_MISSING"
	SigInvalid           Code = "SIG_INVALID"
	BlobHashMismatch     Code = "BLOB_HASH_MISMATCH"
	ControlPlaneRequired Code = "CONTROL_PLANE_REQUIRED"
	BreakGlassRefused    Code = "BREAK_GLASS_REFUSED"
	LegacyArchiveRetired Code = "LEGACY_ARCHIVE_RETIRED"
	LegacyWriteBlocked   Code = "LEGACY_WRITE_BLOCKED"
	ArchiveMigrated      Code = "ARCHIVE_MIGRATED"
	EscrowWrapMissing    Code = "ESCROW_WRAP_MISSING"
	TokenExchangeFailed  Code = "TOKEN_EXCHANGE_FAILED"
	BlobTooLarge         Code = "BLOB_TOO_LARGE"
	NotAvailable         Code = "NOT_AVAILABLE"
	Internal             Code = "INTERNAL"
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
	AuthExpired:          {"run wapps login in a terminal", false},
	OfflineWriteBlocked:  {"retry when online; writes are never queued", true},
	StaleReceipt:         {"retry; if Cloudflare is down a human may run exec --intent deploy --break-glass in a terminal", true},
	WitnessContradiction: {"do NOT deploy; investigate per §9 (possible CF-side freeze); page the admin", false},
	WitnessUnreachable:   {"retry; if the outage is confirmed benign, a human may re-run with --accept-witness-outage in a terminal (double-confirm)", true},
	WitnessNotWired:      {"deploy needs an escrow-witness origin; none is wired yet — use --intent dev, or wait for the witness to be configured", false},
	WriterNotAllowed:     {"integrity failure — the manifest writer lacks a grant for a changed key; do not proceed; run wapps doctor and contact the admin", false},
	TFOriginMirrorOnly:   {"rotate at the origin: run the tofu-level recipe, then tofu apply, then wapps secrets sync", false},
	EpochDowngrade:       {"possible rollback attack; verify with wapps secrets status and contact the admin; do not force", false},
	CacheStale:           {"reconnect and re-run; wapps secrets status shows cache_age", true},
	CASConflict:          {"re-run the original command; conflicting writers are shown above", true},
	GrantDenied:          {"ask an admin to run wapps secrets grant <principal> <project>/<KEY>", false},
	RateLimited:          {"wait for the Retry-After window and retry", true},
	IdentityMissing:      {"run wapps secrets enroll in a terminal", false},
	SigInvalid:           {"integrity failure — do not proceed; run wapps doctor and contact the admin", false},
	BlobHashMismatch:     {"integrity failure — do not proceed; run wapps doctor and contact the admin", false},
	ControlPlaneRequired: {"this is an admin ceremony: a human must run it in a terminal with the admin key present", false},
	BreakGlassRefused:    {"a human must run this in a terminal (double-confirm required)", false},
	LegacyArchiveRetired: {"this project migrated to the store; pull latest .wapps.yaml and use wapps secrets set", false},
	LegacyWriteBlocked:   {"this project reads from the store; use wapps secrets set", false},
	ArchiveMigrated:      {"run wapps secrets exec in this repo; the git archive is retired", false},
	EscrowWrapMissing:    {"re-fetch trust and rebuild the wrap-set; run wapps doctor if it persists", false},
	TokenExchangeFailed:  {"verify the per-repo service token in Woodpecker secrets; an admin can re-issue via §6 token ops", false},
	BlobTooLarge:         {"store a pointer/reference instead; the store caps values at 64KB", false},
	NotAvailable:         {"this action needs a live Cloudflare Access session; run it from a human terminal", false},
	Internal:             {"run wapps doctor; if it persists contact the admin", false},
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
