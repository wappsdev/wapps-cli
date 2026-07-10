// Package intent, tazelik politikasını intent'e göre uygular (SPEC §7.3.4).
//
//	--intent dev  (default): önbelleği ≤24h tolere eder (stderr uyarısı SADECE
//	              anahtar-sayısı + yaş ismiyle, ASLA değerlerle); daha eski → CACHE_STALE.
//	--intent deploy (fresh-or-fail): Worker liveness receipt'i iat ≤ 5dk (±5dk skew)
//	              VE epoch ≥ client-pinned epoch gerektirir; yoksa STALE_RECEIPT
//	              (alt-komut ÇALIŞMADAN ÖNCE).
//
// Çevrimdışı: okumalar doğrulanmış önbelleğe düşer (dev); YAZIMLAR fail-closed
// (OFFLINE_WRITE_BLOCKED) — asla kuyruklanmış/ertelenmiş yazım.
//
// ESCROW-WITNESS ÇAPRAZ KONTROLÜ (SPEC §7.3.4 deploy satırı, §9.3): deploy
// intent'in escrow-witness head'ini non-CF origin'den çekip epoch-çelişkisi
// (WITNESS_CONTRADICTION) / erişilemezlik (WITNESS_UNREACHABLE) kontrol etmesi
// gerekir. Bu G10'a kadar bir STUB'dır (Witness arayüzü + NoWitness varsayılanı,
// aşağıda) — deploy fresh-or-fail'in receipt+epoch yarısı BU pakette tamdır.
package intent

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// Intent, okuma tazelik sınıfıdır.
type Intent string

const (
	Dev    Intent = "dev"
	Deploy Intent = "deploy"
)

// Pinli sayısal parametreler (SPEC §14.2 / §7.3.4).
const (
	// MaxStaleDev, dev intent çevrimdışı önbellek toleransıdır.
	MaxStaleDev = 24 * time.Hour
	// ReceiptMaxAge, deploy liveness receipt'inin azami yaşıdır.
	ReceiptMaxAge = 5 * time.Minute
	// ClockSkew, receipt iat için saat sapması toleransıdır (±).
	ClockSkew = 5 * time.Minute
)

// Parse, bir --intent bayrağını çözer; boş → Dev (default). Bilinmeyen değer hata.
func Parse(s string) (Intent, error) {
	switch s {
	case "", string(Dev):
		return Dev, nil
	case string(Deploy):
		return Deploy, nil
	default:
		return "", clierr.Newf(clierr.Internal, "unknown intent %q (allowed: dev, deploy)", s)
	}
}

// ReceiptPayload, liveness receipt payload'ının şemasıdır (SPEC §6.6).
type ReceiptPayload struct {
	Schema         string `json:"schema"`
	ManifestSha256 string `json:"manifestSha256"`
	Epoch          uint64 `json:"epoch"`
	IAT            int64  `json:"iat"`
}

// ReceiptSchema, receipt payload şema tanımlayıcısı.
const ReceiptSchema = "receipt/v1"

// Receipt, Worker'ın döndürdüğü imzalı liveness receipt'in tel formudur:
// payload = base64(TAM UTF-8 bayt), sig = base64 ES256 (raw r‖s). İstemci ham
// payload baytlarını doğrular SONRA parse eder (§3.6.2 exact-bytes disiplini).
type Receipt struct {
	Payload string `json:"payload"`
	Kid     string `json:"kid"`
	Sig     string `json:"sig"`
}

// receiptJWK, pinlenmiş Worker receipt public anahtarının JWK şeklidir (EC P-256).
type receiptJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// b64any, hem base64url hem std (padding'li/siz) çözmeyi dener — JWK koordinatları
// base64url, receipt payload/sig std base64'tür (Worker bytesToB64).
func b64any(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// verifierFromJWK, EC P-256 JWK'dan bir cryptoid.VerifierKey kurar: x‖y'yi
// sıkıştırılmamış SEC1 noktaya (0x04‖X‖Y) çevirir. Nokta eğri üzerinde
// doğrulanır (crypto/ecdh).
func verifierFromJWK(raw json.RawMessage) (cryptoid.VerifierKey, error) {
	var j receiptJWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return cryptoid.VerifierKey{}, clierr.Wrapf(clierr.SigInvalid, err, "receipt pubkey JWK unparseable")
	}
	if j.Kty != "EC" || (j.Crv != "" && j.Crv != "P-256") {
		return cryptoid.VerifierKey{}, clierr.New(clierr.SigInvalid, "receipt pubkey is not an EC P-256 JWK")
	}
	x, okx := b64any(j.X)
	y, oky := b64any(j.Y)
	if !okx || !oky || len(x) != 32 || len(y) != 32 {
		return cryptoid.VerifierKey{}, clierr.New(clierr.SigInvalid, "receipt pubkey JWK missing/invalid x,y")
	}
	sec1 := make([]byte, 0, 65)
	sec1 = append(sec1, 0x04)
	sec1 = append(sec1, x...)
	sec1 = append(sec1, y...)
	if _, err := ecdh.P256().NewPublicKey(sec1); err != nil {
		return cryptoid.VerifierKey{}, clierr.Wrapf(clierr.SigInvalid, err, "receipt pubkey not on P-256 curve")
	}
	vk, err := cryptoid.NewVerifierKey(cryptoid.AlgECDSAP256SHA256, sec1)
	if err != nil {
		return cryptoid.VerifierKey{}, clierr.Wrapf(clierr.SigInvalid, err, "receipt pubkey")
	}
	return vk, nil
}

// VerifyReceipt, deploy fresh-or-fail'in receipt+epoch yarısını uygular
// (SPEC §7.3.4). Adımlar: (1) payload+sig base64 çöz; (2) imzayı TAM payload
// baytları üzerinde pinlenmiş receipt anahtarıyla doğrula; (3) payload'ı parse
// et + şema; (4) manifestSha256 == çekilen manifest ETag'ı; (5) epoch ≥ epochPin;
// (6) iat ∈ [now - 5dk - skew, now + skew].
//
// wantManifestSha256, doğrulanmış manifest'in obje hash'idir (bind — receipt
// başka bir epoch'a ait olamaz). Herhangi bir ihlal STALE_RECEIPT/SIG_INVALID.
func VerifyReceipt(r Receipt, pinnedJWK json.RawMessage, wantManifestSha256 string, epochPin uint64, now time.Time) (ReceiptPayload, error) {
	payloadBytes, ok := b64any(r.Payload)
	if !ok {
		return ReceiptPayload{}, clierr.New(clierr.StaleReceipt, "receipt payload not base64")
	}
	sigBytes, ok := b64any(r.Sig)
	if !ok {
		return ReceiptPayload{}, clierr.New(clierr.StaleReceipt, "receipt signature not base64")
	}
	vk, err := verifierFromJWK(pinnedJWK)
	if err != nil {
		return ReceiptPayload{}, err
	}
	// İmza TAM payload baytları üzerinde (vk.Verify D=SHA-256(payload) hesaplar,
	// WebCrypto ES256 ile aynı) — parse ETMEDEN önce.
	if err := vk.Verify(payloadBytes, sigBytes); err != nil {
		return ReceiptPayload{}, clierr.Wrapf(clierr.SigInvalid, err, "receipt signature invalid")
	}
	var p ReceiptPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return ReceiptPayload{}, clierr.Wrapf(clierr.StaleReceipt, err, "receipt payload unparseable")
	}
	if p.Schema != ReceiptSchema {
		return ReceiptPayload{}, clierr.Newf(clierr.StaleReceipt, "receipt schema %q unexpected", p.Schema)
	}
	if wantManifestSha256 != "" && p.ManifestSha256 != wantManifestSha256 {
		return ReceiptPayload{}, clierr.New(clierr.StaleReceipt, "receipt does not bind to the fetched manifest")
	}
	if p.Epoch < epochPin {
		return ReceiptPayload{}, clierr.Newf(clierr.EpochDowngrade, "receipt epoch %d below pinned %d", p.Epoch, epochPin)
	}
	iat := time.Unix(p.IAT, 0)
	oldest := now.Add(-ReceiptMaxAge - ClockSkew)
	newest := now.Add(ClockSkew)
	if iat.Before(oldest) || iat.After(newest) {
		return ReceiptPayload{}, clierr.Newf(clierr.StaleReceipt, "receipt iat outside the freshness window (age constraint 5m ±5m)")
	}
	return p, nil
}

// --- Escrow witness cross-check (STUB, G10) ---------------------------------

// Witness, deploy intent'in escrow tanık head'ini non-CF origin'den çekmesi için
// arayüzdür (SPEC §7.3.4 / §9.3). G10'a kadar NoWitness kullanılır — bu, tanık
// kontrolünü NO-OP yapar ve DOKÜMANTE edilmiş bir eksiktir (deploy'un receipt+
// epoch yarısı yine de zorlanır).
type Witness interface {
	// HeadEpoch, tanık origin'in gördüğü son epoch'u döner. Erişilemezse hata.
	HeadEpoch() (uint64, error)
}

// NoWitness, G10'a kadarki STUB tanıktır: çapraz kontrol devre dışı. HeadEpoch
// asla-çelişmeyen bir 0 döner ve CheckWitness(nil, ...) ile birlikte tanık
// kontrolünü NO-OP yapar (G10'da gerçek non-CF origin implementasyonuyla değişir).
type NoWitness struct{}

// HeadEpoch, stub: her zaman 0 (çelişki üretmez).
func (NoWitness) HeadEpoch() (uint64, error) { return 0, nil }

// CheckWitness, tanık çapraz kontrolünü uygular (SPEC §7.3.4). w nil ise NO-OP
// (G10 stub). Gerçek bir Witness ile: tanık epoch > çekilen epoch ⇒
// WITNESS_CONTRADICTION; erişilemez ⇒ WITNESS_UNREACHABLE.
func CheckWitness(w Witness, fetchedEpoch uint64) error {
	if w == nil {
		return nil // stub: tanık yok → kontrol atlanır (G10)
	}
	head, err := w.HeadEpoch()
	if err != nil {
		return clierr.Wrapf(clierr.WitnessUnreachable, err, "escrow witness unreachable")
	}
	if head > fetchedEpoch {
		return clierr.Newf(clierr.WitnessContradiction, "witness epoch %d > fetched %d (freeze detected)", head, fetchedEpoch)
	}
	return nil
}

// EvaluateOfflineRead, çevrimdışı/bayat bir okumanın kabul edilebilirliğini
// intent'e göre değerlendirir (SPEC §7.3.4). keyCount + cacheAge uyarı
// metnindedir (ASLA değer). Dönüş: stderr uyarısı (boş olabilir) + hata.
//
//   - deploy: çevrimdışı ⇒ STALE_RECEIPT (fresh-or-fail, alt-komuttan ÖNCE).
//   - dev + yaş ≤ 24h: uyarı "using cached secrets from <date> (N keys, Xh old)".
//   - dev + yaş > 24h: CACHE_STALE.
func EvaluateOfflineRead(in Intent, cacheAge time.Duration, keyCount int, fetchedAt time.Time) (string, error) {
	if in == Deploy {
		return "", clierr.New(clierr.StaleReceipt, "deploy intent requires a fresh liveness receipt; Cloudflare unreachable")
	}
	if cacheAge > MaxStaleDev {
		return "", clierr.Newf(clierr.CacheStale, "cache is %dh old (> 24h dev limit)", int(cacheAge.Hours()))
	}
	warn := fmt.Sprintf("using cached secrets from %s (%d keys, %dh old)",
		fetchedAt.UTC().Format("2006-01-02"), keyCount, int(cacheAge.Hours()))
	return warn, nil
}

// BlockOfflineWrite, çevrimdışı bir yazımı fail-closed reddeder
// (OFFLINE_WRITE_BLOCKED, SPEC §7.3.4). Yazımlar asla kuyruklanmaz.
func BlockOfflineWrite() error {
	return clierr.New(clierr.OfflineWriteBlocked, "the store is unreachable; writes are never queued")
}
