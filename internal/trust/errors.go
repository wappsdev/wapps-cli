// Package trust, wapps-secrets güven omurgasının (trust spine) istemci-doğrulamalı
// köküdür (SPEC §4): admin/roster manifest'i, roster-zinciri doğrulaması, pin
// deposu (roots.json + derlenmiş genesis), epoch-reset kayıtları ve N=1→N≥3
// geçişinin katmanlı (tiered) co-sign politikası.
//
// Bu paket TCB'nin (Trusted Computing Base) parçasıdır: doğrulama R2, Worker ve
// Cloudflare'den BAĞIMSIZDIR — pinlenmiş genesis + getirilen güven epoch'ları
// zinciriyle bir istemci tüm omurgayı online otorite OLMADAN doğrular.
//
// Kripto primitifleri (Ed25519/P-256 imza, parmak izi, imza zarfı) cryptoid'den;
// kimlik/grant tipleri registry'den YENİDEN KULLANILIR — burada çoğaltılmaz.
//
// KATİ KURAL (SPEC §3.6.3/§4.2.1): imza, depolanan TAM baytların SHA-256'sı
// üzerinedir. Doğrulayıcı ham baytları hash'ler ve imza kümesini kabul kuralına
// göre doğrular; payload'daki HİÇBİR alan imza kümesi TAM baytlar üzerinde
// geçene kadar GÜVENİLMEZ. Canonical-JSON imzalama HER YERDE YASAKTIR.
package trust

import "errors"

// Hata sözleşmesi (SPEC §4.11) — SCREAMING_SNAKE kodları, fail-closed. Mesajlar
// pinlenmiş vs sunulan epoch'ları isimlendirir; asla anahtar materyali içermez.
var (
	// ErrTrustDowngrade: sunulan herhangi bir güven epoch'u/head'i/reset'i
	// last_verified pin'inin ALTINDA. Tüm verb'lerde (okumalar dahil) HARD FAIL.
	ErrTrustDowngrade = errors.New("trust: TRUST_DOWNGRADE")

	// ErrTrustChainBroken: hash-link uyumsuzluğu, doldurulamayan epoch boşluğu,
	// yanlış imzalayan sınıfı veya anlamsal-değişmez ihlali (SPEC §4.5/§4.11).
	ErrTrustChainBroken = errors.New("trust: TRUST_CHAIN_BROKEN")

	// ErrTrustQuorumUnmet: epoch'un change_class katmanı için gereken imza
	// sayısından az (SPEC §4.11 TRUST_QUORUM_UNMET).
	ErrTrustQuorumUnmet = errors.New("trust: TRUST_QUORUM_UNMET")

	// ErrTrustPinMissing: ne roots.json var ne de derlenmiş genesis'ten
	// doğrulanabilir bir zincir (SPEC §4.11 TRUST_PIN_MISSING).
	ErrTrustPinMissing = errors.New("trust: TRUST_PIN_MISSING")

	// ErrTrustPinConflict: derlenmiş genesis pin ≠ yerel roots.json genesis pin
	// (SPEC §4.11 TRUST_PIN_CONFLICT). Sessizce birini tercih ETME.
	ErrTrustPinConflict = errors.New("trust: TRUST_PIN_CONFLICT")

	// ErrUnsupportedSchema: bilinmeyen schema değeri.
	ErrUnsupportedSchema = errors.New("trust: UNSUPPORTED_SCHEMA")

	// ErrUnknownChangeClass: kapalı-küme dışı change_class.
	ErrUnknownChangeClass = errors.New("trust: UNKNOWN_CHANGE_CLASS")
)
