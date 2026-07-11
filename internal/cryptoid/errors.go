// Package cryptoid, wapps-secrets sisteminin donmuş (frozen) kripto çekirdeğidir.
//
// Kapsam (SPEC §3): şifreleme kimlikleri (X25519, age üzerinden), imzalama
// kimlikleri (Ed25519 + ECDSA P-256, şifrelemeden AYRI hiyerarşi), ayrık
// (detached) imza zarfı, per-key DEK zarfı (pad → AEAD → içerik-adresleme →
// wrap), deterministik DEK wrap + WrapVerify öz-kontrolü ve Shamir 2-of-3.
//
// FROZEN TCB: bu paketteki on-disk/on-wire formatlar (padding kovaları, AAD
// kurulumu, blob düzeni, wrap şeması, imza zarfı) ilk production blob
// yazıldıktan sonra yeni bir sürümlü format + göç planı olmadan DEĞİŞTİRİLEMEZ.
// Format sabitliği testdata/frozen_vectors.json ile kilitlenir; herhangi bir
// vektör çıktısı değişirse testler kırılır (SPEC §3.1).
package cryptoid

import "errors"

// Hata sözleşmesi (SPEC §3.10) — tüm kripto hataları FAIL-CLOSED ve makine
// okunur. Mesajlar ASLA anahtar materyali veya plaintext içermez.
var (
	// ErrSigInvalid: gerekli bir imza doğrulanamadı veya M-of-N / writer
	// allowlist kuralını karşılamıyor. Nesne YOK sayılır; asla parse edilmez.
	ErrSigInvalid = errors.New("cryptoid: SIG_INVALID")

	// ErrAlgUnsupported: alg veya blob magic kapalı v1 registry dışında.
	ErrAlgUnsupported = errors.New("cryptoid: ALG_UNSUPPORTED")

	// ErrBlobHashMismatch: getirilen blob baytları manifest blobHash ile
	// eşleşmiyor. Parse/decrypt ÖNCESİ reddedilir.
	ErrBlobHashMismatch = errors.New("cryptoid: BLOB_HASH_MISMATCH")

	// ErrBlobMalformed: bozuk magic, bozuk padding dolgusu, kova dışı uzunluk
	// veya AEAD auth hatası. Tamper olarak ele alınır; alternatif parametreyle
	// yeniden DENENMEZ.
	ErrBlobMalformed = errors.New("cryptoid: BLOB_MALFORMED")

	// ErrNotARecipient: yerel kimliklerden hiçbirine ait wrap yok.
	ErrNotARecipient = errors.New("cryptoid: NOT_A_RECIPIENT")

	// ErrWrapSelfcheckFailed: kurulan bir wrap, zorunlu çift-yollu (dual-path)
	// yeniden-türetme bayt karşılaştırmasında tutmadı (SPEC §3.5.5). İmzadan
	// ÖNCE yazımı iptal eder; olası TCB kusuru.
	ErrWrapSelfcheckFailed = errors.New("cryptoid: WRAP_SELFCHECK_FAILED")

	// ErrValueTooLarge: padlenmiş değer 64 KB blob kapasitesini aşardı.
	ErrValueTooLarge = errors.New("cryptoid: VALUE_TOO_LARGE")

	// ErrEscrowWrapMissing: bir manifest girdisinin wrap-set'inde aktif escrow
	// alıcısı yok (SPEC §3.10, §5.4.3).
	ErrEscrowWrapMissing = errors.New("cryptoid: ESCROW_WRAP_MISSING")
)
