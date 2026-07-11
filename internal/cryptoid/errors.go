// Package cryptoid, wapps-secrets sisteminin donmuş (frozen) kripto çekirdeğidir.
//
// SERVER-DECRYPT pivotu (SPEC §0.2/§8.4) sonrası kapsam: üretim zarf kriptosu
// SUNUCUDA koşar; bu pakette yalnızca DR aracının (`wapps dr restore`) alt kümesi
// yaşar — WSB1 blob aç/pad doğrulama (dek.go), HKDF per-project KEK + WKW1
// DEK-unwrap + kid türetimi (kek.go, worker crypto/kek.ts paritesi) ve Shamir
// 2-of-3 (shamir.go). ZK build'inin X25519 wrap/imza/bech32 katmanları SİLİNDİ.
//
// FROZEN TCB: bu paketteki on-disk/on-wire formatlar (padding kovaları, AAD
// kurulumu, blob düzeni, WKW1 çerçevesi) ilk production blob yazıldıktan sonra
// yeni bir sürümlü format + göç planı olmadan DEĞİŞTİRİLEMEZ. Format sabitliği
// kek_test.go'daki Go↔TS parite vektörleriyle kilitlenir (build gate 2).
package cryptoid

import "errors"

// Hata sözleşmesi — tüm kripto hataları FAIL-CLOSED ve makine okunur.
// Mesajlar ASLA anahtar materyali veya plaintext içermez. (ZK-only hatalar —
// SIG_INVALID, NOT_A_RECIPIENT, WRAP_SELFCHECK_FAILED, ESCROW_WRAP_MISSING —
// alt sistemleriyle birlikte silindi, SPEC §0.2.)
var (
	// ErrBlobHashMismatch: getirilen blob baytları manifest blobHash ile
	// eşleşmiyor. Parse/decrypt ÖNCESİ reddedilir.
	ErrBlobHashMismatch = errors.New("cryptoid: BLOB_HASH_MISMATCH")

	// ErrBlobMalformed: bozuk magic, bozuk padding dolgusu, kova dışı uzunluk
	// veya AEAD auth hatası. Tamper olarak ele alınır; alternatif parametreyle
	// yeniden DENENMEZ.
	ErrBlobMalformed = errors.New("cryptoid: BLOB_MALFORMED")

	// ErrValueTooLarge: padlenmiş değer 64 KB blob kapasitesini aşardı.
	ErrValueTooLarge = errors.New("cryptoid: VALUE_TOO_LARGE")
)
