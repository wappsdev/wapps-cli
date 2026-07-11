package cryptoid

import (
	"crypto/sha256"
	"encoding/hex"
)

// FingerprintPrefix, tüm anahtar parmak izlerinin ortak öneki (SPEC §3.7).
const FingerprintPrefix = "sha256:"

// Fingerprint, sistemdeki HER anahtar için tek parmak izi formatını üretir:
// "sha256:" + ham public key baytlarının SHA-256'sının küçük-harf hex'i
// (SPEC §3.7).
//
// Girdi baytları (pubBytes) çağırana göre değişir:
//   - İmzalama Ed25519: 32 baytlık public key.
//   - İmzalama P-256: 65 baytlık sıkıştırılmamış SEC1 nokta (0x04 ‖ X ‖ Y).
//   - Şifreleme kimlikleri: canonical bech32 metin formundaki age recipient
//     string'inin UTF-8 baytları (age1... / age1se1... / age1yubikey1...),
//     böylece native ve plugin alıcı tipleri aynı biçimde kapsanır.
func Fingerprint(pubBytes []byte) string {
	sum := sha256.Sum256(pubBytes)
	return FingerprintPrefix + hex.EncodeToString(sum[:])
}

// FingerprintRecipient, bir age recipient string'inin (bech32) parmak izini
// döner. Şifreleme kimlikleri için canonical girdi, recipient string'inin
// kendisidir (SPEC §3.7).
func FingerprintRecipient(recipient string) string {
	return Fingerprint([]byte(recipient))
}
