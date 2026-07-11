package rotation

// Legacy arşiv (SALT-OKUNUR: IRON RULE). ZK cutover motoru pivotla silindi
// (SPEC §0.2); tombstone akışının + Path B migrasyonunun ihtiyacı olan
// salt-okunur handle burada yaşamaya devam eder (SPEC §8.2).

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// LegacyArchive, eski scrypt all.enc.age arşivinin SALT-OKUNUR bir handle'ıdır.
// KASITLI olarak HİÇBİR yazma metodu YOKTUR — store'a rotate edilen bir değer
// buraya geri yazılamaz (IRON RULE). Yalnızca tombstone.go'daki guard'lı yol
// legacy'e (o da SADECE __MIGRATED__ sentinel'i) yazabilir.
type LegacyArchive struct {
	ciphertext []byte
}

// LegacyArchiveFromBytes, ham ciphertext'ten salt-okunur bir handle kurar (test +
// bellek). Dosyadan okuma CLI tarafında (resolveArchivePath) yapılır.
func LegacyArchiveFromBytes(ciphertext []byte) *LegacyArchive {
	cp := make([]byte, len(ciphertext))
	copy(cp, ciphertext)
	return &LegacyArchive{ciphertext: cp}
}

// Values, legacy arşivi passphrase ile ÇÖZER ve her anahtar için düz-metin
// değeri döner. __MIGRATED__ tombstone'u taşıyorsa ErrArchiveMigrated
// (bayat/tombstoned arşiv — migrasyon tekrar edilmez).
func (a *LegacyArchive) Values(passphrase string) (map[string][]byte, error) {
	plaintext, err := ageutil.Decrypt(a.ciphertext, passphrase)
	if err != nil {
		return nil, fmt.Errorf("rotation.Values: legacy decrypt: %w", err)
	}
	var outputs map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &outputs); err != nil {
		return nil, fmt.Errorf("rotation.Values: parse legacy archive: %w", err)
	}
	if _, ok := outputs[MigratedSentinelKey]; ok {
		return nil, ErrArchiveMigrated
	}
	out := make(map[string][]byte, len(outputs))
	for k, raw := range outputs {
		out[k] = legacyValueBytes(raw)
	}
	return out, nil
}

// legacyValueBytes, bir legacy arşiv değerini kanonik düz-metin baytlarına çevirir.
// tofu-output arşiv şekli {"KEY":{"value":..}} VEYA düz {"KEY":"val"} destekler:
// {value:X} sarmalayıcısını açar, JSON string'i unquote eder, aksi halde compact
// JSON. Import + verify AYNI fonksiyonu kullanır → roundtrip byte-tutarlı.
func legacyValueBytes(raw json.RawMessage) []byte {
	// {value: X} sarmalayıcısı (tofu output) → X'i al.
	var wrapper struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Value) > 0 {
		raw = wrapper.Value
	}
	// JSON string → unquote (legacy rawValueToString ile aynı semantik).
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []byte(s)
	}
	// Diğer (obje/sayı/bool) → compact JSON.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err == nil {
		return compact.Bytes()
	}
	return bytes.TrimSpace(raw)
}
