package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// manifestBody, verilen wrap + rotation snippet'iyle KATİ-parse edilebilir minimal
// bir data-manifest body'si kurar (imza gerekmez; ParseManifestBody imza doğrulamaz).
func manifestBody(wrapB64, rotation string) string {
	rot := ""
	if rotation != "" {
		rot = `,"rotation":` + rotation
	}
	return `{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,` +
		`"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-11T00:00:00Z",` +
		`"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab",` +
		`"wraps":[{"recipient":"sha256:ff","wrap":"` + wrapB64 + `"}]` + rot + `}]}`
}

// TestParseSignedObject_NonCanonicalBase64 (FIX #1): imzasız sarmalayıcının bytes
// ve sig alanları KATİ KANONİK base64 (B64Strict) olmalı — bir saldırgan payload'ı
// hiç bozmadan bunları non-canonical spelling'e re-encode edip Go-kabul/Worker-red
// bölünmesi yaratamaz.
func TestParseSignedObject_NonCanonicalBase64(t *testing.T) {
	// Kanonik sarmalayıcı: parse edilir.
	okWrapper := `{"bytes":"//8=","sigs":[{"schema":"wapps-secrets/sig/v1","key_id":"k","alg":"ed25519","sig":"//8="}]}`
	_, err := ParseSignedObject([]byte(okWrapper))
	require.NoError(t, err)

	// Non-canonical `bytes` (son-bayt bitleri): red.
	_, err = ParseSignedObject([]byte(`{"bytes":"//9=","sigs":[]}`))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)

	// Padding'siz `bytes`: red.
	_, err = ParseSignedObject([]byte(`{"bytes":"aGVsbG8","sigs":[]}`))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)

	// Gömülü newline'lı `bytes` (encoding/json ATLAR, biz REDDEDERİZ): red.
	_, err = ParseSignedObject([]byte(`{"bytes":"aGVs\nbG8h","sigs":[]}`))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)

	// Non-canonical `sig`: red.
	badSig := `{"bytes":"//8=","sigs":[{"schema":"wapps-secrets/sig/v1","key_id":"k","alg":"ed25519","sig":"//9="}]}`
	_, err = ParseSignedObject([]byte(badSig))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)
}

// TestParseManifestBody_NonCanonicalWrap (FIX #1): DEK wrap alanı KATİ KANONİK
// base64 olmalı — wrap-set byte-exact karşılaştırıldığından ve Worker de aynı alanı
// KATİ okuduğundan, non-canonical bir spelling iki tarafta ayrışmamalı.
func TestParseManifestBody_NonCanonicalWrap(t *testing.T) {
	// Kanonik wrap: parse edilir.
	_, err := ParseManifestBody([]byte(manifestBody("//8=", "")))
	require.NoError(t, err)

	// Non-canonical wrap (son-bayt bitleri): red.
	_, err = ParseManifestBody([]byte(manifestBody("//9=", "")))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)

	// Padding'siz wrap: red.
	_, err = ParseManifestBody([]byte(manifestBody("aGVsbG8", "")))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)
}

// TestParseManifestBody_RotationPassthroughInteger (FIX #2): rotation passthrough
// (json.RawMessage) İÇİNDEKİ sayılar da JS güvenli-tamsayı alanını paylaşmalı.
// Tipli struct alan kontrolleri passthrough'u atlardı; whole-body tarama (Worker
// assertCanonicalIntegerJSON paritesi) bunu yakalar.
func TestParseManifestBody_RotationPassthroughInteger(t *testing.T) {
	// Güvenli aralıktaki rotation sayısı: parse edilir.
	_, err := ParseManifestBody([]byte(manifestBody("//8=", `{"rotatedAt":9007199254740991}`)))
	require.NoError(t, err)

	// rotation İÇİNDE >2^53-1: red.
	_, err = ParseManifestBody([]byte(manifestBody("//8=", `{"rotatedAt":9007199254740992}`)))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalJSONNumber)

	// rotation İÇİNDE non-integer biçim (1e3): red.
	_, err = ParseManifestBody([]byte(manifestBody("//8=", `{"rotatedAt":1e3}`)))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalJSONNumber)
}

// TestParseSignedObject_NullBase64 (GO-1): ZORUNLU imzalı base64 alanları (bytes,
// sig) JSON `null` OLAMAZ — Worker b64ToBytes bir string bekler; `null` bir string
// değildir. encoding/json `null`'ı sessizce nil dilime çözerdi; B64Strict reddeder.
func TestParseSignedObject_NullBase64(t *testing.T) {
	// bytes:null → red.
	_, err := ParseSignedObject([]byte(`{"bytes":null,"sigs":[]}`))
	assert.ErrorIs(t, err, cryptoid.ErrMissingBase64)

	// sig:null → red.
	badSig := `{"bytes":"//8=","sigs":[{"schema":"wapps-secrets/sig/v1","key_id":"k","alg":"ed25519","sig":null}]}`
	_, err = ParseSignedObject([]byte(badSig))
	assert.ErrorIs(t, err, cryptoid.ErrMissingBase64)
}

// TestParseManifestBody_NullWrap (GO-1): DEK wrap alanı JSON `null` OLAMAZ — wrap-set
// byte-exact karşılaştırıldığından ve Worker aynı alanı KATİ (string) okuduğundan.
// KATİ ŞEKİL geçidi null'ı (ve yokluğu — *json.RawMessage ikisini de nil pointer'a
// çözer) MEVCUT-string gereğiyle reddeder (ErrNotJSONString); B64Strict'in null-only
// ErrMissingBase64'ünü ÖNCELER ve ayrıca missing-wrap bölünmesini de kapatır. İki
// taraf da wrap:null'ı reddeder → consensus korunur (yalnızca iç hata kodu değişir).
func TestParseManifestBody_NullWrap(t *testing.T) {
	body := `{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,` +
		`"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-11T00:00:00Z",` +
		`"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab",` +
		`"wraps":[{"recipient":"sha256:ff","wrap":null}]}]}`
	_, err := ParseManifestBody([]byte(body))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONString)

	// Yokluk (wrap alanı hiç yok) da reddedilmeli — B64Strict'in yakalayamadığı gap.
	missing := `{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,` +
		`"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-11T00:00:00Z",` +
		`"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab",` +
		`"wraps":[{"recipient":"sha256:ff"}]}]}`
	_, err = ParseManifestBody([]byte(missing))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONString)
}

// TestParseManifestBody_RequiredArrayShapes (GO-2): ZORUNLU imzalı dizi alanları
// (`entries` ve her girdinin `wraps`'ı) JSON `null`, YOK veya bir dizi-dışı değer
// OLAMAZ — Worker Array.isArray ile reddeder; encoding/json ise sessizce nil dilime
// çözerdi. Boş [] İZİNLİDİR (Worker de izin verir).
func TestParseManifestBody_RequiredArrayShapes(t *testing.T) {
	const head = `{"schema":"wapps-secrets/data-manifest/v1","project":"p","epoch":1,` +
		`"prevManifestSha256":"","trustEpoch":1,"createdAt":"2026-07-11T00:00:00Z"`

	// Boş entries [] → KABUL (Worker izinli).
	_, err := ParseManifestBody([]byte(head + `,"entries":[]}`))
	require.NoError(t, err)

	// Boş wraps [] → KABUL (dizi-şekli geçerli; escrow kontrolü ayrı bir katman).
	_, err = ParseManifestBody([]byte(head +
		`,"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab","wraps":[]}]}`))
	require.NoError(t, err)

	reject := map[string]string{
		"entries null":    head + `,"entries":null}`,
		"entries missing": head + `}`,
		"entries object":  head + `,"entries":{}}`,
		"entries [null]":  head + `,"entries":[null]}`,
		"wraps null":      head + `,"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab","wraps":null}]}`,
		"wraps missing":   head + `,"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab"}]}`,
		"wraps object":    head + `,"entries":[{"keyName":"A","keyVersion":1,"blobHash":"ab","wraps":{}}]}`,
	}
	for name, body := range reject {
		t.Run(name, func(t *testing.T) {
			_, err := ParseManifestBody([]byte(body))
			assert.ErrorIs(t, err, ErrRequiredArrayInvalid, "body %s must be rejected", body)
		})
	}
}

// TestParseManifestBody_StrictStringShape (strict-shape): imzalı string alanları
// (project, prevManifestSha256, createdAt, entries[].keyName/blobHash, wraps[].recipient)
// MEVCUT bir JSON string OLMALI — Worker asString `null`/yokluğu/non-string'i reddeder;
// encoding/json ise `null`/yokluğu sessizce ""'e çözerdi (Go-kabul/Worker-red bölünmesi).
func TestParseManifestBody_StrictStringShape(t *testing.T) {
	base := func(project, prev, created, keyName, blobHash, recipient string) string {
		return `{"schema":"wapps-secrets/data-manifest/v1","project":` + project + `,"epoch":1,` +
			`"prevManifestSha256":` + prev + `,"trustEpoch":1,"createdAt":` + created + `,` +
			`"entries":[{"keyName":` + keyName + `,"keyVersion":1,"blobHash":` + blobHash + `,` +
			`"wraps":[{"recipient":` + recipient + `,"wrap":"//8="}]}]}`
	}
	const s = `"x"`
	// {body, expected-sentinel} — string alanları ErrNotJSONString, sayı ErrNotJSONNumber.
	reject := []struct {
		name string
		body string
		want error
	}{
		{"project null", base(`null`, `""`, `"2026-07-11T00:00:00Z"`, `"A"`, `"ab"`, `"r"`), cryptoid.ErrNotJSONString},
		{"project number", base(`1`, `""`, `"2026-07-11T00:00:00Z"`, `"A"`, `"ab"`, `"r"`), cryptoid.ErrNotJSONString},
		{"prevManifestSha null", base(s, `null`, `"2026-07-11T00:00:00Z"`, `"A"`, `"ab"`, `"r"`), cryptoid.ErrNotJSONString},
		{"createdAt null", base(s, `""`, `null`, `"A"`, `"ab"`, `"r"`), cryptoid.ErrNotJSONString},
		{"createdAt number", base(s, `""`, `123`, `"A"`, `"ab"`, `"r"`), cryptoid.ErrNotJSONString},
		{"keyName null", base(s, `""`, `"2026-07-11T00:00:00Z"`, `null`, `"ab"`, `"r"`), cryptoid.ErrNotJSONString},
		{"blobHash null", base(s, `""`, `"2026-07-11T00:00:00Z"`, `"A"`, `null`, `"r"`), cryptoid.ErrNotJSONString},
		{"recipient null", base(s, `""`, `"2026-07-11T00:00:00Z"`, `"A"`, `"ab"`, `null`), cryptoid.ErrNotJSONString},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifestBody([]byte(tc.body))
			assert.ErrorIs(t, err, tc.want, "body %s must be rejected", tc.body)
		})
	}

	// createdAt geçersiz RFC3339 (takvim-dışı) → tipli time.Time decode reddeder.
	badCal := base(s, `""`, `"2026-02-31T00:00:00Z"`, `"A"`, `"ab"`, `"r"`)
	_, err := ParseManifestBody([]byte(badCal))
	assert.Error(t, err)

	// Temiz body geçmeli (kontrol).
	ok := base(s, `""`, `"2026-07-11T00:00:00Z"`, `"A"`, `"ab"`, `"r"`)
	_, err = ParseManifestBody([]byte(ok))
	require.NoError(t, err)
}
