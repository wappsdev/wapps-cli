package cryptoid

// Bu dosya, imzalı-consensus gövdelerinin KATİ ŞEKİL (strict-shape) doğrulaması
// için paylaşılan ham-JSON yardımcılarını barındırır — Go CLI ile TS Worker'ın
// HER imzalı alan üzerinde AYNI kabul/red kararını vermesi için. Sorun sınıfı:
// Go'nun encoding/json'ı bir string alanına gelen JSON `null`/yokluğu SESSİZCE
// "" değerine, bir bool'a gelen null'ı false'a, bir slice'a gelen null'ı nil'e
// çözer; TS `str()`/`bool()`/`strArr()` ise bunları REDDEDER. Bu yardımcılar
// tipli decode'dan ÖNCE ham şekli denetleyerek o "Go-kabul / Worker-red"
// bölünmesini kapatır (COORD strict-shape). Her yardımcı bir *json.RawMessage
// alır: nil pointer = alan YOK (absent); non-nil ise dış decode tarafından
// zaten iyi-biçimli tek bir JSON değeri olarak doğrulanmış bir span'dir → ilk
// non-boşluk bayt tip için yeterlidir.

import (
	"bytes"
	"encoding/json"
	"errors"
)

var (
	// ErrNotJSONString: ZORUNLU imzalı bir string alanı MEVCUT bir JSON string
	// DEĞİL (null / yok / sayı / bool / obje / dizi). TS `str()` bunları reddeder.
	ErrNotJSONString = errors.New("cryptoid: NOT_JSON_STRING")
	// ErrEmptyJSONString: bir string alanı boş ("") — non-empty gereken alanlar
	// (F3: roots/enc_keys/signing_keys[].key_id) için. TS'te de "" reddedilir.
	ErrEmptyJSONString = errors.New("cryptoid: EMPTY_JSON_STRING")
	// ErrNotJSONArray: ZORUNLU imzalı bir dizi alanı MEVCUT bir JSON dizisi ([)
	// DEĞİL. TS `Array.isArray` / `strArr` reddeder.
	ErrNotJSONArray = errors.New("cryptoid: NOT_JSON_ARRAY")
	// ErrNotJSONStringArray: bir dizi alanı JSON dizisi değil VEYA bir elemanı
	// JSON string değil. TS `strArr` (F2: grants[].verbs/keys, writer_allowlists
	// [].keys) reddeder — Go []string null elemanı sessizce ""'e çözerdi.
	ErrNotJSONStringArray = errors.New("cryptoid: NOT_JSON_STRING_ARRAY")
	// ErrNotJSONBool: ZORUNLU imzalı bir bool alanı MEVCUT bir JSON bool (true/
	// false) DEĞİL. TS `bool()` reddeder — Go bool null'ı sessizce false'a çözerdi.
	ErrNotJSONBool = errors.New("cryptoid: NOT_JSON_BOOL")
	// ErrNotJSONObject: ZORUNLU imzalı bir obje alanı MEVCUT bir JSON obje ({)
	// DEĞİL. TS `obj()` reddeder — Go struct null'ı sessizce zero değere çözerdi.
	ErrNotJSONObject = errors.New("cryptoid: NOT_JSON_OBJECT")
	// ErrNotJSONNumber: ZORUNLU imzalı bir sayı (uint) alanı MEVCUT bir JSON sayı
	// DEĞİL. TS `uint()` yokluğu reddeder — Go uint64 yokluğu/null'ı 0'a çözerdi.
	// Kanonik biçim + [0,2^53-1] aralığı AssertCanonicalIntegerJSON'da denetlenir;
	// bu yardımcı yalnızca VARLIĞI + sayı-tipini doğrular.
	ErrNotJSONNumber = errors.New("cryptoid: NOT_JSON_NUMBER")
)

// rawFirst, ham mesajın çevre-boşluğu kırpılmış ilk baytını döner. nil pointer
// veya boş span → ok=false (alan yok / geçersiz).
func rawFirst(raw *json.RawMessage) (byte, bool) {
	if raw == nil {
		return 0, false
	}
	b := bytes.TrimSpace(*raw)
	if len(b) == 0 {
		return 0, false
	}
	return b[0], true
}

// IsAbsentOrNull, alanın YOK (nil pointer) veya JSON `null` olduğunu döner —
// normalize/nullable alan semantiği (admins, vouched_by, enrolled_at, rotate_by,
// worker_mint_pubkeys, epoch_reset) için: bu değerler KABUL edilir (boş sayılır).
func IsAbsentOrNull(raw *json.RawMessage) bool {
	if raw == nil {
		return true
	}
	return string(bytes.TrimSpace(*raw)) == "null"
}

// RequireJSONString, alanın MEVCUT bir JSON string (") olduğunu doğrular.
// null / yok / non-string → ErrNotJSONString (TS `str()` paritesi).
func RequireJSONString(raw *json.RawMessage) error {
	c, ok := rawFirst(raw)
	if !ok || c != '"' {
		return ErrNotJSONString
	}
	return nil
}

// RequireJSONStringNonEmpty, RequireJSONString + değerin boş string ("")
// OLMADIĞINI doğrular (F3: key_id alanları non-empty olmalı; boş key_id, offboard
// self-authorize authz-deliğini açardı — consensus-safe, iki taraf da "" reddeder).
func RequireJSONStringNonEmpty(raw *json.RawMessage) error {
	if err := RequireJSONString(raw); err != nil {
		return err
	}
	if string(bytes.TrimSpace(*raw)) == `""` {
		return ErrEmptyJSONString
	}
	return nil
}

// RequireJSONArray, alanın MEVCUT bir JSON dizisi ([) olduğunu doğrular.
// null / yok / non-array → ErrNotJSONArray. Boş [] geçerlidir.
func RequireJSONArray(raw *json.RawMessage) error {
	c, ok := rawFirst(raw)
	if !ok || c != '[' {
		return ErrNotJSONArray
	}
	return nil
}

// RequireJSONStringArray, alanın MEVCUT bir JSON dizisi olduğunu VE her elemanının
// JSON string olduğunu doğrular (TS `strArr` paritesi, F2). null / yok / non-array
// veya string-dışı eleman → ErrNotJSONStringArray. Boş [] geçerlidir.
func RequireJSONStringArray(raw *json.RawMessage) error {
	if err := RequireJSONArray(raw); err != nil {
		return ErrNotJSONStringArray
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(*raw, &elems); err != nil {
		return ErrNotJSONStringArray
	}
	for i := range elems {
		e := elems[i]
		if RequireJSONString(&e) != nil {
			return ErrNotJSONStringArray
		}
	}
	return nil
}

// NullableJSONStringArray, roster-sınıfı NORMALİZE dizi semantiğini uygular
// (admins, identities[].vouched_by): null / yok / [] hepsi KABUL + eşdeğerdir;
// MEVCUT non-null bir değer ise string dizisi OLMALI (TS `x == null ? [] :
// strArr(x)` paritesi). Böylece null-vs-[] ayrımı Go-red yaratmaz ama string-dışı
// eleman iki tarafta da reddedilir.
func NullableJSONStringArray(raw *json.RawMessage) error {
	if IsAbsentOrNull(raw) {
		return nil
	}
	return RequireJSONStringArray(raw)
}

// RequireJSONBool, alanın MEVCUT bir JSON bool (true/false) olduğunu doğrular.
// null / yok / non-bool → ErrNotJSONBool (TS `bool()` paritesi).
func RequireJSONBool(raw *json.RawMessage) error {
	if raw == nil {
		return ErrNotJSONBool
	}
	s := string(bytes.TrimSpace(*raw))
	if s != "true" && s != "false" {
		return ErrNotJSONBool
	}
	return nil
}

// RequireJSONObject, alanın MEVCUT bir JSON obje ({) olduğunu doğrular.
// null / yok / non-object → ErrNotJSONObject (TS `obj()` paritesi).
func RequireJSONObject(raw *json.RawMessage) error {
	c, ok := rawFirst(raw)
	if !ok || c != '{' {
		return ErrNotJSONObject
	}
	return nil
}

// RequireJSONNumber, alanın MEVCUT bir JSON sayısı (0-9 ile başlayan) olduğunu
// doğrular — TS `uint()` yokluğu reddeder. İşaret/kanonik-biçim/[0,2^53-1] aralığı
// AssertCanonicalIntegerJSON'da bütün-gövde taranarak yaptırılır; burada yalnızca
// VARLIK + sayı-tipi (null/yok/string/bool → red). '-' ile başlayan da red (işaretsiz).
func RequireJSONNumber(raw *json.RawMessage) error {
	c, ok := rawFirst(raw)
	if !ok || c < '0' || c > '9' {
		return ErrNotJSONNumber
	}
	return nil
}

// ForEachElemNullable, container-dizi alanları (roots/identities/grants/
// writer_allowlists/enc_keys/signing_keys) için NORMALİZE iterasyon uygular —
// TS `arr()` paritesi: null / yok → iterasyon YOK (boş dizi, KABUL); MEVCUT
// non-null bir değer bir dizi OLMALI (non-array → ErrNotJSONArray, TS `arr` throw),
// her eleman fn'e verilir. NOT: Go MarshalCanonical nil slice'ı `null` emit eder →
// bu alanların null'ı KABUL edilmeli, aksi halde Go KENDİ imzalı çıktısını reddederdi.
func ForEachElemNullable(raw *json.RawMessage, fn func(int, json.RawMessage) error) error {
	if IsAbsentOrNull(raw) {
		return nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(*raw, &elems); err != nil {
		return ErrNotJSONArray
	}
	for i := range elems {
		if err := fn(i, elems[i]); err != nil {
			return err
		}
	}
	return nil
}
