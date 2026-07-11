package cryptoid

// Bu dosya, Go CLI ile TS Worker'ın imzalı-consensus yapıları üzerinde AYNI
// kabul/red kararını vermesi için paylaşılan KATİLİK (strictness) yardımcılarını
// barındırır — Worker crypto/verify.ts (b64ToBytes + assertCanonicalIntegerJSON)
// ile TAM parite. Sarmalayıcının KENDİSİ imzalı olmadığından, base64/sayı
// katılığında en ufak ayrışma bir "Go-kabul / Worker-red" (veya tersi) bölünmesi
// yaratır → read/trust desync. Bu yüzden her consensus base64 alanı ve her imzalı
// tamsayı token'ı burada TEK kanonik forma sabitlenir.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// maxSafeInteger, JS Number güvenli-tamsayı üst sınırıdır (2^53 - 1). İmzalı bir
// body'deki HER tamsayı token'ı bu alanı paylaşır (COORD a): Worker JSON sayılarını
// double olarak okur ve MAX_SAFE_INTEGER üstünü reddeder; Go uint64 daha fazlasını
// tam taşıyabildiği için burada açıkça reddedilmeli — böylece iki taraf aynı
// [0, 2^53-1] tamsayı alanında hemfikir olur.
const maxSafeInteger uint64 = 1<<53 - 1

var (
	// ErrNonCanonicalBase64: bir consensus base64 alanı (imzalı sarmalayıcı
	// bytes/sig, pubkey, DEK wrap) KATİ KANONİK RFC4648 std değil — padding'siz,
	// gömülü boşluk/newline, b64url alfabesi veya non-canonical son-bayt bitleri.
	// Worker b64ToBytes bunları reddeder; Go da reddetmeli (COORD a).
	ErrNonCanonicalBase64 = errors.New("cryptoid: NON_CANONICAL_BASE64")

	// ErrNonCanonicalJSONNumber: imzalı bir body'de kanonik-olmayan (1e3 / 1.0 /
	// baştaki sıfır) VEYA güvenli-tamsayı alanını (2^53-1) aşan bir sayı literali.
	// Worker assertCanonicalIntegerJSON ile parite (COORD a).
	ErrNonCanonicalJSONNumber = errors.New("cryptoid: NON_CANONICAL_JSON_NUMBER")

	// ErrMissingBase64: ZORUNLU imzalı bir base64 alanı (sarmalayıcı bytes/sig,
	// kök pubkey, DEK wrap) JSON `null` — bu alanlar Worker'da b64ToBytes ile
	// çözülür ve BİR STRING olmak ZORUNDADIR; `null` (veya yokluk) reddedilir.
	// encoding/json `null`'ı SESSİZCE nil dilime çözer → Go-kabul/Worker-red
	// bölünmesi. Bu sentinel o boşluğu kapatır (COORD a).
	ErrMissingBase64 = errors.New("cryptoid: MISSING_BASE64")
)

// DecodeStrictBase64, KATİ KANONİK standart base64'ü (RFC4648, padding'li) ham
// baytlara çözer — Worker crypto/verify.ts b64ToBytes ile TAM parite. Üç katman:
//  1. len%4 == 0 (padding'siz / gömülü boşluk-newline'lı girdiler elenir),
//  2. base64.StdEncoding.Strict (kanonik alfabe + non-canonical son-bayt bitleri red),
//  3. roundtrip: base64(decoded) == girdi (TEK kanonik kodlamayı zorlar).
//
// encoding/json'ın []byte decode'u (base64.StdEncoding, NON-strict) gömülü \n/\r'ı
// SESSİZCE ATLAR ve non-canonical son-bayt bitlerini KABUL eder → gevşek; bu
// fonksiyon o gap'i kapatır. Herhangi bir katman tutmazsa ErrNonCanonicalBase64.
func DecodeStrictBase64(s string) ([]byte, error) {
	// (1) padding'li olmalı: uzunluk 4'ün katı.
	if len(s)%4 != 0 {
		return nil, fmt.Errorf("cryptoid.DecodeStrictBase64: length %d not a multiple of 4: %w", len(s), ErrNonCanonicalBase64)
	}
	// (2) kanonik alfabe + non-canonical son-bayt bitleri reddi.
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.DecodeStrictBase64: %v: %w", err, ErrNonCanonicalBase64)
	}
	// (3) roundtrip kanoniklik kilidi: yeniden-kodlama girdiyle bit-bit aynı olmalı.
	if base64.StdEncoding.EncodeToString(raw) != s {
		return nil, fmt.Errorf("cryptoid.DecodeStrictBase64: roundtrip mismatch: %w", ErrNonCanonicalBase64)
	}
	return raw, nil
}

// B64Strict, imzalı-consensus base64 alanları için []byte tipidir: JSON'dan
// çözülürken KATİ KANONİK base64 (DecodeStrictBase64) zorunludur. encoding/json'ın
// varsayılan []byte decode'u gevşek olduğundan, bu tip katılığı alanın KENDİSİNDE
// YAPISAL olarak zorlar — her çağrı yerinin hatırlamasına bağlı kalmaz.
//
// Marshal tarafı ÖZEL DEĞİLDİR (MarshalJSON YOK): encoding/json, []byte-kind bir
// tipi base64 std padding'li kodlar → imzalanan kanonik baytlar DEĞİŞMEZ (frozen
// vektörler korunur).
type B64Strict []byte

// UnmarshalJSON, base64 string alanını KATİ KANONİK çözer. Alan ZORUNLU bir imzalı
// base64'tür → JSON `null` REDDEDİLİR (Worker b64ToBytes bir string bekler; `null`
// bir string değildir). Yalnızca kanonik base64 bir STRING kabul edilir.
func (b *B64Strict) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return fmt.Errorf("cryptoid.B64Strict.UnmarshalJSON: %w", ErrMissingBase64)
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("cryptoid.B64Strict.UnmarshalJSON: %w", err)
	}
	raw, err := DecodeStrictBase64(s)
	if err != nil {
		return err
	}
	*b = raw
	return nil
}

// AssertCanonicalIntegerJSON, imzalı bir body metnindeki string-DIŞI HER sayı
// token'ının Go json integer-decode paritesiyle uyumlu olduğunu doğrular — Worker
// crypto/verify.ts assertCanonicalIntegerJSON ile TAM parite (COORD a). Manifest'lerde
// (trust + data) HİÇBİR float alan yoktur; tüm sayılar tamsayıdır. Go, tamsayı
// alanına `1e3` / `1.0` literallerini REDDEDER ve >2^53 değerleri TAM taşır; ama
// bu katılık YALNIZCA tipli struct alanlarına uygulanır — rotation / jwk passthrough
// (json.RawMessage) içindeki sayılar denetlenmez. Worker ise TÜM body metnini tarar.
// Parite için burada da tüm ham body taranır: string DIŞINDAKİ her sayı token'ı
// kanonik İŞARETSİZ tamsayı biçiminde (`(0|[1-9][0-9]*)`, COORD b: negatif/-0 YASAK)
// ve güvenli aralıkta (≤2^53-1) olmalı; değilse ErrNonCanonicalJSONNumber. String
// literalleri (base64/hex/tarih içerik) atlanır.
func AssertCanonicalIntegerJSON(body []byte) error {
	n := len(body)
	i := 0
	inStr := false
	for i < n {
		c := body[i]
		if inStr {
			if c == '\\' {
				i += 2 // kaçış dizisi (\", \\, \uXXXX ...) — bir sonraki baytı atla
				continue
			}
			if c == '"' {
				inStr = false
			}
			i++
			continue
		}
		if c == '"' {
			inStr = true
			i++
			continue
		}
		// String dışında bir sayı ancak value pozisyonunda görünür (JSON anahtarları
		// daima string'tir) → '-' veya rakamla başlayan maksimal token'ı yakala.
		if c == '-' || (c >= '0' && c <= '9') {
			j := i
			for j < n {
				d := body[j]
				if (d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E' {
					j++
				} else {
					break
				}
			}
			tok := body[i:j]
			if !isCanonicalIntegerToken(tok) {
				return fmt.Errorf("cryptoid.AssertCanonicalIntegerJSON: non-integer number literal %q: %w", tok, ErrNonCanonicalJSONNumber)
			}
			if !isSafeIntegerMagnitude(tok) {
				return fmt.Errorf("cryptoid.AssertCanonicalIntegerJSON: integer literal out of safe range %q: %w", tok, ErrNonCanonicalJSONNumber)
			}
			i = j
			continue
		}
		i++
	}
	return nil
}

// isCanonicalIntegerToken, token'ın `^(0|[1-9][0-9]*)$` kalıbına uyduğunu döner
// (İŞARETSİZ; baştaki sıfır yasak — çok basamaklıda). İmzalı tamsayı alanı
// [0, 2^53-1] İŞARETSİZ olduğundan (COORD b), baştaki `-` (negatif / `-0`)
// REDDEDİLİR — Worker assertCanonicalIntegerJSON ile parite. `1e3`, `1.0`,
// `01`, `1-2`, `-1`, `-0` gibi biçimler reddedilir.
func isCanonicalIntegerToken(tok []byte) bool {
	s := tok
	if len(s) == 0 {
		return false
	}
	if s[0] == '-' { // COORD (b): işaretsiz alan → negatif / -0 yasak
		return false
	}
	if len(s) == 1 {
		return s[0] >= '0' && s[0] <= '9'
	}
	if s[0] == '0' { // çok basamaklı: baştaki sıfır kanonik değil
		return false
	}
	for _, d := range s {
		if d < '0' || d > '9' {
			return false
		}
	}
	return true
}

// isSafeIntegerMagnitude, kanonik (işaretsiz) bir tamsayı token'ının değerinin
// [0, 2^53-1] içinde olduğunu döner (Number.isSafeInteger paritesi). Negatifler
// isCanonicalIntegerToken'da zaten elendiği için buraya yalnızca işaretsiz token gelir.
func isSafeIntegerMagnitude(tok []byte) bool {
	s := tok
	// 2^53-1 = 9007199254740991 → 16 basamak. 16'dan fazla basamak kesinlikle taşar.
	if len(s) > 16 {
		return false
	}
	v, err := strconv.ParseUint(string(s), 10, 64)
	if err != nil {
		return false
	}
	return v <= maxSafeInteger
}
