package cryptoid

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeStrictBase64 (FIX #1): KATİ KANONİK base64 decode'un Worker b64ToBytes
// ile TAM parite gösterdiğini doğrular — kanonik girdi kabul; padding'siz, gömülü
// newline, b64url alfabesi, non-canonical son-bayt bitleri ve gömülü boşluk RED.
// encoding/json'ın gevşek []byte decode'u bunların bir kısmını sessizce kabul eder;
// bu fonksiyon Go-kabul/Worker-red bölünmesini kapatır.
func TestDecodeStrictBase64(t *testing.T) {
	// Kanonik: kabul (roundtrip'li).
	raw, err := DecodeStrictBase64("//8=") // [0xff, 0xff]
	require.NoError(t, err)
	assert.Equal(t, []byte{0xff, 0xff}, raw)

	raw, err = DecodeStrictBase64("aGVsbG8h") // "hello!"
	require.NoError(t, err)
	assert.Equal(t, []byte("hello!"), raw)

	reject := map[string]string{
		"unpadded":            "aGVsbG8",    // padding'siz (len%4 != 0)
		"embedded newline":    "aGVs\nbG8h", // gömülü \n (encoding/json ATLAR)
		"embedded crlf":       "aGV\r\nsbG8h",
		"b64url alphabet":     "-_-_",      // std alfabe değil
		"non-canonical tail":  "//9=",      // son-bayt bitleri sıfır değil (StdEncoding KABUL ederdi)
		"embedded space len4": "a A=",      // boşluk (alfabe dışı)
		"trailing space":      "aGVsbG8h ", // sondaki boşluk
	}
	for name, s := range reject {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeStrictBase64(s)
			assert.ErrorIs(t, err, ErrNonCanonicalBase64, "input %q must be rejected", s)
		})
	}
}

// TestB64Strict_UnmarshalJSON (FIX #1): B64Strict alanının KATİLİĞİ YAPISAL olarak
// (UnmarshalJSON içinde) zorladığını doğrular — bir consensus base64 alanı gevşek
// bir spelling ile decode edilemez. ZORUNLU alan olduğundan JSON `null` REDDEDİLİR
// (Worker b64ToBytes bir string bekler; `null` bir string değildir — COORD a).
func TestB64Strict_UnmarshalJSON(t *testing.T) {
	type wrapper struct {
		B B64Strict `json:"b"`
	}

	// Kanonik: kabul.
	var w wrapper
	require.NoError(t, json.Unmarshal([]byte(`{"b":"aGVsbG8h"}`), &w))
	assert.Equal(t, []byte("hello!"), []byte(w.B))

	// null → red (ZORUNLU base64 alanı bir string olmalı).
	var wn wrapper
	assert.ErrorIs(t, json.Unmarshal([]byte(`{"b":null}`), &wn), ErrMissingBase64)

	// Non-canonical: red (gömülü newline + non-canonical tail).
	for _, bad := range []string{`{"b":"aGVsbG8"}`, `{"b":"aGVs\nbG8h"}`, `{"b":"//9="}`} {
		var wb wrapper
		err := json.Unmarshal([]byte(bad), &wb)
		assert.ErrorIs(t, err, ErrNonCanonicalBase64, "input %s must be rejected", bad)
	}
}

// TestAssertCanonicalIntegerJSON (FIX #2): imzalı body'deki HER sayı token'ının
// Worker assertCanonicalIntegerJSON paritesiyle denetlendiğini doğrular — kanonik
// tamsayı + güvenli aralık kabul; non-integer biçim (1e3/1.0/baştaki-sıfır) ve
// >2^53-1 magnitude RED; string İÇİNDEKİ sayılar (base64/tarih) atlanır.
func TestAssertCanonicalIntegerJSON(t *testing.T) {
	// Kabul: sınır değer 2^53-1 + 0 + string içinde büyük "sayı" (atlanmalı).
	ok := []string{
		`{"a":1,"b":9007199254740991,"c":0}`,
		`{"s":"1e999","hash":"9999999999999999999999","t":"2026-07-11T00:00:00Z"}`,
		`{"nested":{"n":42},"arr":[1,2,3]}`,
	}
	for _, body := range ok {
		assert.NoError(t, AssertCanonicalIntegerJSON([]byte(body)), "body %s must pass", body)
	}

	// Red: >2^53-1 + non-integer biçimler + İŞARETSİZ alan → negatif/-0 (COORD b).
	bad := map[string]string{
		"over max":           `{"n":9007199254740992}`,     // 2^53
		"over max negative":  `{"n":-9007199254740992}`,    // -2^53
		"way over":           `{"n":99999999999999999999}`, // 20 basamak
		"exponent":           `{"n":1e3}`,
		"float":              `{"n":1.0}`,
		"leading zero":       `{"n":01}`,
		"negative":           `{"n":-1}`, // COORD b: işaretsiz alan → negatif yasak
		"negative one digit": `{"d":-5}`,
		"negative max safe":  `{"neg":-9007199254740991}`,
		"negative zero":      `{"n":-0}`, // COORD b: -0 yasak
		"nested passthrough": `{"rotation":{"deep":1e9999}}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, AssertCanonicalIntegerJSON([]byte(body)), ErrNonCanonicalJSONNumber, "body %s must be rejected", body)
		})
	}
}
