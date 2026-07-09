package cryptoid

// Bu dosya, age recipient/identity string'lerinden ham anahtar baytlarını
// çözmek için minimal bir Bech32 kodlayıcı/çözücü sağlar (BIP-0173 referans
// algoritması, age'in kaldırdığı 90-karakter sınırı olmadan; checksum sabiti
// 1 — bech32m DEĞİL). age'in kendi bech32'si internal/ altında olduğu için
// dışa aktarılamıyor; deterministik X25519 wrap'in ham noktaya ihtiyacı var.
//
// Referans: Pieter Wuille, BIP-0173 (BSD-2). age/internal/bech32 ile aynı
// davranış — deterministik ve iyi test edilmiş bir algoritma.

import (
	"fmt"
	"strings"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Rev = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(bech32Charset); i++ {
		t[bech32Charset[i]] = int8(i)
	}
	return t
}()

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	// age ile aynı: checksum HER ZAMAN küçük-harf HRP üzerinden hesaplanır.
	h := strings.ToLower(hrp)
	out := make([]byte, 0, len(h)*2+1)
	for i := 0; i < len(h); i++ {
		out = append(out, h[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(h); i++ {
		out = append(out, h[i]&31)
	}
	return out
}

func bech32VerifyChecksum(hrp string, data []byte) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), data...)) == 1
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return out
}

// convertBits, bir bayt dizisini frombits→tobits genişliğine yeniden paketler.
func convertBits(data []byte, frombits, tobits uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	var out []byte
	maxv := uint32((1 << tobits) - 1)
	for _, b := range data {
		if uint32(b)>>frombits != 0 {
			return nil, fmt.Errorf("cryptoid.convertBits: invalid data range")
		}
		acc = acc<<frombits | uint32(b)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(tobits-bits)&maxv))
		}
	} else if bits >= frombits || byte(acc<<(tobits-bits)&maxv) != 0 {
		return nil, fmt.Errorf("cryptoid.convertBits: invalid padding")
	}
	return out, nil
}

// bech32Decode, bir bech32 string'ini (hrp, 8-bit veri) olarak çözer.
func bech32Decode(s string) (string, []byte, error) {
	if s != strings.ToLower(s) && s != strings.ToUpper(s) {
		return "", nil, fmt.Errorf("cryptoid.bech32Decode: mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, fmt.Errorf("cryptoid.bech32Decode: invalid separator position")
	}
	hrp := s[:pos]
	data := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		d := bech32Rev[s[i]]
		if d == -1 {
			return "", nil, fmt.Errorf("cryptoid.bech32Decode: invalid character")
		}
		data = append(data, byte(d))
	}
	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("cryptoid.bech32Decode: bad checksum")
	}
	// Son 6 checksum karakterini at, 5-bit→8-bit dönüştür.
	conv, err := convertBits(data[:len(data)-6], 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("cryptoid.bech32Decode: %w", err)
	}
	return hrp, conv, nil
}

// bech32Encode, hrp + 8-bit veriyi bech32 string'e kodlar (age uzunluk sınırı
// yok). HRP büyük harfse çıktı büyük harf olur (age ile aynı davranış).
// Deterministik; test/round-trip için kullanılır.
func bech32Encode(hrp string, data []byte) (string, error) {
	if hrp == "" {
		return "", fmt.Errorf("cryptoid.bech32Encode: empty HRP")
	}
	if strings.ToUpper(hrp) != hrp && strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("cryptoid.bech32Encode: mixed case HRP")
	}
	conv, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("cryptoid.bech32Encode: %w", err)
	}
	lower := strings.ToLower(hrp) == hrp
	lhrp := strings.ToLower(hrp)
	checksum := bech32CreateChecksum(lhrp, conv)
	var sb strings.Builder
	sb.WriteString(lhrp)
	sb.WriteByte('1')
	for _, b := range append(conv, checksum...) {
		sb.WriteByte(bech32Charset[b])
	}
	if lower {
		return sb.String(), nil
	}
	return strings.ToUpper(sb.String()), nil
}
