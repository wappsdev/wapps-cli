package cryptoid

import (
	"fmt"
	"io"
)

// Shamir Secret Sharing, GF(2^8) üzerinde bayt-bazlı (SPEC §3.9). Escrow gizli
// skalarını (32 bayt) 2-of-3 böler. Harici modül BAĞIMLILIĞI YOK — algoritma
// bu pakette vendor edilmiştir (SPEC §3.1/§3.9). Bu, HashiCorp Vault'un iyi
// test edilmiş GF(2^8) Shamir algoritmasının bir portudur (MPL-2.0); pinned
// test vektörleri format sabitliğini kilitler.
//
// Share formatı: her share = [len(secret) bayt y-değeri] ‖ [1 bayt x-koordinat].
// x-koordinatları sabittir (1..parts) ve share içinde açıkça saklanır (gizli
// değil). Bölme yalnızca offline ceremony'de yapılır; araç birleştirilmiş
// skaları veya herhangi bir share'i ASLA diske yazmaz — göster/transkribe et.

// GF(2^8) log/exp tabloları, AES indirgeme polinomu 0x11b ve üreteç 0x03 ile.
var (
	gfExp [256]uint8
	gfLog [256]uint8
)

func init() {
	x := uint8(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = uint8(i)
		x = gfMulNoTable(x, 3)
	}
	// gfExp[255] pratikte kullanılmaz; wrap için gfExp[0]'a eşitle.
	gfExp[255] = gfExp[0]
}

// gfMulNoTable, tablosuz GF(2^8) çarpımı (Russian peasant, poly 0x11b) — sadece
// tablo kurulumunda kullanılır.
func gfMulNoTable(a, b uint8) uint8 {
	var p uint8
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// gfAdd, GF(2^8) toplamı = XOR.
func gfAdd(a, b uint8) uint8 { return a ^ b }

// gfMul, tablo tabanlı GF(2^8) çarpımı.
func gfMul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

// gfInv, GF(2^8) çarpımsal tersi.
func gfInv(a uint8) uint8 {
	if a == 0 {
		// 0'ın tersi tanımsız; çağıranlar bunu asla tetiklememeli.
		panic("cryptoid: gfInv(0)")
	}
	return gfExp[(255-int(gfLog[a]))%255]
}

// gfDiv, GF(2^8) bölmesi.
func gfDiv(a, b uint8) uint8 {
	if b == 0 {
		panic("cryptoid: gfDiv by zero")
	}
	if a == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

// gfEval, poly polinomunu x noktasında değerlendirir (Horner, katsayılar artan
// derece sırasında: poly[0] = sabit terim).
func gfEval(poly []uint8, x uint8) uint8 {
	var result uint8
	for i := len(poly) - 1; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), poly[i])
	}
	return result
}

// ShamirSplit, secret'ı GF(2^8) üzerinde bayt-bazlı `parts` paya böler; herhangi
// `threshold` pay ile geri toplanabilir. Rastgelelik rng'den okunur (test
// vektörleri için sabit rng geçirilebilir).
func ShamirSplit(secret []byte, parts, threshold int, rng io.Reader) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("cryptoid.ShamirSplit: empty secret")
	}
	if parts < threshold {
		return nil, fmt.Errorf("cryptoid.ShamirSplit: parts < threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("cryptoid.ShamirSplit: threshold < 2")
	}
	if parts > 255 {
		return nil, fmt.Errorf("cryptoid.ShamirSplit: parts > 255")
	}
	if rng == nil {
		return nil, fmt.Errorf("cryptoid.ShamirSplit: nil rng")
	}

	// x-koordinatları sabit: 1..parts (0 asla kullanılamaz; 0 = gizli).
	shares := make([][]byte, parts)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][len(secret)] = uint8(i + 1) // x-koordinat son bayt
	}

	// Her gizli bayt için rastgele bir (threshold-1) dereceli polinom.
	poly := make([]uint8, threshold)
	for j := 0; j < len(secret); j++ {
		poly[0] = secret[j] // sabit terim = gizli bayt
		if _, err := io.ReadFull(rng, poly[1:]); err != nil {
			return nil, fmt.Errorf("cryptoid.ShamirSplit: rng: %w", err)
		}
		for i := 0; i < parts; i++ {
			shares[i][j] = gfEval(poly, uint8(i+1))
		}
	}
	return shares, nil
}

// ShamirCombine, verilen payları Lagrange interpolasyonuyla x=0'da birleştirip
// gizli sırrı geri döner. Paylar eşit uzunlukta olmalı ve x-koordinatları
// (son bayt) ayrık olmalıdır.
func ShamirCombine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("cryptoid.ShamirCombine: need at least 2 shares")
	}
	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, fmt.Errorf("cryptoid.ShamirCombine: share too short")
	}
	xs := make([]uint8, len(shares))
	seen := make(map[uint8]bool, len(shares))
	for i, sh := range shares {
		if len(sh) != shareLen {
			return nil, fmt.Errorf("cryptoid.ShamirCombine: shares have unequal length")
		}
		x := sh[shareLen-1]
		if x == 0 {
			return nil, fmt.Errorf("cryptoid.ShamirCombine: invalid x-coordinate 0")
		}
		if seen[x] {
			return nil, fmt.Errorf("cryptoid.ShamirCombine: duplicate x-coordinate")
		}
		seen[x] = true
		xs[i] = x
	}

	secretLen := shareLen - 1
	secret := make([]byte, secretLen)
	for j := 0; j < secretLen; j++ {
		// Lagrange interpolasyonu, x=0'da: sum_i y_i * prod_{k!=i} x_k/(x_i - x_k).
		var result uint8
		for i := range shares {
			yi := shares[i][j]
			num := uint8(1)
			den := uint8(1)
			for k := range shares {
				if k == i {
					continue
				}
				num = gfMul(num, xs[k])               // (0 - x_k) = x_k  (GF'de -a = a)
				den = gfMul(den, gfAdd(xs[i], xs[k])) // (x_i - x_k) = x_i xor x_k
			}
			result = gfAdd(result, gfMul(yi, gfDiv(num, den)))
		}
		secret[j] = result
	}
	return secret, nil
}
