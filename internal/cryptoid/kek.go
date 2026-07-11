package cryptoid

// MASTER_KEK → per-project KEK → DEK wrap (SPEC §2.2–§2.5) — Go tarafı.
// Server-decrypt pivotunda zarf kriptosu SUNUCUDA koşar (§2.7); bu dosya
// yalnızca DR aracının (§8.4: `wapps dr restore`) ihtiyacı olan alt kümeyi
// taşır: kid türetimi, HKDF per-project KEK, WKW1 DEK-unwrap. Worker'daki
// crypto/kek.ts ile bayt-bayt paritelidir; frozen vektörler her iki tarafta
// CI'da koşar (build gate 2) — sapma release-blocker'dır.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// WrapRecipient, v2 manifest'lerdeki tek geçerli wrap alıcısı (kapalı küme, §2.4).
const WrapRecipient = "worker-kek:v1"

// WrapMagic, WKW1 çerçeve sihirli baytları (§2.4).
const WrapMagic = "WKW1"

// hkdfSalt, per-project KEK türetiminin sabit salt'ı (20 ASCII bayt, §2.3).
const hkdfSalt = "wapps-secrets/kek/v1"

// WrapTotalLen, bir WKW1 wrap'inin toplam bayt uzunluğu: magic(4) + nonce(24)
// + ciphertext(32+16) = 76 (§2.4).
const WrapTotalLen = 4 + chacha20poly1305.NonceSizeX + dekSize + chacha20poly1305.Overhead

// ErrWrapInvalid, WKW1 çerçeve/AEAD ihlali — tamper veya anahtar uyuşmazlığı
// (§2.4 WRAP_INVALID, fail-closed).
var ErrWrapInvalid = fmt.Errorf("cryptoid: WRAP_INVALID")

// KekKid, bir master anahtarın kid'ini türetir: SHA-256(32 HAM bayt)'ın ilk
// 16 küçük-harf hex karakteri (§2.2 — girdi ASLA ASCII hex string'i değildir).
func KekKid(raw []byte) (string, error) {
	if len(raw) != 32 {
		return "", fmt.Errorf("cryptoid.KekKid: master key must be 32 raw bytes")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16], nil
}

// DeriveProjectKEK, per-project KEK'i türetir (§2.3):
// HKDF-SHA-256(ikm=master, salt=hkdfSalt, info=project, L=32).
func DeriveProjectKEK(master []byte, project string) ([]byte, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("cryptoid.DeriveProjectKEK: master key must be 32 raw bytes")
	}
	kek := make([]byte, 32)
	r := hkdf.New(sha256.New, master, []byte(hkdfSalt), []byte(project))
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("cryptoid.DeriveProjectKEK: hkdf: %w", err)
	}
	return kek, nil
}

// WrapDEKForKEK, bir DEK'i projenin KEK'i altında WKW1 çerçevesine sarar
// (§2.4). Üretimde bu SUNUCU işidir; Go tarafında yalnızca DR/parite testleri
// fixture üretmek için kullanır. nonce nil → CSPRNG.
func WrapDEKForKEK(master []byte, project string, slot Slot, dek DEK, nonce []byte) ([]byte, error) {
	if err := slot.validate(); err != nil {
		return nil, err
	}
	kek, err := DeriveProjectKEK(master, project)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		nonce = make([]byte, chacha20poly1305.NonceSizeX)
		if _, rerr := rand.Read(nonce); rerr != nil {
			return nil, fmt.Errorf("cryptoid.WrapDEKForKEK: nonce: %w", rerr)
		}
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("cryptoid.WrapDEKForKEK: nonce must be %d bytes", chacha20poly1305.NonceSizeX)
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.WrapDEKForKEK: aead: %w", err)
	}
	out := make([]byte, 0, WrapTotalLen)
	out = append(out, WrapMagic...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, dek[:], slot.AAD())
	return out, nil
}

// UnwrapDEKWithKEK, bir WKW1 wrap'ini projenin KEK'i altında açar (§2.4).
// AAD = blob AEAD ile AYNI slot bağlaması — bir wrap başka projeye/anahtara/
// versiyona replay edilemez. Her ihlal ErrWrapInvalid (fail-closed, tamper).
func UnwrapDEKWithKEK(master []byte, project string, slot Slot, wrap []byte) (DEK, error) {
	var dek DEK
	if err := slot.validate(); err != nil {
		return dek, err
	}
	if len(wrap) != WrapTotalLen {
		return dek, ErrWrapInvalid
	}
	if string(wrap[:4]) != WrapMagic {
		return dek, ErrWrapInvalid
	}
	kek, err := DeriveProjectKEK(master, project)
	if err != nil {
		return dek, err
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return dek, fmt.Errorf("cryptoid.UnwrapDEKWithKEK: aead: %w", err)
	}
	nonce := wrap[4 : 4+chacha20poly1305.NonceSizeX]
	ct := wrap[4+chacha20poly1305.NonceSizeX:]
	pt, err := aead.Open(nil, nonce, ct, slot.AAD())
	if err != nil {
		return dek, ErrWrapInvalid
	}
	if len(pt) != dekSize {
		return dek, ErrWrapInvalid
	}
	copy(dek[:], pt)
	return dek, nil
}
