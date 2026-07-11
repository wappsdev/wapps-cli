package cryptoid

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DEK wrap'leri (SPEC §3.5.5): her manifest girdisi, DEK'ini yetkilendirilmiş
// her alıcıya sızdırmadan ulaştıran bir wrap-set taşır. Her wrap, 32 baytlık
// DEK'in BAĞIMSIZ tek-alıcılı bir age v1 şifrelemesidir (binary format) —
// çok-alıcılı ortak header yok, böylece wrap'ler manifest'te tek tek eklenip
// çıkarılabilir.
//
// DETERMİNİSTİK KURULUM (F8, normatif §3.5.5): Bir wrap'in tükettiği TÜM
// rastgelelik (age file key + per-stanza ephemeral scalar + payload nonce) bir
// HKDF-SHA-256 akışından çekilir:
//
//	ikm  = DEK
//	salt = recipient fingerprint (§3.7, "sha256:<hex>" string'inin baytları)
//	info = "wapps-wrap-v1" ‖ project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion
//
// Akıştan SABİT sırayla okunur: fileKey(16) ‖ ephemeral(32) ‖ payloadNonce(16).
// Wrap baytları böylece (DEK, recipient, slot)'ın SAF bir fonksiyonudur. Bu
// güvenlidir çünkü DEK'ler blob başına benzersizdir (§3.5.1); türetilen akış
// farklı DEK'ler arasında asla tekrar etmez. Bu el-yapımı age-v1 üretimi
// standart age.Decrypt ile çözülebilir olmalıdır (UnsealDEK ile test edilir);
// zorunlu WrapVerify öz-kontrolü bu üretimin doğruluğunu imzadan önce kanıtlar.
//
// NOT (age API): filippo.io/age.Encrypt rastgeleliği crypto/rand'dan doğrudan
// çeker ve enjekte edilebilir bir rand kaynağı SUNMAZ; deterministik çıktı
// için age v1 tek-alıcılı X25519 konteynerini (iyi belgelenmiş, sabit format)
// burada byte-exact yeniden üretiyoruz. Okuma yolu standart age'i kullanır.

const (
	// wrapInfoLabel, HKDF info önekidir (§3.5.5).
	wrapInfoLabel = "wapps-wrap-v1"
	// x25519Label, age'in X25519 stanza HKDF etiketiyle AYNI olmalıdır.
	x25519Label = "age-encryption.org/v1/X25519"
	// ageIntro, age v1 dosya girişi.
	ageIntro = "age-encryption.org/v1\n"
	// ageFileKeySize, age file key boyutu (16 bayt).
	ageFileKeySize = 16
	// ageStreamNonceSize, age payload nonce boyutu (16 bayt).
	ageStreamNonceSize = 16
	// b64 sarma genişliği (age WrappedBase64Encoder ile aynı).
	b64Columns = 64
)

// ageB64, age'in kullandığı base64: RawStd (padding yok).
var ageB64 = base64.RawStdEncoding

// deriveWrapEntropy, wrap için deterministik entropiyi türetir (§3.5.5).
func deriveWrapEntropy(dek DEK, recipientFingerprint string, slot Slot) (fileKey, ephemeral, payloadNonce []byte, err error) {
	info := append([]byte(wrapInfoLabel), slot.AAD()...) // "wapps-wrap-v1" ‖ project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion
	h := hkdf.New(sha256.New, dek[:], []byte(recipientFingerprint), info)
	buf := make([]byte, ageFileKeySize+x25519PointSize+ageStreamNonceSize)
	if _, err = io.ReadFull(h, buf); err != nil {
		return nil, nil, nil, fmt.Errorf("cryptoid.deriveWrapEntropy: %w", err)
	}
	fileKey = buf[:ageFileKeySize]
	ephemeral = buf[ageFileKeySize : ageFileKeySize+x25519PointSize]
	payloadNonce = buf[ageFileKeySize+x25519PointSize:]
	return fileKey, ephemeral, payloadNonce, nil
}

// wrapBase64Body, gövdeyi age'in WrappedBase64Encoder'ı gibi 64 sütunda
// LF ile sarar (baş/son newline yok).
func wrapBase64Body(raw []byte) string {
	s := ageB64.EncodeToString(raw)
	if len(s) <= b64Columns {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i += b64Columns {
		if i > 0 {
			sb.WriteByte('\n')
		}
		end := i + b64Columns
		if end > len(s) {
			end = len(s)
		}
		sb.WriteString(s[i:end])
	}
	return sb.String()
}

// SealDEK, DEK'i verilen X25519 alıcısına DETERMİNİSTİK olarak wrap'ler ve
// tam bir age v1 dosyası (byte-exact) döner (SPEC §3.5.5). Aynı (DEK, recipient,
// slot) her zaman aynı baytları üretir.
func SealDEK(dek DEK, recipient *X25519Recipient, slot Slot) ([]byte, error) {
	if err := slot.validate(); err != nil {
		return nil, err
	}
	if recipient == nil || len(recipient.point) != x25519PointSize {
		return nil, fmt.Errorf("cryptoid.SealDEK: invalid recipient")
	}
	fileKey, ephemeral, payloadNonce, err := deriveWrapEntropy(dek, recipient.Fingerprint(), slot)
	if err != nil {
		return nil, err
	}

	// 1) Ephemeral X25519: ourPublicKey + sharedSecret (age x25519.go ile aynı).
	ourPublicKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.SealDEK: ephemeral public: %w", err)
	}
	sharedSecret, err := curve25519.X25519(ephemeral, recipient.point)
	if err != nil {
		// Düşük mertebeli nokta / tüm-sıfır paylaşılan sır: age de reddeder.
		return nil, fmt.Errorf("cryptoid.SealDEK: shared secret: %w", err)
	}

	// 2) Wrapping key = HKDF(sharedSecret, ourPub‖theirPub, x25519Label)[:32].
	salt := make([]byte, 0, len(ourPublicKey)+len(recipient.point))
	salt = append(salt, ourPublicKey...)
	salt = append(salt, recipient.point...)
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sharedSecret, salt, []byte(x25519Label)), wrappingKey); err != nil {
		return nil, fmt.Errorf("cryptoid.SealDEK: wrapping key: %w", err)
	}

	// 3) Wrapped file key = ChaCha20Poly1305(wrappingKey, zeroNonce, fileKey).
	//    age aeadEncrypt sabit sıfır nonce kullanır (anahtar tek-kullanımlık).
	wrapAEAD, err := chacha20poly1305.New(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.SealDEK: wrap aead: %w", err)
	}
	zeroNonce := make([]byte, chacha20poly1305.NonceSize)
	wrappedFileKey := wrapAEAD.Seal(nil, zeroNonce, fileKey, nil)

	// 4) Header (MAC'siz): intro + stanza + "---".
	stanza := "-> X25519 " + ageB64.EncodeToString(ourPublicKey) + "\n" +
		wrapBase64Body(wrappedFileKey) + "\n"
	hdrWithoutMAC := ageIntro + stanza + "---"

	// 5) Header MAC = HMAC-SHA256(HKDF(fileKey, nil, "header")[:32], hdrWithoutMAC).
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, fileKey, nil, []byte("header")), hmacKey); err != nil {
		return nil, fmt.Errorf("cryptoid.SealDEK: hmac key: %w", err)
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(hdrWithoutMAC))
	header := hdrWithoutMAC + " " + ageB64.EncodeToString(mac.Sum(nil)) + "\n"

	// 6) Payload = payloadNonce(16) ‖ STREAM(dek). Tek son-chunk: nonce12 =
	//    [0]*11 ‖ 0x01; streamKey = HKDF(fileKey, payloadNonce, "payload")[:32].
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, fileKey, payloadNonce, []byte("payload")), streamKey); err != nil {
		return nil, fmt.Errorf("cryptoid.SealDEK: stream key: %w", err)
	}
	streamAEAD, err := chacha20poly1305.New(streamKey)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.SealDEK: stream aead: %w", err)
	}
	lastChunkNonce := make([]byte, chacha20poly1305.NonceSize) // 12 bayt
	lastChunkNonce[len(lastChunkNonce)-1] = 0x01               // son-chunk bayrağı
	streamCT := streamAEAD.Seal(nil, lastChunkNonce, dek[:], nil)

	out := make([]byte, 0, len(header)+len(payloadNonce)+len(streamCT))
	out = append(out, header...)
	out = append(out, payloadNonce...)
	out = append(out, streamCT...)
	return out, nil
}

// WrapVerify, kurulan bir wrap için zorunlu çift-yollu (dual-path) öz-kontrolü
// gerçekleştirir (SPEC §3.5.5): wrap'i (DEK, recipient, slot)'tan SIFIRDAN
// yeniden türetir ve depolanan wrap ile byte-compare eder. Uyuşmazsa
// ErrWrapSelfcheckFailed — yazım imzadan ÖNCE iptal edilmelidir. Bu, bellekteki
// wrap'e güvenmez; bağımsız olarak yeniden hesaplar.
func WrapVerify(dek DEK, recipient *X25519Recipient, slot Slot, storedWrap []byte) error {
	rederived, err := SealDEK(dek, recipient, slot)
	if err != nil {
		return fmt.Errorf("cryptoid.WrapVerify: %w", err)
	}
	if subtle.ConstantTimeCompare(rederived, storedWrap) != 1 {
		return ErrWrapSelfcheckFailed
	}
	return nil
}

// UnsealDEK, bir wrap'i (age v1 dosyası) STANDART age.Decrypt ile verilen X25519
// kimliğiyle çözer ve 32 baytlık DEK'i döner (SPEC §3.5.5 okuma yolu). Bu, wrap
// üretiminin age-uyumluluğunun kanıtıdır. Kimlik eşleşmezse/wrap bozuksa hata.
func UnsealDEK(wrap []byte, id *X25519Identity) (DEK, error) {
	if id == nil {
		return DEK{}, fmt.Errorf("cryptoid.UnsealDEK: nil identity")
	}
	r, err := age.Decrypt(bytes.NewReader(wrap), id.AgeIdentity())
	if err != nil {
		return DEK{}, fmt.Errorf("cryptoid.UnsealDEK: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return DEK{}, fmt.Errorf("cryptoid.UnsealDEK: read: %w", err)
	}
	if len(out) != dekSize {
		return DEK{}, ErrBlobMalformed
	}
	var dek DEK
	copy(dek[:], out)
	return dek, nil
}

// WrapSelfCheck, yazarın KENDİ cihaz kimlikleri için tam öz-kontroldür
// (SPEC §3.5.5): önce byte-compare yeniden türetme (WrapVerify), sonra bir
// wrap'i round-trip DECRYPT ederek DEK'in geri geldiğini doğrular.
func WrapSelfCheck(dek DEK, recipient *X25519Recipient, slot Slot, storedWrap []byte, id *X25519Identity) error {
	if err := WrapVerify(dek, recipient, slot, storedWrap); err != nil {
		return err
	}
	got, err := UnsealDEK(storedWrap, id)
	if err != nil {
		return fmt.Errorf("cryptoid.WrapSelfCheck: roundtrip: %w", err)
	}
	if subtle.ConstantTimeCompare(got[:], dek[:]) != 1 {
		return ErrWrapSelfcheckFailed
	}
	return nil
}
