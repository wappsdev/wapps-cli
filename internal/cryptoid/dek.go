package cryptoid

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// DEK, tek bir değer bloğunu şifreleyen Data Encryption Key'dir: 32 bayt
// CSPRNG, her (project, keyName, keyVersion) için TAZE üretilir; asla yeniden
// kullanılmaz, asla türetilmez, asla düz metin diske yazılmaz (SPEC §3.5.1).
type DEK [32]byte

// dekSize, DEK bayt uzunluğu.
const dekSize = 32

// NewDEK, CSPRNG'den taze bir 32 baytlık DEK üretir.
func NewDEK() (DEK, error) {
	var k DEK
	if err := randRead(k[:]); err != nil {
		return DEK{}, fmt.Errorf("cryptoid.NewDEK: %w", err)
	}
	return k, nil
}

// Slot, bir değerin mantıksal yerini tanımlar: (project, keyName, keyVersion).
// AAD (§3.5.3) ve deterministik wrap info (§3.5.5) bundan türetilir.
type Slot struct {
	Project    string
	KeyName    string
	KeyVersion uint64
}

// validateSlot, project/keyName'in NUL içermediğini doğrular (§3.5.3) — AAD
// kodlamasının injektif olması için gerekli.
func (s Slot) validate() error {
	if strings.IndexByte(s.Project, 0x00) >= 0 {
		return fmt.Errorf("cryptoid: project name must not contain NUL")
	}
	if strings.IndexByte(s.KeyName, 0x00) >= 0 {
		return fmt.Errorf("cryptoid: key name must not contain NUL")
	}
	return nil
}

// AAD, ciphertext'i mantıksal slot'una bağlayan ek doğrulama verisidir:
// AAD = project ‖ 0x00 ‖ keyName ‖ 0x00 ‖ keyVersion(decimal ASCII) (§3.5.3).
func (s Slot) AAD() []byte {
	var b bytes.Buffer
	b.WriteString(s.Project)
	b.WriteByte(0x00)
	b.WriteString(s.KeyName)
	b.WriteByte(0x00)
	b.WriteString(strconv.FormatUint(s.KeyVersion, 10))
	return b.Bytes()
}

// --- Padding (v1, frozen §3.5.2) ---

const (
	bucket256 = 256
	bucket1K  = 1024
	bucket4K  = 4096
	// blobCap, toplam depolanan blob objesi üst sınırı (§5.7): 64 KB.
	blobCap = 65536
	// blobOverhead, magic(4) + nonce(24) + AEAD tag(16).
	blobOverhead = blobMagicLen + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	// lenPrefix, padlenmiş formdaki uint32-BE uzunluk öneki.
	lenPrefix = 4
)

// maxBucket, blob kapasitesine sığan en büyük 4 KiB katı kova.
var maxBucket = (blobCap - blobOverhead) / bucket4K * bucket4K

// bucketFor, plaintext uzunluğu için hedef kova boyutunu seçer (§3.5.2). Kova
// sığmazsa ErrValueTooLarge döner.
func bucketFor(plaintextLen int) (int, error) {
	n := plaintextLen + lenPrefix // uzunluk öneki dahil
	switch {
	case n <= bucket256:
		return bucket256, nil
	case n <= bucket1K:
		return bucket1K, nil
	case n <= bucket4K:
		return bucket4K, nil
	default:
		// Bir sonraki 4 KiB katına yuvarla, 64 KB kapasitesiyle sınırlı.
		bucket := (n + bucket4K - 1) / bucket4K * bucket4K
		if bucket > maxBucket {
			return 0, ErrValueTooLarge
		}
		return bucket, nil
	}
}

// isValidBucket, decrypt'te bir kova boyutunun tanınan bir kova olup olmadığını
// doğrular (tamper savunması).
func isValidBucket(size int) bool {
	switch size {
	case bucket256, bucket1K:
		return true
	}
	return size >= bucket4K && size <= maxBucket && size%bucket4K == 0
}

// pad, plaintext'i uint32-BE uzunluk öneki ‖ plaintext ‖ sıfır dolgu olarak
// seçilen kovaya doldurur (§3.5.2).
func pad(plaintext []byte) ([]byte, error) {
	if len(plaintext) > int(^uint32(0)) {
		return nil, ErrValueTooLarge
	}
	bucket, err := bucketFor(len(plaintext))
	if err != nil {
		return nil, err
	}
	out := make([]byte, bucket)
	binary.BigEndian.PutUint32(out[:lenPrefix], uint32(len(plaintext)))
	copy(out[lenPrefix:], plaintext)
	return out, nil
}

// unpad, padlenmiş formu çözer ve fill baytlarının sıfır olduğunu + uzunluğun
// kovaya sığdığını doğrular (§3.5.2). İhlal → ErrBlobMalformed (tamper).
func unpad(padded []byte) ([]byte, error) {
	if len(padded) < lenPrefix {
		return nil, ErrBlobMalformed
	}
	if !isValidBucket(len(padded)) {
		return nil, ErrBlobMalformed
	}
	l := binary.BigEndian.Uint32(padded[:lenPrefix])
	end := lenPrefix + int(l)
	if end < lenPrefix || end > len(padded) { // taşma veya kova aşımı
		return nil, ErrBlobMalformed
	}
	// 4 + length ötesindeki her fill baytı sıfır olmalı.
	for _, b := range padded[end:] {
		if b != 0 {
			return nil, ErrBlobMalformed
		}
	}
	out := make([]byte, int(l))
	copy(out, padded[lenPrefix:end])
	return out, nil
}

// --- Blob konteyneri (v1, frozen §3.5.4) ---

// BlobMagic, v1 blob konteyner sihirli baytları (magic + version).
const BlobMagic = "WSB1"

const blobMagicLen = 4

// SealBlob, plaintext'i pad → XChaCha20-Poly1305 (taze rastgele 24 baytlık
// nonce, AAD = slot) → "WSB1"-konteyner olarak şifreler (SPEC §3.5.4). Nonce
// rastgeledir; blob baytları bu yüzden deterministik DEĞİLDİR (wrap'ler
// deterministiktir, wrap.go).
func SealBlob(plaintext []byte, dek DEK, slot Slot) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if err := randRead(nonce); err != nil {
		return nil, fmt.Errorf("cryptoid.SealBlob: nonce: %w", err)
	}
	return sealBlobWithNonce(plaintext, dek, slot, nonce)
}

// sealBlobWithNonce, verilen nonce ile blob üretir (frozen vektörler için).
func sealBlobWithNonce(plaintext []byte, dek DEK, slot Slot, nonce []byte) ([]byte, error) {
	if err := slot.validate(); err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("cryptoid.sealBlobWithNonce: nonce must be %d bytes", chacha20poly1305.NonceSizeX)
	}
	padded, err := pad(plaintext)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(dek[:])
	if err != nil {
		return nil, fmt.Errorf("cryptoid.sealBlobWithNonce: aead: %w", err)
	}
	out := make([]byte, 0, blobMagicLen+len(nonce)+len(padded)+chacha20poly1305.Overhead)
	out = append(out, BlobMagic...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, padded, slot.AAD())
	if len(out) > blobCap {
		return nil, ErrValueTooLarge
	}
	return out, nil
}

// OpenBlob, bir "WSB1" blob'unu çözer: magic + AEAD (AAD = slot) doğrulanır,
// padding kaldırılır. Her ihlal ErrBlobMalformed (tamper) döner.
func OpenBlob(blob []byte, dek DEK, slot Slot) ([]byte, error) {
	if err := slot.validate(); err != nil {
		return nil, err
	}
	if len(blob) < blobOverhead {
		return nil, ErrBlobMalformed
	}
	if string(blob[:blobMagicLen]) != BlobMagic {
		// Bilinmeyen magic (§3.5.4) → BLOB_MALFORMED.
		return nil, ErrBlobMalformed
	}
	nonce := blob[blobMagicLen : blobMagicLen+chacha20poly1305.NonceSizeX]
	ct := blob[blobMagicLen+chacha20poly1305.NonceSizeX:]
	aead, err := chacha20poly1305.NewX(dek[:])
	if err != nil {
		return nil, fmt.Errorf("cryptoid.OpenBlob: aead: %w", err)
	}
	padded, err := aead.Open(nil, nonce, ct, slot.AAD())
	if err != nil {
		// AEAD auth hatası: yanlış DEK/AAD/tamper → BLOB_MALFORMED.
		return nil, ErrBlobMalformed
	}
	return unpad(padded)
}

// BlobHash, blob'un içerik adresi: TÜM depolanan baytlar üzerinde küçük-harf
// hex SHA-256 (§3.5.4). Manifest blobHash ve R2 obje anahtarları bu çıplak hex
// formu taşır ("sha256:" öneki YALNIZCA parmak izlerinde, §3.7).
func BlobHash(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// VerifyBlobHash, getirilen blob baytlarının beklenen çıplak-hex içerik
// adresiyle eşleştiğini parse/decrypt ÖNCESİ doğrular (§3.5.4). Eşleşmezse
// ErrBlobHashMismatch. Sabit-zamanlı karşılaştırma.
func VerifyBlobHash(blob []byte, expectedHex string) error {
	got := BlobHash(blob)
	if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(expectedHex))) != 1 {
		return ErrBlobHashMismatch
	}
	return nil
}
