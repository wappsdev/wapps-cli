package cryptoid

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// v1 algoritma registry (kapalı küme, SPEC §3.2). Doğrulayıcılar bu tablo
// dışındaki hiçbir alg'ı KABUL ETMEZ (ErrAlgUnsupported).
const (
	// AlgEd25519: 32 baytlık SHA-256 digest üzerinde Ed25519 (root + otomasyon).
	AlgEd25519 = "ed25519"
	// AlgECDSAP256SHA256: SHA-256 üzerinde ECDSA P-256, ham r‖s 64 baytlık imza
	// (IEEE P1363). İnsan daily+admin donanım anahtarları; Worker ES256.
	AlgECDSAP256SHA256 = "ecdsa-p256-sha256"
	// SigSchema: imza zarfı şeması (SPEC §3.6.1).
	SigSchema = "wapps-secrets/sig/v1"
)

// p256ScalarLen, P-256 için r/s bileşenlerinin bayt uzunluğu.
const p256ScalarLen = 32

// Signature, tek bir ayrık (detached) imzanın depolanan formudur (SPEC §3.6.1).
// Sig alanı Go JSON'da base64 (RFC 4648 std, padding'li) olarak kodlanır.
type Signature struct {
	Schema string `json:"schema"` // "wapps-secrets/sig/v1"
	KeyID  string `json:"key_id"` // imza-anahtarı parmak izi (§3.7)
	Alg    string `json:"alg"`    // "ed25519" | "ecdsa-p256-sha256"
	Sig    []byte `json:"sig"`    // base64; SHA-256(Bytes) üzerinde ayrık imza
}

// SignedObject, her imzalı manifest (data ve trust) için depolanan sarmalayıcı
// formdur (SPEC §3.6.1, §5.4.4). Bytes alanı Go JSON'da base64 olarak kodlanır
// ve TAM imzalanmış baytlardır — parse ETMEDEN önce hash ile doğrulanır.
type SignedObject struct {
	Bytes []byte      `json:"bytes"`
	Sigs  []Signature `json:"sigs"`
}

// SigningKey, bir imzalama kimliğinin ortak arayüzüdür. İmzalama kimlikleri
// şifreleme kimliklerinden KATİ olarak ayrıdır (SPEC §3.4); hiçbir kod yolu
// birinden diğerini türetemez.
type SigningKey interface {
	// KeyID, imzalama public key'inin parmak izi (§3.7).
	KeyID() string
	// Alg, bu anahtarın algoritma tanımlayıcısı (registry'den).
	Alg() string
	// PublicKeyBytes, parmak izi girdisi olan ham public key baytları (§3.6.1).
	PublicKeyBytes() []byte
	// Sign, TAM msg baytları üzerinden ayrık imza üretir: D = SHA-256(msg)
	// hesaplar ve alg'a göre D'yi imzalar (SPEC §3.6.2), Signature döner.
	Sign(msg []byte) (Signature, error)
}

// --- Ed25519 imzalama anahtarı ---

// Ed25519SigningKey, offline root + otomasyon writer sınıfı için yazılımsal
// Ed25519 imzalama anahtarıdır (SPEC §3.4).
type Ed25519SigningKey struct {
	priv ed25519.PrivateKey
}

// GenerateEd25519, yeni bir Ed25519 imzalama anahtarı üretir.
func GenerateEd25519() (*Ed25519SigningKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.GenerateEd25519: %w", err)
	}
	return &Ed25519SigningKey{priv: priv}, nil
}

// NewEd25519FromSeed, 32 baytlık seed'den deterministik bir Ed25519 imzalama
// anahtarı üretir (test vektörleri + offline ceremony reprodüksiyonu için).
func NewEd25519FromSeed(seed []byte) (*Ed25519SigningKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("cryptoid.NewEd25519FromSeed: seed must be %d bytes", ed25519.SeedSize)
	}
	return &Ed25519SigningKey{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func (k *Ed25519SigningKey) Alg() string { return AlgEd25519 }

// PublicKeyBytes, 32 baytlık Ed25519 public key (§3.6.1).
func (k *Ed25519SigningKey) PublicKeyBytes() []byte {
	pub := k.priv.Public().(ed25519.PublicKey)
	out := make([]byte, len(pub))
	copy(out, pub)
	return out
}

func (k *Ed25519SigningKey) KeyID() string { return Fingerprint(k.PublicKeyBytes()) }

func (k *Ed25519SigningKey) Sign(msg []byte) (Signature, error) {
	// Ed25519, 32 baytlık digest'i mesaj olarak imzalar (SPEC §3.6.2).
	d := sha256.Sum256(msg)
	sig := ed25519.Sign(k.priv, d[:])
	return Signature{Schema: SigSchema, KeyID: k.KeyID(), Alg: AlgEd25519, Sig: sig}, nil
}

// PrivateSeed, Ed25519 anahtarının 32 baytlık seed'inin bir KOPYASINI döner —
// YAZILIM (CI/test) kimliğinin 0600 kimlik deposuna kalıcılaştırılması için
// (SPEC §8.1.1 software fallback). NewEd25519FromSeed ile geri kurulur. DİKKAT:
// gizli materyal; loglanmamalı, yalnızca 0600 kimlik dosyasına yazılmalı.
func (k *Ed25519SigningKey) PrivateSeed() []byte {
	seed := k.priv.Seed()
	out := make([]byte, len(seed))
	copy(out, seed)
	return out
}

// --- ECDSA P-256 imzalama anahtarı ---

// ECDSAP256SigningKey, insan daily/admin donanım sınıfı (SE/YubiKey) için
// ECDSA P-256 imzalama anahtarıdır. Bu implementasyon YAZILIMSAL sign/verify
// sağlar; donanım bağlama (Secure Enclave CryptoKit / YubiKey PIV, presence)
// bu paketin KAPSAMI DIŞINDADIR (SPEC §3.4) — kabuk/arayüz aynıdır, gerçek
// donanım anahtarı da aynı P1363 baytlarını üretir.
type ECDSAP256SigningKey struct {
	priv *ecdsa.PrivateKey
}

// GenerateECDSAP256, yeni bir yazılımsal ECDSA P-256 imzalama anahtarı üretir.
func GenerateECDSAP256() (*ECDSAP256SigningKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.GenerateECDSAP256: %w", err)
	}
	return &ECDSAP256SigningKey{priv: priv}, nil
}

// NewECDSAP256FromPriv, mevcut bir *ecdsa.PrivateKey'i sarmalar.
func NewECDSAP256FromPriv(priv *ecdsa.PrivateKey) (*ECDSAP256SigningKey, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("cryptoid.NewECDSAP256FromPriv: key must be P-256")
	}
	return &ECDSAP256SigningKey{priv: priv}, nil
}

// PrivateScalar, P-256 gizli skalarını 32 baytlık big-endian (sabit-uzunluk) döner
// — YAZILIM (CI/test) kimliğinin 0600 kimlik deposuna kalıcılaştırılması için.
// NewECDSAP256FromScalar ile geri kurulur. ecdsa.PrivateKey.Bytes() kullanır
// (deprecated ham .D yerine, Go 1.25+). DİKKAT: gizli materyal.
func (k *ECDSAP256SigningKey) PrivateScalar() []byte {
	b, err := k.priv.Bytes()
	if err != nil {
		// Geçerli bir P-256 anahtarı için Bytes() her zaman başarılıdır; olmazsa bug.
		panic("cryptoid: internal error: P-256 PrivateKey.Bytes() failed: " + err.Error())
	}
	return b
}

// NewECDSAP256FromScalar, 32 baytlık gizli skalardan bir P-256 imzalama anahtarını
// yeniden kurar (kimlik deposundan yükleme). ecdsa.ParseRawPrivateKey skaları
// aralık/geçerlilik açısından doğrular ve public noktayı türetir (Go 1.25+).
func NewECDSAP256FromScalar(scalar []byte) (*ECDSAP256SigningKey, error) {
	if len(scalar) != p256ScalarLen {
		return nil, fmt.Errorf("cryptoid.NewECDSAP256FromScalar: scalar must be %d bytes", p256ScalarLen)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.NewECDSAP256FromScalar: %w", err)
	}
	return NewECDSAP256FromPriv(priv)
}

func (k *ECDSAP256SigningKey) Alg() string { return AlgECDSAP256SHA256 }

// PublicKeyBytes, 65 baytlık sıkıştırılmamış SEC1 nokta (0x04 ‖ X ‖ Y) — §3.6.1.
// crypto/ecdh ile üretilir (deprecated elliptic.Marshal yerine).
func (k *ECDSAP256SigningKey) PublicKeyBytes() []byte {
	ecdhPub, err := k.priv.PublicKey.ECDH()
	if err != nil {
		// P-256 anahtarları için ECDH() her zaman başarılıdır; olmazsa bug.
		panic("cryptoid: internal error: P-256 ECDH() failed: " + err.Error())
	}
	return ecdhPub.Bytes()
}

func (k *ECDSAP256SigningKey) KeyID() string { return Fingerprint(k.PublicKeyBytes()) }

func (k *ECDSAP256SigningKey) Sign(msg []byte) (Signature, error) {
	// D = SHA-256(msg); ECDSA D'yi imzalar (SPEC §3.6.2).
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, d[:])
	if err != nil {
		return Signature{}, fmt.Errorf("cryptoid.ECDSAP256SigningKey.Sign: %w", err)
	}
	// Ham r‖s (P1363): her biri 32 bayt, big-endian, sıfır dolgulu (SPEC §3.2).
	// DER değil — WebCrypto-native format, CLI ve Worker baytları aynı olsun.
	sig := make([]byte, 2*p256ScalarLen)
	r.FillBytes(sig[:p256ScalarLen])
	s.FillBytes(sig[p256ScalarLen:])
	return Signature{Schema: SigSchema, KeyID: k.KeyID(), Alg: AlgECDSAP256SHA256, Sig: sig}, nil
}

// --- Doğrulama ---

// VerifierKey, bir imza doğrulamak için gereken public anahtarı + algoritmayı
// tutar. Parmak izi (KeyID) üzerinden keyring'lerde çözümlenir.
type VerifierKey struct {
	alg   string
	keyID string
	raw   []byte
	ed    ed25519.PublicKey
	ec    *ecdsa.PublicKey
}

// NewVerifierKey, verilen alg ve ham public key baytlarından bir VerifierKey
// kurar. Ham bayt formatı §3.6.1: Ed25519 = 32 bayt, P-256 = 65 bayt SEC1.
func NewVerifierKey(alg string, pubBytes []byte) (VerifierKey, error) {
	switch alg {
	case AlgEd25519:
		if len(pubBytes) != ed25519.PublicKeySize {
			return VerifierKey{}, fmt.Errorf("cryptoid.NewVerifierKey: ed25519 pubkey must be %d bytes: %w", ed25519.PublicKeySize, ErrAlgUnsupported)
		}
		pk := make(ed25519.PublicKey, len(pubBytes))
		copy(pk, pubBytes)
		return VerifierKey{alg: alg, keyID: Fingerprint(pubBytes), raw: pk, ed: pk}, nil
	case AlgECDSAP256SHA256:
		// crypto/ecdh, noktanın eğri üzerinde ve sıkıştırılmamış (65 bayt, 0x04)
		// olduğunu doğrular (deprecated elliptic.Unmarshal yerine).
		if _, err := ecdh.P256().NewPublicKey(pubBytes); err != nil {
			return VerifierKey{}, fmt.Errorf("cryptoid.NewVerifierKey: invalid P-256 SEC1 point: %w", ErrAlgUnsupported)
		}
		pk := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pubBytes[1:33]),
			Y:     new(big.Int).SetBytes(pubBytes[33:65]),
		}
		raw := make([]byte, len(pubBytes))
		copy(raw, pubBytes)
		return VerifierKey{alg: alg, keyID: Fingerprint(pubBytes), raw: raw, ec: pk}, nil
	default:
		return VerifierKey{}, fmt.Errorf("cryptoid.NewVerifierKey: %q: %w", alg, ErrAlgUnsupported)
	}
}

// KeyID, bu doğrulama anahtarının parmak izi.
func (vk VerifierKey) KeyID() string { return vk.keyID }

// Alg, bu doğrulama anahtarının algoritması.
func (vk VerifierKey) Alg() string { return vk.alg }

// Verify, TAM msg baytları üzerinden verilen imzayı doğrular. Doğrulama sırası
// (SPEC §3.6.2/§3.6.3): D = SHA-256(msg) hesapla, sonra alg'a göre doğrula.
// Başarısızlık ErrSigInvalid; kapalı-küme dışı alg ErrAlgUnsupported döner.
func (vk VerifierKey) Verify(msg, sig []byte) error {
	d := sha256.Sum256(msg)
	switch vk.alg {
	case AlgEd25519:
		if !ed25519.Verify(vk.ed, d[:], sig) {
			return ErrSigInvalid
		}
		return nil
	case AlgECDSAP256SHA256:
		// Yalnızca ham 64 baytlık r‖s kabul edilir; DER REDDEDİLİR (SPEC §3.2).
		if len(sig) != 2*p256ScalarLen {
			return ErrSigInvalid
		}
		r := new(big.Int).SetBytes(sig[:p256ScalarLen])
		s := new(big.Int).SetBytes(sig[p256ScalarLen:])
		if !ecdsa.Verify(vk.ec, d[:], r, s) {
			return ErrSigInvalid
		}
		return nil
	default:
		return ErrAlgUnsupported
	}
}

// VerifySignatureEnvelope, tek bir Signature'ı verilen VerifierKey ile msg
// üzerinde doğrular. Schema, alg tutarlılığı ve key_id eşleşmesi kontrol edilir.
func VerifySignatureEnvelope(msg []byte, s Signature, vk VerifierKey) error {
	if s.Schema != SigSchema {
		return fmt.Errorf("cryptoid.VerifySignatureEnvelope: bad schema %q: %w", s.Schema, ErrSigInvalid)
	}
	if s.Alg != vk.alg {
		return fmt.Errorf("cryptoid.VerifySignatureEnvelope: alg mismatch: %w", ErrSigInvalid)
	}
	if s.KeyID != vk.keyID {
		return fmt.Errorf("cryptoid.VerifySignatureEnvelope: key_id mismatch: %w", ErrSigInvalid)
	}
	return vk.Verify(msg, s.Sig)
}
