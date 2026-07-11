package lifecycle

import (
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// HardwareKeygen, enroll anahtar üretimini soyutlar (SPEC §8.1.1). YAZILIM
// uygulaması (SoftwareKeygen) CI/test yoludur; DONANIM yolu (Secure Enclave via
// age-plugin-se / CryptoKit, YubiKey via age-plugin-yubikey / PIV) bu ARAYÜZÜN
// arkasına düşer ve motorun KAPSAMI DIŞINDADIR — gerçek donanım anahtarı da aynı
// public-key baytlarını + aynı parmak izini üretir, yalnızca gizli materyal
// donanım öğesini asla terk etmez. Bir donanım uygulaması EncKeyHandle.Identity()
// için nil döner (çözme plugin üzerinden yapılır).
type HardwareKeygen interface {
	// EncIdentity, bir X25519 şifreleme kimliği üretir.
	EncIdentity() (EncKeyHandle, error)
	// SigningKey, verilen sınıf için (§3.4) bir imzalama anahtarı üretir:
	//   daily/admin → ECDSA P-256 (insan donanım sınıfları),
	//   automation  → Ed25519 (makine yazar).
	SigningKey(class string) (cryptoid.SigningKey, error)
	// Media, kayıt girdilerine yazılan medya etiketi ("software"|"secure-enclave"|
	// "yubikey").
	Media() string
}

// EncKeyHandle, üretilmiş bir şifreleme kimliğine erişimdir. Recipient her zaman
// mevcuttur (kayıt + wrap-set için); Identity YALNIZCA yazılım-resident anahtarlar
// için doludur (donanımda nil — çözme plugin ile yapılır).
type EncKeyHandle interface {
	Recipient() *cryptoid.X25519Recipient
	Identity() *cryptoid.X25519Identity
	Media() string
}

// SoftwareKeygen, HardwareKeygen'in yazılımsal (SPEC §8.1.1 "software fallback")
// uygulamasıdır — CI/test yolu. class: "software" olarak işaretlenir.
type SoftwareKeygen struct{}

// EncIdentity, yazılımsal bir X25519 şifreleme kimliği üretir.
func (SoftwareKeygen) EncIdentity() (EncKeyHandle, error) {
	id, err := cryptoid.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return softwareEncHandle{id: id}, nil
}

// SigningKey, sınıfa göre yazılımsal bir imzalama anahtarı üretir.
func (SoftwareKeygen) SigningKey(class string) (cryptoid.SigningKey, error) {
	switch class {
	case registry.SignClassAutomation, registry.SignClassRoot:
		return cryptoid.GenerateEd25519()
	default: // daily | admin → insan donanım sınıfları P-256
		return cryptoid.GenerateECDSAP256()
	}
}

// Media, yazılım keygen etiketi.
func (SoftwareKeygen) Media() string { return "software" }

// softwareEncHandle, yazılım-resident bir enc kimliği handle'ı.
type softwareEncHandle struct{ id *cryptoid.X25519Identity }

func (h softwareEncHandle) Recipient() *cryptoid.X25519Recipient { return h.id.Recipient() }
func (h softwareEncHandle) Identity() *cryptoid.X25519Identity   { return h.id }
func (h softwareEncHandle) Media() string                        { return "software" }

// BackupIdentity, enrollment seremonisinde bellekte üretilen paper/steel yedek
// age X25519 anahtarıdır (SPEC §8.3 / D11). Public yarı kayda girer; gizli yarı
// YALNIZCA BİR KEZ SecretOnce() ile terminale basılır ve ASLA diske/clipboard'a
// yazılmaz — motor gizliyi yalnızca bellekte tutar ve SecretOnce çağrısından sonra
// bufferı sıfırlar (best-effort; Go GC nedeniyle mutlak değil, ama --out bayrağı
// veya kalıcılık YOKTUR).
type BackupIdentity struct {
	recipient *cryptoid.X25519Recipient
	secret    []byte // AGE-SECRET-KEY-1... baytları; SecretOnce sonrası sıfırlanır
	consumed  bool
}

// GenerateBackupIdentity, bellek-içi bir yedek kimlik üretir. Gizli yarı yalnızca
// SecretOnce ile bir kez alınabilir.
func GenerateBackupIdentity() (*BackupIdentity, error) {
	id, err := cryptoid.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return &BackupIdentity{
		recipient: id.Recipient(),
		secret:    []byte(id.String()),
	}, nil
}

// Recipient, yedek kimliğin PUBLIC alıcısını döner (kayda + wrap-set'e girer).
func (b *BackupIdentity) Recipient() *cryptoid.X25519Recipient { return b.recipient }

// SecretOnce, gizli anahtarı BİR KEZ döner (transkripsiyon için); ikinci çağrı boş
// döner. Dönüşten sonra iç buffer sıfırlanır — kalıcılık/tekrar-okuma yoktur (§8.3
// tool-enforced: özel yarı diske asla yazılmaz).
func (b *BackupIdentity) SecretOnce() string {
	if b.consumed {
		return ""
	}
	s := string(b.secret)
	for i := range b.secret {
		b.secret[i] = 0
	}
	b.secret = nil
	b.consumed = true
	return s
}
