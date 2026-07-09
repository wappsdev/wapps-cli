package cryptoid

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// Şifreleme kimlikleri (SPEC §3.3): SADECE DEK unwrap etmek için kullanılan age
// alıcılarıdır. İMZALAYAMAZLAR — age X25519 kimliklerinin imzalama yeteneği
// yoktur ve hiçbir kod yolu bir şifreleme kimliğinden imzalama anahtarı
// türetemez. İmzalama anahtarları ayrı bir hiyerarşidir (signing.go, §3.4).

const (
	// x25519RecipientHRP, native age X25519 recipient bech32 HRP'si ("age1...").
	x25519RecipientHRP = "age"
	// x25519PointSize, Curve25519 nokta/skalar boyutu.
	x25519PointSize = 32
)

// X25519Recipient, deterministik DEK wrap'in ham 32 baytlık public noktasına
// erişebildiği yazılımsal bir age X25519 alıcısıdır (SPEC §3.3).
type X25519Recipient struct {
	point []byte // 32 bayt Curve25519 public key
	str   string // canonical "age1..." bech32
}

// ParseX25519Recipient, "age1..." bech32 alıcı string'ini çözer. age'in kendi
// parser'ıyla çapraz-doğrulanır; ham nokta deterministik wrap için saklanır.
func ParseX25519Recipient(s string) (*X25519Recipient, error) {
	s = strings.TrimSpace(s)
	// Savunma: age'in parser'ı formatı ve HRP'yi doğrular. Fingerprint'in
	// çapraz-implementasyon (TS Worker) tutarlılığı için age'in KANONİK
	// String()'ini saklıyoruz — çağıranın ham girdisini değil (§3.7).
	rec, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.ParseX25519Recipient: %w", err)
	}
	s = rec.String()
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.ParseX25519Recipient: %w", err)
	}
	if hrp != x25519RecipientHRP || len(data) != x25519PointSize {
		return nil, fmt.Errorf("cryptoid.ParseX25519Recipient: not a native X25519 recipient")
	}
	return &X25519Recipient{point: data, str: s}, nil
}

// String, canonical bech32 alıcı string'i döner.
func (r *X25519Recipient) String() string { return r.str }

// Point, ham 32 baytlık Curve25519 public key'in bir kopyasını döner.
func (r *X25519Recipient) Point() []byte {
	out := make([]byte, len(r.point))
	copy(out, r.point)
	return out
}

// Fingerprint, alıcının §3.7 parmak izi (recipient string üzerinden SHA-256).
func (r *X25519Recipient) Fingerprint() string { return FingerprintRecipient(r.str) }

// X25519Identity, yazılımsal bir age X25519 şifreleme kimliğidir (SPEC §3.3.1
// yazılım fallback'i / §3.3.3 makine kimlikleri / §3.3.2 backup). Donanım (SE/
// YubiKey) yolu plugin ile yüklenir (aşağıdaki LoadPlugin* — CI'da çalışmaz).
type X25519Identity struct {
	id *age.X25519Identity
}

// GenerateX25519Identity, yeni bir yazılımsal X25519 şifreleme kimliği üretir.
func GenerateX25519Identity() (*X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("cryptoid.GenerateX25519Identity: %w", err)
	}
	return &X25519Identity{id: id}, nil
}

// NewX25519IdentityFromScalar, 32 baytlık gizli skalardan deterministik bir
// kimlik üretir (test vektörleri + ceremony reprodüksiyonu için).
func NewX25519IdentityFromScalar(scalar []byte) (*X25519Identity, error) {
	if len(scalar) != x25519PointSize {
		return nil, fmt.Errorf("cryptoid.NewX25519IdentityFromScalar: scalar must be %d bytes", x25519PointSize)
	}
	// age'in parser'ından geçir ki gizli anahtar da age uyumlu olsun (parser
	// skaları clamp'ler ve public key'i türetir). Büyük-harf HRP → bech32Encode
	// büyük-harf "AGE-SECRET-KEY-1..." döner.
	sk, err := bech32Encode("AGE-SECRET-KEY-", scalar)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.NewX25519IdentityFromScalar: %w", err)
	}
	id, err := age.ParseX25519Identity(sk)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.NewX25519IdentityFromScalar: %w", err)
	}
	return &X25519Identity{id: id}, nil
}

// ParseX25519Identity, "AGE-SECRET-KEY-1..." bech32 gizli anahtarını çözer.
func ParseX25519Identity(s string) (*X25519Identity, error) {
	id, err := age.ParseX25519Identity(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("cryptoid.ParseX25519Identity: %w", err)
	}
	return &X25519Identity{id: id}, nil
}

// Recipient, bu kimliğe karşılık gelen X25519Recipient'ı döner.
func (i *X25519Identity) Recipient() *X25519Recipient {
	s := i.id.Recipient().String()
	// Kendi ürettiğimiz string; parse tekrar çözer ve noktayı doldurur.
	r, err := ParseX25519Recipient(s)
	if err != nil {
		// Kendi kimliğimizin recipient'ı her zaman geçerlidir; olmazsa bug.
		panic("cryptoid: internal error: own recipient unparseable: " + err.Error())
	}
	return r
}

// Fingerprint, kimliğin §3.7 parmak izi (recipient üzerinden).
func (i *X25519Identity) Fingerprint() string { return i.Recipient().Fingerprint() }

// AgeIdentity, read/unwrap yolunda age.Decrypt için age.Identity döner.
func (i *X25519Identity) AgeIdentity() age.Identity { return i.id }

// String, canonical "AGE-SECRET-KEY-1..." gizli anahtar string'i döner.
// DİKKAT: gizli materyal; loglanmamalı/diske yazılmamalı (SPEC §3.3).
func (i *X25519Identity) String() string { return i.id.String() }

// --- Donanım plugin kimlikleri (hardware path — CI'da ÇALIŞMAZ) ---
//
// Plugin alıcı/kimlikleri (age-plugin-se / age-plugin-yubikey) age'in plugin
// mekanizmasına DELEGE edilir; elle kurulmaz (SPEC §3.1/§3.3.1). Gerçek
// wrap/unwrap plugin binary'sini + donanımı gerektirir; bu yazılım çekirdeği
// yalnızca YÜKLEME arayüzünü sağlar. Parmak izi ise string'den offline
// hesaplanır (aşağıdaki PluginRecipientFingerprint), binary gerektirmez.

// LoadPluginRecipient, bir plugin alıcı string'ini (age1se1.../age1yubikey1...)
// age'in plugin mekanizmasıyla yükler. Plugin binary'si yoksa hata döner
// (donanım yolu — CI'da beklenen başarısızlık).
func LoadPluginRecipient(s string, ui *plugin.ClientUI) (*plugin.Recipient, error) {
	r, err := plugin.NewRecipient(strings.TrimSpace(s), ui)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.LoadPluginRecipient (hardware path): %w", err)
	}
	return r, nil
}

// LoadPluginIdentity, bir plugin kimlik string'ini age'in plugin mekanizmasıyla
// yükler (donanım yolu — CI'da beklenen başarısızlık).
func LoadPluginIdentity(s string, ui *plugin.ClientUI) (*plugin.Identity, error) {
	id, err := plugin.NewIdentity(strings.TrimSpace(s), ui)
	if err != nil {
		return nil, fmt.Errorf("cryptoid.LoadPluginIdentity (hardware path): %w", err)
	}
	return id, nil
}

// PluginRecipientFingerprint, herhangi bir alıcı string'inin (native VEYA
// plugin) §3.7 parmak izini binary GEREKMEDEN hesaplar — parmak izi girdisi
// alıcı string'inin kendisidir.
func PluginRecipientFingerprint(recipientString string) string {
	return FingerprintRecipient(strings.TrimSpace(recipientString))
}

// randRead, test edilebilirlik için crypto/rand sarmalayıcısı.
func randRead(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}
