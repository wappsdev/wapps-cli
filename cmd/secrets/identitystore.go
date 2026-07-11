package secrets

// identitystore.go, enroll'un ürettiği YAZILIM (CI/test) kimliğini yerel diske
// (~/.config/wapps/identity.json, 0600) kalıcılaştırır ve store yolunun çözme
// (§7.1: CLI çözer) + commit imzası için geri yükler. DONANIM (SE/YubiKey)
// kimlikleri BURAYA yazılmaz — gizli materyal güvenli öğeyi terk etmez; bu depo
// yalnızca yazılım fallback'i içindir (SPEC §8.1.1). Backup gizli yarısı ASLA
// persist edilmez (yalnızca enroll çıktısında SecretOnce ile bir kez gösterilir,
// §8.3); yalnızca PUBLIC backup alıcısı (opsiyonel) kaydedilir.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/lifecycle"
)

// identitySchema, yerel kimlik dosyasının şema tanımlayıcısı.
const identitySchema = "wapps-identity/v1"

// identityFileName, yerel kimlik deposunun dosya adı (~/.config/wapps/ altında).
const identityFileName = "identity.json"

// persistedSigningKey, bir YAZILIM imzalama anahtarının gizli materyalinin kalıcı
// formudur: Ed25519 → 32B seed; P-256 → 32B gizli skalar (D), base64 (std).
type persistedSigningKey struct {
	Alg  string `json:"alg"`  // ed25519 | ecdsa-p256-sha256
	Priv string `json:"priv"` // base64: seed(32) | scalar(32)
}

// persistedIdentity, yerel yazılım kimliğinin diske yazılan şeklidir. enc_secret
// device X25519 gizli anahtarıdır (CLI çözme yapar, §7.1); writer daily(insan)/
// automation(makine) imzalama anahtarıdır (store commit imzası). backup_recipient
// yalnızca PUBLIC alıcıdır (gizli yarı asla yazılmaz).
type persistedIdentity struct {
	Schema          string               `json:"schema"`
	ID              string               `json:"id"`
	Type            string               `json:"type"`
	Media           string               `json:"media"`
	EncSecret       string               `json:"enc_secret"`
	Writer          persistedSigningKey  `json:"writer"`
	Admin           *persistedSigningKey `json:"admin,omitempty"`
	BackupRecipient string               `json:"backup_recipient,omitempty"`
}

// identityPath, kimlik deposunun tam yolunu döner (XDG onurlandırılır).
func identityPath() (string, error) {
	dir, err := wappsHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, identityFileName), nil
}

// marshalSigningKey, bir YAZILIM imzalama anahtarını kalıcı forma çevirir. Donanım
// (plugin) anahtarları gizli materyali ifşa etmez → hata (yazılım yolu gerekir).
func marshalSigningKey(k cryptoid.SigningKey) (persistedSigningKey, error) {
	switch kk := k.(type) {
	case *cryptoid.Ed25519SigningKey:
		return persistedSigningKey{Alg: cryptoid.AlgEd25519, Priv: base64.StdEncoding.EncodeToString(kk.PrivateSeed())}, nil
	case *cryptoid.ECDSAP256SigningKey:
		return persistedSigningKey{Alg: cryptoid.AlgECDSAP256SHA256, Priv: base64.StdEncoding.EncodeToString(kk.PrivateScalar())}, nil
	default:
		return persistedSigningKey{}, fmt.Errorf("cannot persist a hardware/non-software signing key")
	}
}

// toSigningKey, kalıcı formu bir cryptoid.SigningKey'e geri kurar.
func (p persistedSigningKey) toSigningKey() (cryptoid.SigningKey, error) {
	raw, err := base64.StdEncoding.DecodeString(p.Priv)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	switch p.Alg {
	case cryptoid.AlgEd25519:
		return cryptoid.NewEd25519FromSeed(raw)
	case cryptoid.AlgECDSAP256SHA256:
		return cryptoid.NewECDSAP256FromScalar(raw)
	default:
		return nil, fmt.Errorf("unknown signing alg %q", p.Alg)
	}
}

// saveEnrolledIdentity, bir enroll sonucundan YAZILIM kimliğini 0600 kimlik deposuna
// yazar ve yazılan yolu döner. EncKey donanım-resident ise (Identity()==nil) hata —
// yalnızca yazılım kimlikleri kalıcılaştırılabilir (donanımda gizli HW'de kalır).
// Gizli materyal (enc secret + signing priv) asla loglanmaz; backup gizli yarısı
// ASLA yazılmaz (yalnızca public alıcı).
func saveEnrolledIdentity(res *lifecycle.EnrollResult) (string, error) {
	encID := res.EncKey.Identity()
	if encID == nil {
		return "", clierr.New(clierr.Internal,
			"enroll produced a hardware enc identity; the local software identity store only persists software keys")
	}
	writer, err := marshalSigningKey(res.Daily)
	if err != nil {
		return "", clierr.Wrapf(clierr.Internal, err, "persist writer key")
	}
	pid := persistedIdentity{
		Schema:    identitySchema,
		ID:        res.Identity.ID,
		Type:      res.Identity.Type,
		Media:     res.EncKey.Media(),
		EncSecret: encID.String(),
		Writer:    writer,
	}
	if res.Admin != nil {
		adm, aerr := marshalSigningKey(res.Admin)
		if aerr != nil {
			return "", clierr.Wrapf(clierr.Internal, aerr, "persist admin key")
		}
		pid.Admin = &adm
	}
	if res.Backup != nil {
		pid.BackupRecipient = res.Backup.Recipient().String()
	}
	path, err := identityPath()
	if err != nil {
		return "", clierr.Wrapf(clierr.Internal, err, "resolve identity path")
	}
	if err := writeIdentityFile(path, pid); err != nil {
		return "", err
	}
	return path, nil
}

// writeIdentityFile, kimlik deposunu umask-BAĞIMSIZ 0600 olarak atomik yazar
// (temp yaz → chmod → rename). Böylece gizli enc/imzalama materyali grup/diğer'e
// asla okunur olmaz — umask ne olursa olsun.
func writeIdentityFile(path string, pid persistedIdentity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "create config dir")
	}
	data, err := json.MarshalIndent(pid, "", "  ")
	if err != nil {
		return clierr.Wrapf(clierr.Internal, err, "marshal identity")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return clierr.Wrapf(clierr.Internal, err, "write identity")
	}
	// umask, WriteFile mode'unu kısıtlamış olabilir → açıkça 0600'e zorla.
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return clierr.Wrapf(clierr.Internal, err, "chmod identity")
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return clierr.Wrapf(clierr.Internal, err, "rename identity")
	}
	return nil
}

// loadPersistedIdentity, kimlik deposunu yükler. Dosya YOKSA (nil, nil) döner —
// çağıran bunu eylemli IDENTITY_MISSING'e çevirir. Dosya VARSA ama 0600'den gevşek
// izinli / bozuk / yanlış şema / boş ise SESSİZCE "absent" muamelesi yapılMAZ; net
// bir clierr.IdentityMissing döner (re-enroll ile düzeltilir).
func loadPersistedIdentity() (*persistedIdentity, error) {
	path, err := identityPath()
	if err != nil {
		return nil, clierr.Wrapf(clierr.IdentityMissing, err, "resolve identity path")
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil // gerçekten yok
	}
	if err != nil {
		return nil, clierr.Wrapf(clierr.IdentityMissing, err, "stat identity file")
	}
	// 0600 kontrolü: grup/diğer bitleri set ise reddet (gizli materyal korunmalı).
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, clierr.Newf(clierr.IdentityMissing,
			"identity file %s has insecure permissions %#o (must be 0600); fix perms or re-run wapps secrets enroll", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, clierr.Wrapf(clierr.IdentityMissing, err, "read identity file")
	}
	var pid persistedIdentity
	if err := json.Unmarshal(data, &pid); err != nil {
		return nil, clierr.Wrapf(clierr.IdentityMissing, err, "identity file is corrupt")
	}
	if pid.Schema != identitySchema {
		return nil, clierr.Newf(clierr.IdentityMissing, "identity file has unsupported schema %q", pid.Schema)
	}
	if pid.EncSecret == "" {
		return nil, clierr.New(clierr.IdentityMissing, "identity file has no encryption key")
	}
	return &pid, nil
}
