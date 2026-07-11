// Package session, `wapps login`ın CF Access app-token oturum önbelleğidir
// (SPEC §7.2): token gate-host başına ~/.config/wapps/session/<host>.json
// dosyasında 0600 saklanır; ASLA loglanmaz, ASLA başka yere yazılmaz.
//
// Yükleme sırası (Load): (1) WAPPS_SESSION_TOKEN env (out-of-band — CI/test bir
// bearer'ı canlı tarayıcı login'i olmadan sunar; opsiyonel WAPPS_SESSION_EXPIRES
// unix), (2) session/<host>.json. İkisi de yoksa ok=false → çağıran
// SESSION_EXPIRED üretir (agent) veya login'e yönlendirir (TTY).
package session

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// State, çözülmüş bir oturumdur.
type State struct {
	// Token, CF Access app token'ı (CF_Authorization JWT). Değeri ASLA yazdırma.
	Token string `json:"token"`
	// ExpiresAt, unix saniye; 0 → expiry bilinmiyor (out-of-band env token) →
	// dolmaz sayılır (gate yine de kenarda doğrular).
	ExpiresAt int64 `json:"expires_at"`
}

// Expired, oturumun (bilinen expiry'ye göre) süresinin dolduğunu döner.
func (s State) Expired(now time.Time) bool {
	return s.ExpiresAt != 0 && s.ExpiresAt <= now.Unix()
}

// TTL, kalan süreyi döner (expiry bilinmiyorsa 0).
func (s State) TTL(now time.Time) time.Duration {
	if s.ExpiresAt == 0 {
		return 0
	}
	return time.Duration(s.ExpiresAt-now.Unix()) * time.Second
}

// Dir, oturum dizinini döner: ~/.config/wapps/session (XDG onurlandırılır).
func Dir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps", "session"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("session: resolve home: %w", err)
	}
	return filepath.Join(home, ".config", "wapps", "session"), nil
}

// hostFile, gate host'unu güvenli bir dosya adına indirger (yol ayrıştırma
// karakterleri temizlenir; <host>.json).
func hostFile(host string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, host)
	return safe + ".json"
}

// Path, verilen gate host'un oturum dosya yolunu döner.
func Path(host string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, hostFile(host)), nil
}

// Load, oturumu yükler (env → dosya). ok=false → hiç oturum yok.
func Load(host string) (State, bool) {
	if tok := os.Getenv("WAPPS_SESSION_TOKEN"); tok != "" {
		exp := int64(0)
		if e := os.Getenv("WAPPS_SESSION_EXPIRES"); e != "" {
			if n, perr := strconv.ParseInt(e, 10, 64); perr == nil {
				exp = n
			}
		}
		return State{Token: tok, ExpiresAt: exp}, true
	}
	path, err := Path(host)
	if err != nil {
		return State{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, false
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil || s.Token == "" {
		return State{}, false
	}
	return s, true
}

// Save, oturumu 0600 (dizin 0700) yazar — atomik (tmp + rename).
func Save(host string, s State) error {
	path, err := Path(host)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("session: mkdir: %w", err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("session: encode: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("session: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("session: rename: %w", err)
	}
	return nil
}

// Claims, bir JWT payload'ından İMZA DOĞRULAMADAN okunan bilgilendirici
// alanlardır (yalnızca yerel önbellek/expiry/görüntüleme için — yetkilendirme
// HER ZAMAN kenarda/Worker'da yapılır).
type Claims struct {
	Email string `json:"email"`
	Sub   string `json:"sub"`
	Exp   int64  `json:"exp"`
	Iss   string `json:"iss"`
}

// ParseClaims, bir JWT'nin payload bölümünü çözer (imza DOĞRULANMAZ — yalnızca
// exp/email görüntüleme). Bozuk token → hata.
func ParseClaims(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("session: token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("session: token payload not base64url: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("session: token payload not JSON: %w", err)
	}
	return c, nil
}
