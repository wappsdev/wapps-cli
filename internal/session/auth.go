package session

// auth.go, WorkerStore isteklerine kimlik header'larını iliştiren üretim
// enjektörüdür (SPEC §7.2 adım 4 + §5 service-token yolu):
//
//  1. CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET env → CF-Access-Client-Id /
//     CF-Access-Client-Secret header'ları (CI service token; login verb'i gerekmez).
//     WAPPS_MACHINE_TOKEN de doluysa Authorization: Bearer eklenir (opsiyonel
//     minted-token confinement katmanı, §5.3).
//  2. aksi halde oturum (WAPPS_SESSION_TOKEN env veya session/<host>.json) →
//     cf-access-token header (Access kenarda doğrular ve Worker'a
//     Cf-Access-Jwt-Assertion olarak iletir).
//  3. hiçbiri yoksa/oturum dolmuşsa SESSION_EXPIRED — istek ağ'a HİÇ çıkmaz.

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// DefaultGateURL, OD-4 varsayılan gate hostname'idir.
const DefaultGateURL = "https://secrets.meapps.dev"

// GateURL, secrets-gate kökünü döner: WAPPS_SECRETS_GATE env veya varsayılan.
func GateURL() string {
	if v := strings.TrimSpace(os.Getenv("WAPPS_SECRETS_GATE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultGateURL
}

// GateHost, GateURL'in host bölümünü döner (oturum dosyası anahtarı).
func GateHost() string {
	u, err := url.Parse(GateURL())
	if err != nil || u.Host == "" {
		return "secrets.meapps.dev"
	}
	return u.Host
}

// HeaderAccessToken, CF Access app-token header adıdır (cloudflared paritesi).
const HeaderAccessToken = "cf-access-token"

// Auth, store.Config.Auth için üretim enjektörünü döner.
func Auth() func(*http.Request) error {
	host := GateHost()
	return func(req *http.Request) error {
		// 1) CI service-token yolu (§7.2 sonu): login verb'i gerekmez.
		id, secret := os.Getenv("CF_ACCESS_CLIENT_ID"), os.Getenv("CF_ACCESS_CLIENT_SECRET")
		if id != "" && secret != "" {
			req.Header.Set("CF-Access-Client-Id", id)
			req.Header.Set("CF-Access-Client-Secret", secret)
			if mt := os.Getenv("WAPPS_MACHINE_TOKEN"); mt != "" {
				req.Header.Set("Authorization", "Bearer "+mt)
			}
			return nil
		}
		// 2) İnsan oturumu.
		s, ok := Load(host)
		if !ok || s.Expired(time.Now()) {
			return clierr.New(clierr.SessionExpired, "no valid CF Access session for the secrets gate")
		}
		req.Header.Set(HeaderAccessToken, s.Token)
		return nil
	}
}
