package session

// trustroots_test.go, plan §9.5'in GO YARISINI pinliyor.
//
// Ölçüm: bu tarafta üretim kodunda RootCAs HİÇ set edilmiyor (auth.go yalnızca
// MinVersion'a dokunuyor), yani kök sertifika kümesi PLATFORMUN — macOS'ta
// Security.framework, Linux'ta sistem CA demeti ya da SSL_CERT_FILE. Rust
// ikilisi ise webpki-roots'u İKİLİYE GÖMÜLÜ taşıyor (ureq'in varsayılan `tls`
// özelliğiyle bedava geldi, kimse seçmedi).
//
// Bu test bir DOĞRULUK İDDİA ETMİYOR: hangi tarafın doğru olduğu sahibinin
// kararı. Yalnızca bugünkü hâli kaydediyor. Karar "gömülü kökler" yönünde
// verilir ve Go tarafına da sabit bir kök kümesi konursa bu test kırılır — ve
// kırılması, sahadaki ikililerin güven yüzeyinin sessizce değişmediğinin
// kanıtıdır.
//
// Ayrışmanın davranış tarafı wapps-cli/rust/crates/cli/tests/tlstrust.rs'te
// iki ikili birden TLS'li sahte bir gate'e karşı koşularak ölçülüyor.

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// rootCAsOf, bir istemcinin taşımasındaki RootCAs'ı döner. Taşıma
// http.DefaultTransport ise onun TLS ayarı okunur.
func rootCAsOf(t *testing.T, c *http.Client) *tls.Config {
	t.Helper()
	rt := c.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("transport: want *http.Transport, got %T", rt)
	}
	return tr.TLSClientConfig
}

// TestProductionTransportDelegatesRootsToThePlatform, mTLS env'i YOKKEN üretim
// istemcisinin kök kümesini kendisi taşımadığını doğrular.
func TestProductionTransportDelegatesRootsToThePlatform(t *testing.T) {
	t.Setenv(envMTLSCert, "")
	t.Setenv(envMTLSKey, "")
	c, err := HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient: %v", err)
	}
	cfg := rootCAsOf(t, c)
	if cfg != nil && cfg.RootCAs != nil {
		t.Fatal("default path: RootCAs is set — Go no longer defers to the platform trust store")
	}
}

// TestMTLSTransportStillDelegatesRootsToThePlatform, client-cert yolunun
// SUNUCU doğrulamasını değiştirmediğini doğrular: eklenen tek şey
// Certificates; RootCAs yine platformun.
func TestMTLSTransportStillDelegatesRootsToThePlatform(t *testing.T) {
	certPath, keyPath, _ := genClientCertFiles(t)
	t.Setenv(envMTLSCert, certPath)
	t.Setenv(envMTLSKey, keyPath)
	c, err := HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient: %v", err)
	}
	cfg := rootCAsOf(t, c)
	if cfg == nil {
		t.Fatal("mTLS path: TLSClientConfig is nil — client certificate cannot be presented")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("mTLS path: want 1 client certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs != nil {
		t.Fatal("mTLS path: RootCAs is set — the client cert path changed server verification too")
	}
}
