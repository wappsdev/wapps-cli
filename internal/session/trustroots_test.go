package session

// trustroots_test.go, plan §9.5'in GO YARISINI pinliyor.
//
// Ölçüm: bu tarafta üretim kodunda RootCAs HİÇ set edilmiyor (auth.go yalnızca
// MinVersion'a dokunuyor), yani kök sertifika kümesi PLATFORMUN — macOS'ta
// Security.framework, Linux'ta sistem CA demeti ya da SSL_CERT_FILE.
//
// §9.5'in KARARI VERİLDİ (şık C) ve BU DOSYANIN İDDİALARI DEĞİŞMEDİ: karar
// yalnızca Rust ikilisini bağlıyor. Orada gömülü webpki-roots taban olarak
// kalıyor ve SSL_CERT_FILE/SSL_CERT_DIR ayarlıysa üstüne ekleniyor. Go üretim
// kodu bu dilimde HİÇ değişmedi — sahada kurulu ikililer var — yani Go hâlâ
// kök kümesini platforma devrediyor ve aşağıdaki iki test bunu ölçmeye devam
// ediyor.
//
// Bu test bir DOĞRULUK İDDİA ETMİYOR. "Doğru davranıyor" demiyor; "bugün böyle
// davranıyor, değişirse haberin olsun" diyor. Birisi Go tarafına da sabit bir
// kök kümesi koyarsa kırılır — ve kırılması, sahadaki ikililerin güven
// yüzeyinin sessizce değişmediğinin kanıtıdır.
//
// KARARIN BU TARAFA DÜŞEN DÜRÜST YARISI — davranış testi değil ama burada
// yazılı olması gerekiyor, çünkü ayrışmanın öteki ucu bu dosya:
//
//	Linux'ta crypto/x509 (root_unix.go) SSL_CERT_FILE ve SSL_CERT_DIR'i okuyor;
//	Rust artık okuyor, yani kabul/ret ekseninde parite kazanıldı. §9.5'in
//	anlattığı, TLS denetleyen proxy arkasındaki CI runner Linux'ta.
//
//	macOS'ta parite KAZANILMADI, ayrışma TERS ÇEVRİLDİ. root_unix.go'nun build
//	etiketi darwin'i dışlıyor, yani Go orada bu iki değişkeni HİÇ okumuyor.
//	Önce katı olan taraf Rust'tı; şimdi darwin'de katı olan taraf GO. Ayrışma
//	kapanmadı, yönü değişti.
//
//	Linux'ta bile parite tam değil: Go env değişkenini görünce sistem demetinin
//	YERİNE koyuyor (loadSystemRoots: files = []string{f}), Rust ise gömülü
//	tabana EKLİYOR. Rust'ın kabul yüzeyi daha geniş kalıyor ve bu, şık C'nin
//	tanımı — kaza değil.
//
// Ayrışmanın davranış tarafı wapps-cli/rust/crates/cli/tests/tlstrust.rs'te
// iki ikili birden TLS'li sahte bir gate'e karşı koşularak ölçülüyor; yukarıdaki
// üç paragrafın her biri orada bir assert'e karşılık geliyor.

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
