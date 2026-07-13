package session

// mtls_test.go, P1.9 mTLS client-cert desteğini doğrular: WAPPS_MTLS_CERT +
// WAPPS_MTLS_KEY doluyken HTTPClient() taşıması client-cert SUNAR — client-cert
// İSTEYEN (RequireAndVerifyClientCert) bir httptest TLS sunucusuna karşı uçtan
// uca; yanlış-konfig fail-closed SERVICE_MISCONFIGURED.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// genClientCertFiles, self-signed bir client sertifikası üretir, PEM çiftini
// geçici dosyalara yazar ve sunucunun ClientCAs havuzu için x509 halini döner.
func genClientCertFiles(t *testing.T) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wapps-ci-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed: kendi doğrulama kökü
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath, cert
}

// TestHTTPClient_NoEnvIsDefault, mTLS env'i yokken varsayılan istemciyi doğrular.
func TestHTTPClient_NoEnvIsDefault(t *testing.T) {
	t.Setenv(envMTLSCert, "")
	t.Setenv(envMTLSKey, "")
	c, err := HTTPClient()
	if err != nil {
		t.Fatalf("no env: unexpected error %v", err)
	}
	if c != http.DefaultClient {
		t.Fatalf("no env: want http.DefaultClient, got %#v", c)
	}
}

// TestHTTPClient_HalfPairFailsClosed, çiftin yalnızca biri doluyken
// SERVICE_MISCONFIGURED beklendiğini doğrular (cert'siz sessiz devam YOK).
func TestHTTPClient_HalfPairFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		cert, key string
	}{
		{"only cert", "/tmp/x.crt", ""},
		{"only key", "", "/tmp/x.key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envMTLSCert, tc.cert)
			t.Setenv(envMTLSKey, tc.key)
			if _, err := HTTPClient(); !clierr.Is(err, clierr.ServiceMisconfig) {
				t.Fatalf("half pair: want SERVICE_MISCONFIGURED, got %v", err)
			}
		})
	}
}

// TestHTTPClient_BadFilesFailClosed, yüklenemeyen PEM çiftinin
// SERVICE_MISCONFIGURED ile reddedildiğini doğrular.
func TestHTTPClient_BadFilesFailClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envMTLSCert, filepath.Join(dir, "missing.crt"))
	t.Setenv(envMTLSKey, filepath.Join(dir, "missing.key"))
	if _, err := HTTPClient(); !clierr.Is(err, clierr.ServiceMisconfig) {
		t.Fatalf("bad files: want SERVICE_MISCONFIGURED, got %v", err)
	}
}

// TestHTTPClient_PresentsClientCert, ana P1.9 testi: client-cert İSTEYEN bir TLS
// sunucusuna karşı env'den kurulan istemci el sıkışmayı geçer ve sunucu peer
// sertifikasını görür; cert'siz kontrol istemcisi ise reddedilir.
func TestHTTPClient_PresentsClientCert(t *testing.T) {
	certPath, keyPath, clientCert := genClientCertFiles(t)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCert)
	sawPeerCN := ""
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			sawPeerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientPool,
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// httptest'in self-signed sunucu sertifikasına güven (yalnızca test tarafı).
	serverPool := x509.NewCertPool()
	serverPool.AddCert(srv.Certificate())

	t.Setenv(envMTLSCert, certPath)
	t.Setenv(envMTLSKey, keyPath)
	c, err := HTTPClient()
	if err != nil {
		t.Fatalf("HTTPClient: %v", err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport: want *http.Transport, got %T", c.Transport)
	}
	if len(tr.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("transport: want 1 client certificate, got %d", len(tr.TLSClientConfig.Certificates))
	}
	tr.TLSClientConfig.RootCAs = serverPool

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mTLS request: want 200, got %d", resp.StatusCode)
	}
	if sawPeerCN != "wapps-ci-client" {
		t.Fatalf("server peer cert: want CN wapps-ci-client, got %q", sawPeerCN)
	}

	// Kontrol: client-cert'siz istemci aynı sunucuda el sıkışmada reddedilir.
	bare := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: serverPool, MinVersion: tls.VersionTLS12},
	}}
	if resp, err := bare.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("bare client: want handshake rejection without client cert, got success")
	}
}
