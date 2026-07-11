// Package witness, escrow snapshot'ının BAĞIMSIZ doğrulayıcısıdır (SPEC §9.3) —
// Cloudflare'in KONTROL ETMEDİĞİ bir makinede (ci.meapps.dev VM) saatlik çalışır,
// B2 escrow bucket'ını READ-ONLY key ile çeker, §9.3.2 kontrollerini yapar, tanık
// head'i NON-object-locked NON-Cloudflare witness bucket'ına yayınlar ve
// staleness/başarısızlıkta Discord'a alert eder. Aynı çekirdek `wapps dr verify`
// (§9.5) tarafından da yerel/hava-boşluklu olarak çalıştırılır.
//
// Bu dosya: S3-uyumlu okuyucu/yazıcı soyutlaması (READ-ONLY Reader = escrow B2;
// Writer = witness B2) + bellek-içi FAKE implementasyonlar (test/DR) + gerçek
// SigV4 HTTP implementasyonu (canlı B2). B2/VM canlı deploy DEFERRED (task).
package witness

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrNotExist, bir objenin okuyucuda bulunmadığını işaret eder.
var ErrNotExist = errors.New("witness: object not found")

// Reader, escrow bucket'ının READ-ONLY görünümüdür (§9.3.1 read-only key).
type Reader interface {
	// Get, bir objenin baytlarını döner; yoksa ErrNotExist.
	Get(ctx context.Context, key string) ([]byte, error)
	// List, verilen önekle başlayan tüm anahtarları döner.
	List(ctx context.Context, prefix string) ([]string, error)
}

// Writer, witness bucket'ına yazan (NON-object-locked) arayüzdür (§9.3.3).
type Writer interface {
	Put(ctx context.Context, key string, body []byte, contentType string) error
}

// --- Obje anahtar düzeni (Worker escrow.ts ile BİREBİR mirror) --------------

func keyBlob(project, sha string) string { return "secrets/" + project + "/blobs/" + sha }
func keyManifest(project string, e uint64) string {
	return fmt.Sprintf("secrets/%s/manifests/%d.json", project, e)
}
func keyPointerEvent(project string, e uint64) string {
	return fmt.Sprintf("pointer-events/%s/%d.json", project, e)
}
func keyAuditSegment(seq int) string        { return fmt.Sprintf("audit/segments/%d.json", seq) }
func keyTrustManifest(e uint64) string      { return fmt.Sprintf("trust/manifests/%d.json", e) }
func prefixBlobs(project string) string     { return "secrets/" + project + "/blobs/" }
func prefixManifests(project string) string { return "secrets/" + project + "/manifests/" }

// --- Bellek-içi FAKE (test + DR snapshot) -----------------------------------

// MemStore, hem Reader hem Writer'ı uygulayan bellek-içi bir escrow taklidir
// (test fixture'ları + hava-boşluklu snapshot kopyası). Eşzamanlı değil.
type MemStore struct {
	Objects map[string][]byte
}

// NewMemStore, boş bir bellek-içi store kurar.
func NewMemStore() *MemStore { return &MemStore{Objects: map[string][]byte{}} }

// Get uygular Reader.
func (m *MemStore) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := m.Objects[key]
	if !ok {
		return nil, fmt.Errorf("%s: %w", key, ErrNotExist)
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// List uygular Reader (sıralı — deterministik).
func (m *MemStore) List(_ context.Context, prefix string) ([]string, error) {
	var out []string
	for k := range m.Objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Put uygular Writer.
func (m *MemStore) Put(_ context.Context, key string, body []byte, _ string) error {
	cp := make([]byte, len(body))
	copy(cp, body)
	m.Objects[key] = cp
	return nil
}

// --- Filesystem Reader (hava-boşluklu snapshot kopyası, §9.5.1) -------------

// DirReader, yerel bir dizini escrow Reader'ı olarak sunar (anahtar = dizine
// göre göreli yol). `wapps dr verify --snapshot <dir>` bunu kullanır: Cloudflare
// tamamen erişilemezken bir snapshot'a karşı doğrulama (SPEC §9.5.1).
type DirReader struct{ Root string }

// Get uygular Reader.
func (d DirReader) Get(_ context.Context, key string) ([]byte, error) {
	p := filepath.Join(d.Root, filepath.FromSlash(key))
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s: %w", key, ErrNotExist)
		}
		return nil, fmt.Errorf("witness.DirReader.Get %s: %w", key, err)
	}
	return b, nil
}

// List uygular Reader (dizini yürüyerek prefix'e uyan anahtarları döner).
func (d DirReader) List(_ context.Context, prefix string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(d.Root, func(path string, entry fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if entry.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(d.Root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, prefix) {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("witness.DirReader.List: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// --- Gerçek SigV4 HTTP implementasyonu (canlı B2) ---------------------------

// S3Config, canlı B2 S3-uyumlu erişim yapılandırmasıdır.
type S3Config struct {
	Endpoint  string // ör. "s3.us-west-004.backblazeb2.com" (NON-Cloudflare)
	Region    string
	Bucket    string
	KeyID     string
	SecretKey string
	Client    *http.Client
	Now       func() time.Time
}

// S3Store, S3Config ile Reader/Writer'ı SigV4-imzalı HTTP üzerinden uygular.
// dr verify (READ-ONLY key) ve witness publish (witness bucket write key) buradan
// geçer. Canlı B2 bucket + VM cron deploy DEFERRED — bu kod fonksiyoneldir ama
// canlı çalıştırma insan-eliyle (task).
type S3Store struct{ cfg S3Config }

// NewS3Store kurar.
func NewS3Store(cfg S3Config) *S3Store {
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &S3Store{cfg: cfg}
}

func (s *S3Store) Get(ctx context.Context, key string) ([]byte, error) {
	req, err := s.signed(ctx, http.MethodGet, key, nil, "")
	if err != nil {
		return nil, err
	}
	res, err := s.cfg.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("witness.S3Store.Get: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", key, ErrNotExist)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("witness.S3Store.Get %s: HTTP %d", key, res.StatusCode)
	}
	return body, nil
}

// listObjectsV2Result, ListObjectsV2 XML yanıt kısmı.
type listObjectsV2Result struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	IsTruncated           bool   `xml:"IsTruncated"`
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("prefix", prefix)
		if token != "" {
			q.Set("continuation-token", token)
		}
		req, err := s.signedQuery(ctx, http.MethodGet, "", q, nil, "")
		if err != nil {
			return nil, err
		}
		res, err := s.cfg.Client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("witness.S3Store.List: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("witness.S3Store.List: HTTP %d", res.StatusCode)
		}
		var r listObjectsV2Result
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("witness.S3Store.List: %w", err)
		}
		for _, c := range r.Contents {
			out = append(out, c.Key)
		}
		if !r.IsTruncated || r.NextContinuationToken == "" {
			break
		}
		token = r.NextContinuationToken
	}
	sort.Strings(out)
	return out, nil
}

func (s *S3Store) Put(ctx context.Context, key string, body []byte, contentType string) error {
	req, err := s.signed(ctx, http.MethodPut, key, body, contentType)
	if err != nil {
		return err
	}
	res, err := s.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("witness.S3Store.Put: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("witness.S3Store.Put %s: HTTP %d", key, res.StatusCode)
	}
	return nil
}

func (s *S3Store) signed(ctx context.Context, method, key string, body []byte, contentType string) (*http.Request, error) {
	return s.signedQuery(ctx, method, key, nil, body, contentType)
}

// signedQuery, SigV4-imzalı bir S3 isteği kurar (path-style, tek-chunk).
func (s *S3Store) signedQuery(ctx context.Context, method, key string, query url.Values, body []byte, contentType string) (*http.Request, error) {
	now := s.cfg.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	host := s.cfg.Endpoint
	canonicalURI := "/" + s.cfg.Bucket
	if key != "" {
		canonicalURI += "/" + s3URIEncode(key, false)
	}
	payloadHash := hexSHA256(body)

	canonicalQuery := ""
	if query != nil {
		keys := make([]string, 0, len(query))
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, s3URIEncode(k, true)+"="+s3URIEncode(query.Get(k), true))
		}
		canonicalQuery = strings.Join(parts, "&")
	}

	canonicalHeaders := "host:" + host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := dateStamp + "/" + s.cfg.Region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256([]byte(canonicalRequest))}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+s.cfg.SecretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.cfg.Region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	authorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", s.cfg.KeyID, scope, signedHeaders, signature)

	u := "https://" + host + canonicalURI
	if canonicalQuery != "" {
		u += "?" + canonicalQuery
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, fmt.Errorf("witness: build request: %w", err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if contentType != "" {
		req.Header.Set("content-type", contentType)
	}
	return req, nil
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// s3URIEncode, AWS SigV4 URI kodlamasıdır ('/' path'te korunur, query'de kodlanır).
func s3URIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
