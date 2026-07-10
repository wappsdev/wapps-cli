package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/wappsdev/wapps-cli/internal/intent"
)

// SchemaWitnessHead, per-proje tanık head dokümanının şemasıdır (SPEC §9.3.3).
const SchemaWitnessHead = "wapps.witness-head.v1"

// SchemaTrustHead, trust head dokümanı şeması.
const SchemaTrustHead = "wapps.witness-trust-head.v1"

// StalenessLimit, tanık head'inin bayat sayıldığı eşik (§9.3.5b / §6.7): 2 saat.
const StalenessLimit = 2 * time.Hour

// WitnessHead, yayınlanan per-proje tanık head dokümanıdır (§9.3.3). Otoritatif
// alanlar epoch + manifestSha256; tüketiciler ek alanları tolere ETMELİ.
type WitnessHead struct {
	Schema         string `json:"schema"`
	Project        string `json:"project"`
	Epoch          uint64 `json:"epoch"`
	ManifestSha256 string `json:"manifestSha256"`
	VerifiedAt     string `json:"verified_at"`
	Verifier       string `json:"verifier"`
}

// IsStale, tanık head'inin now'a göre StalenessLimit'i aşıp aşmadığını döner.
func (h WitnessHead) IsStale(now time.Time) bool {
	t, err := time.Parse(time.RFC3339, h.VerifiedAt)
	if err != nil {
		return true // parse edilemeyen zaman = bayat say (fail-closed)
	}
	return now.Sub(t) > StalenessLimit
}

// witnessTrustHeadDoc, yayınlanan trust head dokümanıdır (§9.3.3 son paragraf).
type witnessTrustHeadDoc struct {
	Schema      string `json:"schema"`
	AdminEpoch  uint64 `json:"admin_epoch"`
	TrustSha256 string `json:"trust_sha256"`
	VerifiedAt  string `json:"verified_at"`
	Verifier    string `json:"verifier"`
}

// verificationReport, GC cron'un (§6.7) ve staleness alarm'ının okuduğu son
// doğrulama özetidir (`verification/latest.json`).
type verificationReport struct {
	OK         bool   `json:"ok"`
	VerifiedAt string `json:"verified_at"`
	Verifier   string `json:"verifier"`
}

// PublishHeads, başarılı bir doğrulamanın per-proje head'lerini + trust head'i +
// verification raporunu NON-object-locked witness bucket'ına yazar (§9.3.3). Bu
// path HERHANGİ bir Cloudflare hop'u İÇERMEZ (B2-native writer). Anahtar düzeni:
// witness/<project>.json, witness/trust.json, verification/latest.json.
func PublishHeads(ctx context.Context, w Writer, res *Result, verifier string) error {
	verifiedAt := res.VerifiedAt.UTC().Format(time.RFC3339)
	for project, h := range res.ProjectHeads {
		doc := WitnessHead{Schema: SchemaWitnessHead, Project: project, Epoch: h.Epoch, ManifestSha256: h.ManifestSha256, VerifiedAt: verifiedAt, Verifier: verifier}
		body, _ := json.Marshal(doc)
		if err := w.Put(ctx, "witness/"+project+".json", body, "application/json"); err != nil {
			return fmt.Errorf("witness.PublishHeads: %s: %w", project, err)
		}
	}
	th := witnessTrustHeadDoc{Schema: SchemaTrustHead, AdminEpoch: res.TrustHead.AdminEpoch, TrustSha256: res.TrustHead.TrustSha256, VerifiedAt: verifiedAt, Verifier: verifier}
	thBody, _ := json.Marshal(th)
	if err := w.Put(ctx, "witness/trust.json", thBody, "application/json"); err != nil {
		return fmt.Errorf("witness.PublishHeads: trust head: %w", err)
	}
	rep := verificationReport{OK: true, VerifiedAt: verifiedAt, Verifier: verifier}
	repBody, _ := json.Marshal(rep)
	if err := w.Put(ctx, "verification/latest.json", repBody, "application/json"); err != nil {
		return fmt.Errorf("witness.PublishHeads: report: %w", err)
	}
	return nil
}

// --- intent.Witness implementasyonu (deploy fresh-or-fail tüketimi, §7.3.4) ---

// HTTPWitness, `--intent deploy` için escrow tanık head'ini NON-Cloudflare witness
// origin'inden çeken intent.Witness implementasyonudur (§9.3.4). Origin B2-native
// bir endpoint OLMALIDIR (CF hop YOK, §9.3 F6). HeadEpoch başarısız olursa hata
// döner → intent.CheckWitness bunu WITNESS_UNREACHABLE'a çevirir (fail-closed).
type HTTPWitness struct {
	Origin  string // ör. https://wapps-secrets-witness.s3.us-west-004.backblazeb2.com
	Project string
	Client  *http.Client
	Now     func() time.Time
	// FailOnStale true ise (varsayılan) bayat (>2h) head de HeadEpoch'ta hata
	// döner → deploy fail-closed. CF-kontrollü saldırganın en ucuz hamlesi tanık
	// trafiğini düşürmektir (F6); bayat head'e güvenmek onunla eşdeğerdir.
	FailOnStale bool
}

// NewHTTPWitness, verilen origin+proje için bir HTTPWitness kurar (FailOnStale açık).
func NewHTTPWitness(origin, project string) *HTTPWitness {
	return &HTTPWitness{Origin: origin, Project: project, Client: http.DefaultClient, Now: time.Now, FailOnStale: true}
}

// fetchHead, tanık origin'in bu proje için gördüğü son head dokümanını çeker +
// doğrular (schema + staleness). Nil-alıcı guard'ı: typed-nil bir *HTTPWitness
// (bir intent.Witness arayüzüne saklanmış) panik yerine erişilemez sayılır (P3-c
// — CheckWitness bunu WITNESS_UNREACHABLE'a çevirir). Erişilemez/bayat/malformed → hata.
func (w *HTTPWitness) fetchHead() (WitnessHead, error) {
	if w == nil {
		return WitnessHead{}, fmt.Errorf("witness: nil witness")
	}
	if w.Origin == "" {
		return WitnessHead{}, fmt.Errorf("witness: no origin configured")
	}
	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	url := w.Origin + "/witness/" + w.Project + ".json"
	resp, err := client.Get(url)
	if err != nil {
		return WitnessHead{}, fmt.Errorf("witness: fetch head: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return WitnessHead{}, fmt.Errorf("witness: origin returned HTTP %d", resp.StatusCode)
	}
	var doc WitnessHead
	if err := json.Unmarshal(body, &doc); err != nil {
		return WitnessHead{}, fmt.Errorf("witness: head malformed: %w", err)
	}
	if doc.Schema != SchemaWitnessHead {
		return WitnessHead{}, fmt.Errorf("witness: unexpected head schema %q", doc.Schema)
	}
	if w.FailOnStale {
		now := time.Now
		if w.Now != nil {
			now = w.Now
		}
		if doc.IsStale(now()) {
			return WitnessHead{}, fmt.Errorf("witness: head is stale (verified_at %s > %s ago)", doc.VerifiedAt, StalenessLimit)
		}
	}
	return doc, nil
}

// HeadEpoch, tanık origin'in bu proje için gördüğü son epoch'u döner (intent.Witness).
func (w *HTTPWitness) HeadEpoch() (uint64, error) {
	doc, err := w.fetchHead()
	if err != nil {
		return 0, err
	}
	return doc.Epoch, nil
}

// WitnessHead, tanık origin'in gördüğü son (epoch, manifestSha256) çiftini döner
// (intent.WitnessHeadReader, P3-c). CheckWitness aynı-epoch FORK kontrolü için
// manifestSha256'yı bunun üzerinden okur.
func (w *HTTPWitness) WitnessHead() (uint64, string, error) {
	doc, err := w.fetchHead()
	if err != nil {
		return 0, "", err
	}
	return doc.Epoch, doc.ManifestSha256, nil
}

// ensure HTTPWitness satisfies both intent.Witness and the richer reader.
var (
	_ intent.Witness           = (*HTTPWitness)(nil)
	_ intent.WitnessHeadReader = (*HTTPWitness)(nil)
)
