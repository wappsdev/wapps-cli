package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Alerter, doğrulayıcının staleness/başarısızlık alarmlarını gönderdiği kanaldır
// (SPEC §9.3.5 / alert rule A5 → Discord). Teslimat başarısızlığı doğrulamayı
// bloklamaz (alert = tespit).
type Alerter interface {
	Alert(ctx context.Context, rule, summary string, detail map[string]any)
}

// DiscordAlerter, A5'i mevcut ci.yml Discord webhook'una POST eder (§6.10).
type DiscordAlerter struct {
	WebhookURL string
	Client     *http.Client
}

// Alert uygular Alerter (best-effort; asla throw etmez).
func (d DiscordAlerter) Alert(ctx context.Context, rule, summary string, detail map[string]any) {
	if d.WebhookURL == "" {
		return
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	content := fmt.Sprintf("[secrets-verifier %s] %s", rule, summary)
	payload := map[string]any{"content": content}
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			payload["embeds"] = []map[string]any{{"description": "```" + string(b) + "```"}}
		}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/json")
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// noopAlerter, alert kanalı yapılandırılmadığında sessiz no-op.
type noopAlerter struct{}

func (noopAlerter) Alert(context.Context, string, string, map[string]any) {}

// RunOnce, VM verifier'ın saatlik cron adımıdır (§9.3): Verify → başarılıysa
// PublishHeads, başarısızsa A5 alert + hata döner. now enjekte edilebilir.
// Alerter nil ise no-op. Bu, VM cron entry'sinin (cmd) çekirdeğidir.
func RunOnce(ctx context.Context, r Reader, w Writer, cfg Config, verifier string, alerter Alerter, now time.Time) (*Result, error) {
	if alerter == nil {
		alerter = noopAlerter{}
	}
	res, err := Verify(ctx, r, cfg)
	if err != nil {
		alerter.Alert(ctx, "A5", "escrow verification FAILED", map[string]any{"error": err.Error()})
		return nil, err
	}
	if perr := PublishHeads(ctx, w, res, verifier); perr != nil {
		alerter.Alert(ctx, "A5", "witness head publish failed", map[string]any{"error": perr.Error()})
		return nil, perr
	}
	return res, nil
}
