// Package intent, okuma/yazma niyetini taşır (server-decrypt SPEC §7).
//
// ZK tasarımın tazelik motoru (liveness receipt'ler, ciphertext-cache stale
// katmanları, escrow-witness çapraz kontrolü) pivotla SİLİNDİ (SPEC §0.2 —
// server plaintext döner; her okuma/yazma ağ ister, NETWORK_REQUIRED §7.4).
// Geriye kalan: verb'lerin --intent bayrağının tipi + parse'ı ve Worker'a
// giden bilgilendirici intent header adları (§6.4 — audit verb etiketlemesi
// için; ASLA bir yetkilendirme girdisi değildir).
package intent

import (
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// Intent, okuma/yazma niyet sınıfıdır.
type Intent string

const (
	Dev    Intent = "dev"
	Deploy Intent = "deploy"
)

// Worker'a gönderilen bilgilendirici header'lar (§6.4): rotation header'ı bir
// yazımı rotate.step olarak, sync intent'i bir import'u key.sync olarak
// etiketler. Strip edilirlerse satır key.set/key.import'a düşer — rotate-plan
// oracle'ı yine tamdır (§6.3).
const (
	// HeaderRotation, X-Wapps-Rotation: <recipe-id> (rotate.step etiketi).
	HeaderRotation = "X-Wapps-Rotation"
	// HeaderIntent, X-Wapps-Intent: sync (key.sync etiketi).
	HeaderIntent = "X-Wapps-Intent"
	// IntentSync, HeaderIntent'in sync değeri.
	IntentSync = "sync"
)

// Parse, bir --intent bayrağını çözer; boş → Dev (default). Bilinmeyen değer hata.
func Parse(s string) (Intent, error) {
	switch s {
	case "", string(Dev):
		return Dev, nil
	case string(Deploy):
		return Deploy, nil
	default:
		return "", clierr.Newf(clierr.Internal, "unknown intent %q (allowed: dev, deploy)", s)
	}
}
