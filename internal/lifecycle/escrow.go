package lifecycle

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// Escrow Shamir parametreleri (SPEC §3.9 v1): 2-of-3.
const (
	escrowShares    = 3
	escrowThreshold = 2
)

// EscrowRekeyResult, bir escrow re-key seremonisinin (SPEC §8.5.4/§3.8.5) offline
// çıktısıdır. Yeni escrow PUBLIC anahtarı bir trust epoch ile kayda girer ve tüm
// projelerde bir DEK re-mint kampanyasına (Rewrap, yeni escrow hedef kümede)
// beslenir. Shamir payları YALNIZCA BİR KEZ (SharesOnce) alınır ve ASLA diske
// yazılmaz — combined skalar/pay disipline (§3.9): göster/transkribe et.
type EscrowRekeyResult struct {
	Recipient   *cryptoid.X25519Recipient // yeni escrow public anahtarı (kayda girer)
	Fingerprint string                    // §3.7 parmak izi
	Threshold   int
	Parts       int
	shares      [][]byte // Shamir payları (bayt); SharesOnce sonrası sıfırlanır
	consumed    bool
}

// EscrowRekey, yeni bir escrow keypair'i OFFLINE üretir ve gizli skaları Shamir
// 2-of-3 böler (SPEC §8.5.4 step 1 / §3.9). Payları içeren sonuç döner; birleşik
// skalar HİÇBİR yerde saklanmaz. rng nil ise crypto/rand kullanılır (test için
// sabit rng geçirilebilir — pinned vektörler cryptoid'de).
func (e *Engine) EscrowRekey(rng io.Reader) (*EscrowRekeyResult, error) {
	if rng == nil {
		rng = rand.Reader
	}
	scalar := make([]byte, 32)
	if _, err := io.ReadFull(rng, scalar); err != nil {
		return nil, fmt.Errorf("lifecycle.EscrowRekey: scalar: %w", err)
	}
	id, err := cryptoid.NewX25519IdentityFromScalar(scalar)
	if err != nil {
		return nil, fmt.Errorf("lifecycle.EscrowRekey: identity: %w", err)
	}
	shares, err := cryptoid.ShamirSplit(scalar, escrowShares, escrowThreshold, rng)
	if err != nil {
		return nil, fmt.Errorf("lifecycle.EscrowRekey: split: %w", err)
	}
	// Skaları sıfırla (combined skalar asla tutulmaz — yalnızca paylar, bir kez).
	for i := range scalar {
		scalar[i] = 0
	}
	rec := id.Recipient()
	return &EscrowRekeyResult{
		Recipient:   rec,
		Fingerprint: rec.Fingerprint(),
		Threshold:   escrowThreshold,
		Parts:       escrowShares,
		shares:      shares,
	}, nil
}

// SharesOnce, Shamir paylarını BİR KEZ döner (fiziksel medyaya transkripsiyon
// için); ikinci çağrı nil döner. Dönüşten sonra iç paylar sıfırlanır (§3.9: pay
// asla diske yazılmaz, kalıcılık yok).
func (r *EscrowRekeyResult) SharesOnce() [][]byte {
	if r.consumed {
		return nil
	}
	out := make([][]byte, len(r.shares))
	for i, s := range r.shares {
		cp := make([]byte, len(s))
		copy(cp, s)
		out[i] = cp
		for j := range r.shares[i] {
			r.shares[i][j] = 0
		}
	}
	r.shares = nil
	r.consumed = true
	return out
}
