package trust

import (
	"fmt"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// VerifyEpochReset, bir epoch-reset kaydını (SPEC §4.8) tek başına doğrular —
// güven zincirinin TEK yaptırımlı süreksizliği (felaket kurtarma). Reset,
// zinciri yeniden-anchor'lar ve reset ÖNCESİ son doğrulanmış epoch'un ≥M
// KÖK-class Ed25519 anahtarıyla imzalanır.
//
//   - prior: reset öncesi son (doğrulanmış) manifest — KÖK anahtar materyalini
//     ve son admin_epoch'u sağlar. Prior head KAYIPSA (escrow-restore) yine de
//     roster'ı (kökleri) taşıyan bir manifest verilir; priorHeadAvailable=false.
//   - priorSHA: prior head'in payload hash'i (yalnızca head mevcutken prev-link
//     için).
//   - pinnedLast: istemcinin last_verified pin'i — reset bir rollback'i
//     "aklayamaz": pin, prior_chain.last_admin_epoch'tan YENİYSE TRUST_DOWNGRADE.
//   - witnessBound: escrow tanık head'inin (§9-10) gördüğü en yüksek epoch;
//     reset epoch'u bundan KATİ olarak büyük olmalı (monotonluk reset'i aşar).
func VerifyEpochReset(obj cryptoid.SignedObject, prior *TrustManifest, priorSHA string, pinnedLast Pin, witnessBound uint64, priorHeadAvailable bool) (*VerifiedEpoch, error) {
	if prior == nil {
		return nil, fmt.Errorf("trust.VerifyEpochReset: nil prior roster: %w", ErrTrustChainBroken)
	}
	priorView, err := prior.buildSignerView()
	if err != nil {
		return nil, err
	}
	hash := TrustObjectHash(obj.Bytes)
	cand, err := ParseTrustBody(obj.Bytes)
	if err != nil {
		return nil, err
	}
	if cand.ChangeClass != ChangeEpochReset {
		return nil, fmt.Errorf("trust.VerifyEpochReset: change_class %q is not epoch_reset: %w", cand.ChangeClass, ErrTrustChainBroken)
	}
	return verifyResetInternal(obj, cand, hash, priorView, priorSHA, prior.AdminEpoch, pinnedLast, witnessBound, priorHeadAvailable)
}

// verifyResetInternal, epoch-reset doğrulamasının ortak çekirdeğidir; hem
// zincir-içi (VerifyNext) hem tek-başına (VerifyEpochReset) yollarından çağrılır
// (SPEC §4.8 kuralları).
func verifyResetInternal(
	obj cryptoid.SignedObject,
	cand *TrustManifest,
	hash string,
	priorView signerView,
	priorSHA string,
	priorAdminEpoch uint64,
	pinnedLast Pin,
	witnessBound uint64,
	priorHeadAvailable bool,
) (*VerifiedEpoch, error) {
	if cand.EpochReset == nil {
		return nil, fmt.Errorf("trust.verifyResetInternal: epoch_reset record required: %w", ErrTrustChainBroken)
	}
	er := cand.EpochReset
	if er.Schema != SchemaTrustReset {
		return nil, fmt.Errorf("trust.verifyResetInternal: reset schema %q: %w", er.Schema, ErrTrustChainBroken)
	}
	if er.ResetID == "" || er.Reason == "" {
		return nil, fmt.Errorf("trust.verifyResetInternal: reset missing reset_id/reason: %w", ErrTrustChainBroken)
	}

	// prior_chain, verilen prior roster ile tutarlı olmalı.
	if er.PriorChain.LastAdminEpoch != priorAdminEpoch {
		return nil, fmt.Errorf("trust.verifyResetInternal: prior_chain.last_admin_epoch %d != prior %d: %w",
			er.PriorChain.LastAdminEpoch, priorAdminEpoch, ErrTrustChainBroken)
	}

	// prev-link kuralı (§4.8): prior head mevcutsa prior_chain.last_trust_sha256
	// ile prev_trust_sha256 eşleşir; kayıpsa prev BOŞ olmalıdır.
	if priorHeadAvailable {
		if cand.PrevTrustSHA256 != priorSHA {
			return nil, fmt.Errorf("trust.verifyResetInternal: prev_trust_sha256 does not link to prior head: %w", ErrTrustChainBroken)
		}
		if er.PriorChain.LastTrustSHA256 != priorSHA {
			return nil, fmt.Errorf("trust.verifyResetInternal: prior_chain.last_trust_sha256 mismatch: %w", ErrTrustChainBroken)
		}
	} else {
		if cand.PrevTrustSHA256 != "" {
			return nil, fmt.Errorf("trust.verifyResetInternal: lost-head reset must carry empty prev_trust_sha256: %w", ErrTrustChainBroken)
		}
	}

	// Monotonluk: reset epoch'u prior head'ten VE tanık sınırından KATİ büyük
	// olmalı (§4.8) — monotonluk reset'i aşar.
	if cand.AdminEpoch <= er.PriorChain.LastAdminEpoch {
		return nil, fmt.Errorf("trust.verifyResetInternal: reset admin_epoch %d must exceed prior %d: %w",
			cand.AdminEpoch, er.PriorChain.LastAdminEpoch, ErrTrustChainBroken)
	}
	if cand.AdminEpoch <= witnessBound {
		return nil, fmt.Errorf("trust.verifyResetInternal: reset admin_epoch %d must exceed witness bound %d: %w",
			cand.AdminEpoch, witnessBound, ErrTrustChainBroken)
	}

	// Downgrade: reset bir rollback'i aklayamaz (§4.8). İstemcinin pin'i, reset'in
	// önceki-zincir sınırından YENİYSE reddet.
	if pinnedLast.AdminEpoch > er.PriorChain.LastAdminEpoch {
		return nil, fmt.Errorf("trust.verifyResetInternal: pinned epoch %d newer than reset prior %d: %w",
			pinnedLast.AdminEpoch, er.PriorChain.LastAdminEpoch, ErrTrustDowngrade)
	}

	// İmza: reset ÖNCESİ epoch'un ≥M KÖK-class anahtarı (§4.8).
	req := Requirement{Class: ClassRoot, Threshold: priorView.m}
	if err := verifyQuorum(obj.Bytes, obj.Sigs, req, priorView); err != nil {
		return nil, err
	}

	// Reset epoch'u geçerli bir roster taşır (yeni/devam eden).
	if err := validateRosterInvariants(cand); err != nil {
		return nil, err
	}

	view, err := cand.buildSignerView()
	if err != nil {
		return nil, err
	}
	return &VerifiedEpoch{Manifest: cand, BytesSHA256: hash, Raw: obj, view: view}, nil
}
