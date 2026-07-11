package lifecycle

import (
	"fmt"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// GrantRequest, bir prensibe bir projede erişim veren kontrol-düzlemi işleminin
// girdisidir (SPEC §8.1.4). Co-sign tier PARENT'ın durumundan + classifier'dan
// yaptırılır: prod grant N≥2'de 2 FARKLI admin insan; lab / solo 1 admin + audit.
type GrantRequest struct {
	Parent  *trust.VerifiedEpoch
	Grant   registry.Grant
	Signers []cryptoid.SigningKey
}

// Grant, imzalı bir grant trust epoch'u üretir ve PARENT'a karşı DOĞRULAR (§4.5
// katmanlı co-sign). Manifest-only wrap eklemesi (§8.1.4 step 2 / §3.8.1) grant
// LANDLENDİKTEN sonra rewrap motoruyla (ADD yolu) uygulanır — bu fonksiyon yalnızca
// trust-manifest grant tablosunu (kontrol düzlemi) günceller.
func (e *Engine) Grant(req GrantRequest) (cryptoid.SignedObject, *trust.VerifiedEpoch, error) {
	if req.Parent == nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Grant: nil parent")
	}
	if req.Grant.Principal == "" || req.Grant.Project == "" {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Grant: grant needs principal+project")
	}
	// Prensip kayıtta olmalı (§4.11 IDENTITY_NOT_ENROLLED).
	if _, ok := req.Parent.Manifest.Registry().IdentityByID(req.Grant.Principal); !ok {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Grant: %q: %w", req.Grant.Principal, registry.ErrIdentityNotEnrolled)
	}
	obj, next, err := e.buildTrustEpoch(req.Parent, trust.ChangeGrant, func(child *trust.TrustManifest) {
		grants := make([]registry.Grant, 0, len(req.Parent.Manifest.Grants)+1)
		grants = append(grants, req.Parent.Manifest.Grants...)
		grants = append(grants, req.Grant)
		child.Grants = grants
	}, req.Signers...)
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	return obj, next, nil
}

// RevokeRequest, bir prensibin grant'(lar)ını kaldıran kontrol-düzlemi işleminin
// girdisidir (SPEC §8.5.3 step 1). Project boşsa prensibin TÜM projelerdeki
// grant'ları kaldırılır.
type RevokeRequest struct {
	Parent    *trust.VerifiedEpoch
	Principal string
	Project   string // "" → prensibin tüm grant'ları
	Signers   []cryptoid.SigningKey
}

// Revoke, prensibin grant'larını kaldıran imzalı bir grant trust epoch'u üretir ve
// doğrular. Grant kaldırma safety-increasing'dir; sonuçta gereken wrap-set alıcı
// kümesi küçülür → rewrap motorunun REMOVE (yeni DEK + re-encrypt §3.8.2) yolunu
// tetikler. Bu, offboard step 2'nin trust/registry epoch parçasıdır (§8.5.3).
func (e *Engine) Revoke(req RevokeRequest) (cryptoid.SignedObject, *trust.VerifiedEpoch, error) {
	if req.Parent == nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Revoke: nil parent")
	}
	if req.Principal == "" {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.Revoke: empty principal")
	}
	removed := 0
	obj, next, err := e.buildTrustEpoch(req.Parent, trust.ChangeGrant, func(child *trust.TrustManifest) {
		grants := make([]registry.Grant, 0, len(req.Parent.Manifest.Grants))
		for _, g := range req.Parent.Manifest.Grants {
			if g.Principal == req.Principal && (req.Project == "" || g.Project == req.Project) {
				removed++
				continue // kaldır
			}
			grants = append(grants, g)
		}
		child.Grants = grants
	}, req.Signers...)
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	return obj, next, nil
}

// RetireRequest, bir prensibin kimliğini emekliye ayıran (status → revoked)
// kontrol-düzlemi işleminin girdisidir (SPEC §8.5.3 step 1: "registry epoch
// retiring its identities"). Registry tier (1 admin). Prensibin grant'ları ÖNCE
// Revoke ile kaldırılmış OLMALIDIR — aksi halde sonuç registry snapshot'ı geçersiz
// olur (grant revoked bir prensibi isimlendiremez, §4.3).
type RetireRequest struct {
	Parent    *trust.VerifiedEpoch
	Principal string
	Signers   []cryptoid.SigningKey
}

// RetireIdentity, prensibin kimliğini emekliye ayıran imzalı bir registry trust
// epoch'u üretir ve doğrular. Sonuç registry snapshot'ı yapısal olarak da doğrulanır
// (grant/allowlist artık revoked prensibi isimlendirmemeli).
func (e *Engine) RetireIdentity(req RetireRequest) (cryptoid.SignedObject, *trust.VerifiedEpoch, error) {
	if req.Parent == nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.RetireIdentity: nil parent")
	}
	if _, ok := req.Parent.Manifest.Registry().IdentityByID(req.Principal); !ok {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.RetireIdentity: %q: %w", req.Principal, registry.ErrIdentityNotEnrolled)
	}
	obj, next, err := e.buildTrustEpoch(req.Parent, trust.ChangeRegistry, func(child *trust.TrustManifest) {
		ids := make([]registry.Identity, len(req.Parent.Manifest.Identities))
		copy(ids, req.Parent.Manifest.Identities)
		for i := range ids {
			if ids[i].ID == req.Principal {
				ids[i].Status = registry.StatusRevoked
			}
		}
		child.Identities = ids
	}, req.Signers...)
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	// Sonuç registry snapshot'ı yapısal olarak geçerli olmalı (revoked prensibi
	// isimlendiren grant/allowlist kalmamalı).
	if verr := next.Manifest.Registry().Validate(); verr != nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.RetireIdentity: %w", verr)
	}
	return obj, next, nil
}
