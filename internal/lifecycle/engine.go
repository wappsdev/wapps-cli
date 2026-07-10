package lifecycle

import (
	"fmt"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// Engine, yaşam döngüsü motorudur (SPEC §8). Tüm kontrol-düzlemi mutasyonları —
// enroll-commit, vouch, grant, revoke, offboard adım geçişleri, escrow re-key —
// bu motordan geçer. Dış kenarlar (data/record store, saat, donanım keygen, token
// revoke) enjekte edilebilir → motor tam test-edilebilir.
type Engine struct {
	cfg Config
}

// Config, Engine bağımlılıklarıdır.
type Config struct {
	// Data, per-proje data-manifest kalıcılık port'u (rewrap motoru için).
	Data DataStore
	// Records, imzalı offboard kayıtları + ledger'lar için port.
	Records RecordStore
	// Classifier, grant epoch'larının prod/lab katmanını (co-sign tier) belirler
	// (§4.5). nil → tümü prod (strict-safe).
	Classifier trust.ProjectClassifier
	// Keygen, enroll'da anahtar üretimi. nil → SoftwareKeygen (CI/test). Donanım
	// (SE/YubiKey) yolu arayüzle bağlanır (hardware.go), motor kapsamı DIŞINDA.
	Keygen HardwareKeygen
	// TokenRevoker, offboard step 1 kill-switch'in Worker/CF token revoke tarafı
	// (§8.5.2). nil → StubTokenRevoker (net TODO). G-account (§6) ile bağlanır.
	TokenRevoker TokenRevoker
	// RotationRuns, offboard close'un (§8.5.7) değer-rotasyon worklist run'larının
	// TERMİNAL olduğunu doğruladığı port (§8.5.5.4). nil → StubRotationRunLedger
	// (G11 bağlı değil → close "awaiting rotation"da bloklanır, sahte attestation
	// asla basılmaz).
	RotationRuns RotationRunLedger
	// Now, saat (test için). nil → time.Now.
	Now func() time.Time
}

// New, verilen config'le bir Engine kurar; boş alanlara güvenli varsayılanlar.
func New(cfg Config) *Engine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Classifier == nil {
		cfg.Classifier = func(string) trust.ProjectClass { return trust.ProjectProd }
	}
	if cfg.Keygen == nil {
		cfg.Keygen = SoftwareKeygen{}
	}
	if cfg.TokenRevoker == nil {
		cfg.TokenRevoker = StubTokenRevoker{}
	}
	if cfg.RotationRuns == nil {
		cfg.RotationRuns = StubRotationRunLedger{}
	}
	return &Engine{cfg: cfg}
}

func (e *Engine) now() time.Time { return e.cfg.Now().UTC() }

// buildTrustEpoch, doğrulanmış parent epoch'unun bir HALEFİNİ (E+1) üretir ve
// PARENT'a karşı DOĞRULAR (trust.VerifyNext): mutate ile child manifest üzerinde
// değişiklik yapılır, verilen imzalama anahtar(lar)ıyla TAM baytlar imzalanır ve
// katmanlı co-sign + hash-link + monotonluk + anlamsal değişmezler parent'a karşı
// yaptırılır (SPEC §4.5). İmza kümesi katmanı geçmezse trust.ErrTrustQuorumUnmet;
// bir kural ihlali ErrTrustChainBroken. Bu, vouch/grant/revoke'un ORTAK çekirdeği.
func (e *Engine) buildTrustEpoch(parent *trust.VerifiedEpoch, changeClass string, mutate func(*trust.TrustManifest), signers ...cryptoid.SigningKey) (cryptoid.SignedObject, *trust.VerifiedEpoch, error) {
	if parent == nil {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("lifecycle.buildTrustEpoch: nil parent")
	}
	child := *parent.Manifest // sığ kopya; mutate YENİ dilimler atamalı (parent paylaşılmasın)
	child.AdminEpoch = parent.Manifest.AdminEpoch + 1
	child.PrevTrustSHA256 = parent.BytesSHA256
	child.ChangeClass = changeClass
	child.CreatedAt = e.now()
	mutate(&child)

	obj, _, err := trust.SignTrustManifest(&child, signers...)
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	// Halefi PARENT'ın imzalayan görünümüne karşı doğrula (kendi materyaline karşı
	// DEĞİL) — katman + hash-link + monotonluk + değişmezler burada yaptırılır.
	next, err := trust.VerifyNext(parent, obj, e.cfg.Classifier, parent.Pin(), parent.Manifest.AdminEpoch)
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	return obj, next, nil
}
