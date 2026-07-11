package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// Şema tanımlayıcıları (SPEC §4.2.2 / §4.8).
const (
	SchemaTrust      = "wapps-trust/v1"
	SchemaTrustReset = "wapps-trust-reset/v1"
)

// change_class kapalı kümesi (SPEC §4.2.2). İmzalayan sınıfı + eşik bu değere
// göre belirlenir (SPEC §4.5 step 4, policy.go).
const (
	ChangeRoster     = "roster"
	ChangeRegistry   = "registry"
	ChangeGrant      = "grant"
	ChangePolicy     = "policy"
	ChangeEpochReset = "epoch_reset"
)

// statusActive, kök anahtar durum değeri.
const statusActive = "active"

// GenesisEpoch, güven zincirinin ilk epoch numarasıdır.
const GenesisEpoch uint64 = 1

// Quorum, roster M-of-N eşiğidir (SPEC §4.2.2). Bugün pinli: {M:2, N:3}.
type Quorum struct {
	M int `json:"m"`
	N int `json:"n"`
}

// RootKey, offline Ed25519 admin kök imzalama anahtarının kayıt girdisidir
// (SPEC §4.2.2). Pubkey, ham 32B Ed25519 public key (JSON'da base64).
type RootKey struct {
	KeyID  string `json:"key_id"` // §3.7 parmak izi
	Alg    string `json:"alg"`    // "ed25519"
	Pubkey []byte `json:"pubkey"` // base64; ham 32B
	Media  string `json:"media"`  // yubikey-piv | ... (distinct media)
	Holder string `json:"holder"` // "human:<email>" — custody sahibi
	Status string `json:"status"` // active | retired
}

// ReceiptKey, Worker'ın ES256 liveness-receipt / token-mint public anahtarının
// pinlenmiş halidir (SPEC §4.2.2, §6.4–§6.6). JWK ham JSON passthrough olarak
// tutulur (byte-exact korunur; doğrulayıcı yorumlamaz).
type ReceiptKey struct {
	Kid string          `json:"kid"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}

// PriorChain, bir epoch-reset kaydının zincirlediği önceki head'i tanımlar
// (SPEC §4.8).
type PriorChain struct {
	LastAdminEpoch  uint64 `json:"last_admin_epoch"`
	LastTrustSHA256 string `json:"last_trust_sha256"`
}

// EpochReset, güven zincirinin TEK yaptırımlı süreksizliğidir (SPEC §4.8):
// felaket kurtarma için zinciri yeniden-anchor'lar. Per-proje DATA epoch-reset
// (§9.5) BUNDAN AYRIDIR ve burada kurulmaz.
type EpochReset struct {
	Schema      string     `json:"schema"` // "wapps-trust-reset/v1"
	ResetID     string     `json:"reset_id"`
	Reason      string     `json:"reason"` // dr_restore | escrow_restore | quorum_recovery
	PriorChain  PriorChain `json:"prior_chain"`
	SnapshotRef string     `json:"snapshot_ref"`
}

// TrustManifest, tek bir güven epoch'unun payload'ıdır (SPEC §4.2.2). Depolanan
// form, TAM baytlar üzerinde ≥M imza taşıyan bir cryptoid.SignedObject
// sarmalayıcısıdır.
type TrustManifest struct {
	Schema           string                 `json:"schema"` // "wapps-trust/v1"
	AdminEpoch       uint64                 `json:"admin_epoch"`
	PrevTrustSHA256  string                 `json:"prev_trust_sha256"` // hex; "" yalnızca genesis'te
	CreatedAt        time.Time              `json:"created_at"`
	ChangeClass      string                 `json:"change_class"`
	BootstrapSolo    bool                   `json:"bootstrap_solo"`
	Quorum           Quorum                 `json:"quorum"`
	Roots            []RootKey              `json:"roots"`
	Admins           []string               `json:"admins"` // identity ID'leri
	Identities       []registry.Identity    `json:"identities"`
	Grants           []registry.Grant       `json:"grants"`
	WriterAllowlists []registry.WriterAllow `json:"writer_allowlists"`
	WorkerReceiptPub ReceiptKey             `json:"worker_receipt_pubkey"`
	WorkerMintPubs   []ReceiptKey           `json:"worker_mint_pubkeys"`
	EpochReset       *EpochReset            `json:"epoch_reset,omitempty"`
}

// NewRootKey, bir cryptoid Ed25519 anahtarından kök kayıt girdisi kurar; KeyID'yi
// §3.7'ye göre doldurur. Test/ceremony ergonomisi.
func NewRootKey(k *cryptoid.Ed25519SigningKey, media, holder string) RootKey {
	return RootKey{
		KeyID:  k.KeyID(),
		Alg:    k.Alg(),
		Pubkey: k.PublicKeyBytes(),
		Media:  media,
		Holder: holder,
		Status: statusActive,
	}
}

// Registry, manifest içine gömülü kayıt görünümünü (SPEC §4.3) bir
// registry.Snapshot olarak döndürür; grant çözümleme ve doğrulama için.
func (m *TrustManifest) Registry() *registry.Snapshot {
	return &registry.Snapshot{
		Schema:           registry.SchemaRegistry,
		Identities:       m.Identities,
		Grants:           m.Grants,
		WriterAllowlists: m.WriterAllowlists,
	}
}

// MarshalCanonical, manifest'i DETERMİNİSTİK baytlar olarak seri hale getirir:
// üst-seviye diziler stabil bir anahtara göre sıralanır, HTML-escape kapalıdır
// ve baytlar BİR KEZ üretilir. DİKKAT: bu YALNIZCA imzalayan tarafın baytları
// üretmesi içindir; doğrulama ASLA yeniden serileştirmez, depolanan baytları
// OLDUĞU GİBİ hash'ler (SPEC §3.6.3/§4.2.1).
func (m *TrustManifest) MarshalCanonical() ([]byte, error) {
	out := *m

	roots := append([]RootKey(nil), m.Roots...)
	sort.Slice(roots, func(i, j int) bool { return roots[i].KeyID < roots[j].KeyID })
	out.Roots = roots

	admins := append([]string(nil), m.Admins...)
	sort.Strings(admins)
	out.Admins = admins

	ids := append([]registry.Identity(nil), m.Identities...)
	sort.Slice(ids, func(i, j int) bool { return ids[i].ID < ids[j].ID })
	out.Identities = ids

	grants := append([]registry.Grant(nil), m.Grants...)
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Principal != grants[j].Principal {
			return grants[i].Principal < grants[j].Principal
		}
		return grants[i].Project < grants[j].Project
	})
	out.Grants = grants

	was := append([]registry.WriterAllow(nil), m.WriterAllowlists...)
	sort.Slice(was, func(i, j int) bool {
		if was[i].Principal != was[j].Principal {
			return was[i].Principal < was[j].Principal
		}
		return was[i].Project < was[j].Project
	})
	out.WriterAllowlists = was

	mints := append([]ReceiptKey(nil), m.WorkerMintPubs...)
	sort.Slice(mints, func(i, j int) bool { return mints[i].Kid < mints[j].Kid })
	out.WorkerMintPubs = mints

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&out); err != nil {
		return nil, fmt.Errorf("trust.MarshalCanonical: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseTrustBody, ham body baytlarını TrustManifest'e ayrıştırır ve şemayı
// doğrular. YALNIZCA imza kümesi TAM baytlar üzerinde geçtikten SONRA
// otoritatif kabul edilir (SPEC §3.6.3). Bilinmeyen alanlar reddedilir.
func ParseTrustBody(body []byte) (*TrustManifest, error) {
	var m TrustManifest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("trust.ParseTrustBody: %w", err)
	}
	if m.Schema != SchemaTrust {
		return nil, fmt.Errorf("trust.ParseTrustBody: %q: %w", m.Schema, ErrUnsupportedSchema)
	}
	return &m, nil
}

// SignTrustManifest, manifest'i kanonik olarak seri hale getirir ve verilen
// imzalama anahtar(lar)ıyla TAM baytlar üzerinde ayrık imzalar üretir (SPEC
// §4.2.1). Roster/epoch-reset için ≥M kök Ed25519 anahtarıyla imzalanmalıdır;
// bu fonksiyon N imza üretir, eşik doğrulaması VerifyRosterChain'dedir.
func SignTrustManifest(m *TrustManifest, keys ...cryptoid.SigningKey) (cryptoid.SignedObject, []byte, error) {
	if len(keys) == 0 {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("trust.SignTrustManifest: at least one signing key required: %w", ErrTrustQuorumUnmet)
	}
	body, err := m.MarshalCanonical()
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	sigs := make([]cryptoid.Signature, 0, len(keys))
	for _, k := range keys {
		sig, err := k.Sign(body)
		if err != nil {
			return cryptoid.SignedObject{}, nil, fmt.Errorf("trust.SignTrustManifest: %w", err)
		}
		sigs = append(sigs, sig)
	}
	return cryptoid.SignedObject{Bytes: body, Sigs: sigs}, body, nil
}

// TrustObjectHash, depolanan imzalı-sarmalayıcı baytlarının değil, İMZALANAN
// (payload) baytlarının çıplak-hex SHA-256'sıdır. prev_trust_sha256 ve pinler
// bu değeri taşır: güven zincirinde her epoch bir SONRAKİNİN prev_trust_sha256'sı
// olarak KENDİ payload baytlarının hash'ini kaydeder (SPEC §4.2.2).
func TrustObjectHash(payloadBytes []byte) string {
	sum := sha256.Sum256(payloadBytes)
	return hex.EncodeToString(sum[:])
}
