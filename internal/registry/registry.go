// Package registry, wapps-secrets kimlik kaydını (identity registry) ve
// per-principal grant'ları modeller (SPEC §4.3). Sistemdeki HER prensip —
// insan, makine, backup anahtarı, escrow alıcısı — bir grant kendisini
// isimlendirmeden ÖNCE burada görünmelidir.
//
// Kayıt, otoritesi trust manifest'inin İÇİNDEDİR (`identities` dizisi, §4.2.2):
// trust epoch'u ≥M kök anahtarla imzalandığında kayıt da geçişli olarak
// doğrulanır. Bu paket kaydın TİPLERİNİ (Identity/EncKey/SigningKey/Grant),
// grant çözümleme mantığını, enrollment kayıtlarını ve — bağımsız test/araç
// kullanımı için — admin-imzalı, byte-exact bir kayıt anlık görüntüsünü
// (Snapshot) sağlar.
//
// KATİ KURAL (SPEC §3.6.3): imza, depolanan TAM baytların SHA-256'sı üzerinedir;
// doğrulayıcı ham baytları hash'ler ve imzayı body JSON'unu PARSE ETMEDEN
// doğrular. Kripto primitifleri cryptoid'den YENİDEN KULLANILIR — burada
// çoğaltılmaz.
package registry

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// Şema tanımlayıcıları.
const (
	// SchemaRegistry, bağımsız (admin-imzalı) kayıt anlık görüntüsü şeması.
	SchemaRegistry = "wapps-registry/v1"
)

// Kimlik tipleri (SPEC §4.3).
const (
	TypeHuman   = "human"
	TypeMachine = "machine"
	TypeEscrow  = "escrow"
)

// Durum (status) değerleri (SPEC §4.3).
const (
	StatusActive      = "active"
	StatusOffboarding = "offboarding"
	StatusRevoked     = "revoked"
)

// Şifreleme (enc) anahtarı sınıfları (SPEC §4.3 / §3.3).
const (
	EncClassDevice = "device"
	EncClassBackup = "backup"
)

// İmzalama anahtarı sınıfları (SPEC §4.3 / §3.4).
const (
	SignClassRoot       = "root"
	SignClassAdmin      = "admin"
	SignClassDaily      = "daily"
	SignClassAutomation = "automation"
)

// KeyWildcard, bir grant/allowlist'te "tüm anahtarlar" jokeridir.
const KeyWildcard = "*"

// Hata sözleşmesi (SPEC §4.11 / §5.7) — makine okunur, fail-closed. Mesajlar
// ASLA anahtar materyali içermez.
var (
	// ErrIdentityNotEnrolled: bir işlem, doğrulanmış kayıtta bulunmayan bir
	// prensibi isimlendiriyor (SPEC §4.11 IDENTITY_NOT_ENROLLED).
	ErrIdentityNotEnrolled = errors.New("registry: IDENTITY_NOT_ENROLLED")
	// ErrRegistryInvalid: kayıt yapısal/anlamsal değişmezleri karşılamıyor.
	ErrRegistryInvalid = errors.New("registry: REGISTRY_INVALID")
	// ErrBadSignatureCount: imza kümesi gerekli eşik altında (BAD_SIGNATURE_COUNT).
	ErrBadSignatureCount = errors.New("registry: BAD_SIGNATURE_COUNT")
	// ErrUnsupportedSchema: bilinmeyen schema değeri.
	ErrUnsupportedSchema = errors.New("registry: UNSUPPORTED_SCHEMA")
	// ErrKeyIDMismatch: bir anahtar girdisinin key_id'si, pubkey'inden türetilen
	// parmak izine (§3.7) uymuyor. Tamper/typo koruması.
	ErrKeyIDMismatch = errors.New("registry: KEY_ID_MISMATCH")
)

// EncKey, bir kimliğin age X25519 şifreleme alıcısıdır (SPEC §4.3). Pubkey,
// canonical bech32 recipient string'idir (age1... / age1se1... / age1yubikey1...).
type EncKey struct {
	KeyID   string `json:"key_id"`   // §3.7 parmak izi (recipient string üzerinden)
	Class   string `json:"class"`    // device | backup
	Pubkey  string `json:"pubkey"`   // age1... (bech32)
	Media   string `json:"media"`    // secure-enclave | yubikey | software | paper-steel
	AddedAt uint64 `json:"added_at"` // eklendiği admin_epoch
	Status  string `json:"status"`   // active | revoked
}

// SigningKey, bir kimliğin imzalama anahtarıdır (SPEC §4.3 / §3.4). Pubkey,
// ham public key baytlarının base64'üdür (Ed25519 32B, P-256 65B SEC1).
type SigningKey struct {
	KeyID  string `json:"key_id"` // §3.7 parmak izi (ham pubkey baytları üzerinden)
	Class  string `json:"class"`  // root | admin | daily | automation
	Alg    string `json:"alg"`    // ed25519 | ecdsa-p256-sha256
	Pubkey string `json:"pubkey"` // base64(ham pubkey baytları)
	Media  string `json:"media"`
	Status string `json:"status"` // active | revoked
}

// Identity, kayıttaki tek bir prensiptir (SPEC §4.3).
type Identity struct {
	ID          string       `json:"id"`           // "human:<email>" | "machine:<name>" | "escrow:<name>"
	Type        string       `json:"type"`         // human | machine | escrow
	EncKeys     []EncKey     `json:"enc_keys"`     // age X25519 alıcıları
	SigningKeys []SigningKey `json:"signing_keys"` // §3.4 sınıfları
	Status      string       `json:"status"`       // active | offboarding | revoked
	EnrolledAt  time.Time    `json:"enrolled_at"`
	VouchedBy   []string     `json:"vouched_by"`          // kefil admin identity ID'leri
	RotateBy    *time.Time   `json:"rotate_by,omitempty"` // makine: enrolled_at + 90g (ZORUNLU)
}

// Grant, bir prensibe bir projede verilen okuma/yazma yetkisidir (SPEC §4.3 /
// §6.3). Keys, anahtar allowlist'idir; ["*"] tüm anahtarlar demektir.
type Grant struct {
	Principal string   `json:"principal"` // identity ID
	Project   string   `json:"project"`
	Verbs     []string `json:"verbs"` // get | set | apply | exec | ...
	Keys      []string `json:"keys"`  // allowlist; ["*"] = tümü
}

// WriterAllow, bir otomasyon kimliğinin per-proje anahtar yazma allowlist'idir
// (SPEC §4.3 / §6). Örn. machine:tofu-sync-vaulter yalnızca TF-output anahtarlarını
// yazabilir.
type WriterAllow struct {
	Principal string   `json:"principal"`
	Project   string   `json:"project"`
	Keys      []string `json:"keys"`
}

// Snapshot, kaydın bağımsız, admin-imzalanabilir bir görünümüdür (SPEC §4.3).
// Otoritatif kopya trust manifest'in içindedir; bu anlık görüntü araç/test ve
// "registry sign/verify" akışları içindir.
type Snapshot struct {
	Schema           string        `json:"schema"`
	Identities       []Identity    `json:"identities"`
	Grants           []Grant       `json:"grants"`
	WriterAllowlists []WriterAllow `json:"writer_allowlists"`
}

// --- Parmak izi türetme (cryptoid §3.7 yeniden kullanımı) ---

// Fingerprint, bir imzalama anahtarının §3.7 parmak izini ham pubkey
// baytlarından hesaplar (base64 çöz → cryptoid.Fingerprint).
func (k SigningKey) Fingerprint() (string, error) {
	raw, err := base64.StdEncoding.DecodeString(k.Pubkey)
	if err != nil {
		return "", fmt.Errorf("registry.SigningKey.Fingerprint: decode pubkey: %w", err)
	}
	return cryptoid.Fingerprint(raw), nil
}

// Fingerprint, bir şifreleme anahtarının §3.7 parmak izini recipient string
// üzerinden hesaplar.
func (k EncKey) Fingerprint() string {
	return cryptoid.FingerprintRecipient(k.Pubkey)
}

// --- Yapıcılar (test/araç ergonomisi; cryptoid tiplerini yeniden kullanır) ---

// NewSigningKeyEntry, bir cryptoid imzalama anahtarından kayıt girdisi kurar;
// KeyID'yi §3.7'ye göre doldurur.
func NewSigningKeyEntry(k cryptoid.SigningKey, class, media string) SigningKey {
	return SigningKey{
		KeyID:  k.KeyID(),
		Class:  class,
		Alg:    k.Alg(),
		Pubkey: base64.StdEncoding.EncodeToString(k.PublicKeyBytes()),
		Media:  media,
		Status: StatusActive,
	}
}

// NewEncKeyEntry, bir age alıcısından şifreleme kayıt girdisi kurar.
func NewEncKeyEntry(rec *cryptoid.X25519Recipient, class, media string, addedAt uint64) EncKey {
	return EncKey{
		KeyID:   rec.Fingerprint(),
		Class:   class,
		Pubkey:  rec.String(),
		Media:   media,
		AddedAt: addedAt,
		Status:  StatusActive,
	}
}

// --- Grant çözümleme ---

// IdentityByID, verilen ID'ye sahip kimliği döner.
func (s *Snapshot) IdentityByID(id string) (*Identity, bool) {
	for i := range s.Identities {
		if s.Identities[i].ID == id {
			return &s.Identities[i], true
		}
	}
	return nil, false
}

// GrantsFor, bir prensibin bir projedeki tüm grant'larını döner.
func (s *Snapshot) GrantsFor(principal, project string) []Grant {
	var out []Grant
	for _, g := range s.Grants {
		if g.Principal == principal && g.Project == project {
			out = append(out, g)
		}
	}
	return out
}

// VerbAllowed, prensibin projede verb'ü çalıştırmaya yetkili olup olmadığını
// döner (herhangi bir eşleşen grant yeterli).
func (s *Snapshot) VerbAllowed(principal, project, verb string) bool {
	for _, g := range s.GrantsFor(principal, project) {
		if containsStr(g.Verbs, verb) {
			return true
		}
	}
	return false
}

// KeyAllowed, prensibin projede belirli bir anahtara grant allowlist'i
// üzerinden erişebildiğini döner ("*" = tümü).
func (s *Snapshot) KeyAllowed(principal, project, key string) bool {
	for _, g := range s.GrantsFor(principal, project) {
		if keyMatches(g.Keys, key) {
			return true
		}
	}
	return false
}

// WriterKeyAllowed, bir otomasyon kimliğinin projede belirli bir anahtarı
// YAZMAYA yetkili olduğunu writer_allowlists üzerinden döner (SPEC §6).
func (s *Snapshot) WriterKeyAllowed(principal, project, key string) bool {
	for _, w := range s.WriterAllowlists {
		if w.Principal == principal && w.Project == project && keyMatches(w.Keys, key) {
			return true
		}
	}
	return false
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// keyMatches, allowlist bir anahtarı kapsıyor mu? "*" joker tümünü kapsar.
func keyMatches(allow []string, key string) bool {
	for _, a := range allow {
		if a == KeyWildcard || a == key {
			return true
		}
	}
	return false
}

// --- Doğrulama (yapısal + anlamsal değişmezler, SPEC §4.3) ---

// Validate, kaydın §4.3 kurallarını denetler: benzersiz ID'ler, insan device+
// backup enc + daily signing zorunluluğu, makine rotate_by zorunluluğu, escrow'un
// imzalama anahtarı taşımaması, key_id ↔ pubkey tutarlılığı ve grant/allowlist'in
// yalnızca kayıtlı kimlikleri isimlendirmesi.
func (s *Snapshot) Validate() error {
	seen := map[string]bool{}
	for i := range s.Identities {
		id := &s.Identities[i]
		if id.ID == "" || id.Type == "" || id.Status == "" {
			return fmt.Errorf("registry.Validate: identity %d missing id/type/status: %w", i, ErrRegistryInvalid)
		}
		if seen[id.ID] {
			return fmt.Errorf("registry.Validate: duplicate identity %q: %w", id.ID, ErrRegistryInvalid)
		}
		seen[id.ID] = true
		if err := validateIdentity(id); err != nil {
			return err
		}
	}
	// Grant'lar yalnızca kayıtlı, aktif kimlikleri isimlendirebilir.
	for _, g := range s.Grants {
		if g.Project == "" || len(g.Verbs) == 0 {
			return fmt.Errorf("registry.Validate: grant for %q missing project/verbs: %w", g.Principal, ErrRegistryInvalid)
		}
		principal, ok := s.IdentityByID(g.Principal)
		if !ok {
			return fmt.Errorf("registry.Validate: grant names unknown principal %q: %w", g.Principal, ErrIdentityNotEnrolled)
		}
		if principal.Status == StatusRevoked {
			return fmt.Errorf("registry.Validate: grant names revoked principal %q: %w", g.Principal, ErrRegistryInvalid)
		}
		// P3-a: MAKİNE prensipleri joker ("*") anahtar grant'ı TAŞIYAMAZ — makine
		// yetkisi AÇIK, tam-anahtar allowlist'i olmalı (blast-radius sınırlama, §4.3/§6).
		// Bir tofu-sync makinesinin "*" grant'ı, tek bir sızmış otomasyon anahtarını
		// projedeki HER değere erişim/yazıma çevirirdi.
		if principal.Type == TypeMachine && containsStr(g.Keys, KeyWildcard) {
			return fmt.Errorf("registry.Validate: machine grant %q must use an explicit key allowlist, not %q: %w", g.Principal, KeyWildcard, ErrRegistryInvalid)
		}
	}
	for _, w := range s.WriterAllowlists {
		principal, ok := s.IdentityByID(w.Principal)
		if !ok {
			return fmt.Errorf("registry.Validate: writer allowlist names unknown principal %q: %w", w.Principal, ErrIdentityNotEnrolled)
		}
		// P3-a: makine yazar-allowlist'i de joker taşıyamaz (aynı gerekçe).
		if principal.Type == TypeMachine && containsStr(w.Keys, KeyWildcard) {
			return fmt.Errorf("registry.Validate: machine writer allowlist %q must use an explicit key allowlist, not %q: %w", w.Principal, KeyWildcard, ErrRegistryInvalid)
		}
	}
	return nil
}

func validateIdentity(id *Identity) error {
	// Anahtar girdilerinin key_id ↔ pubkey tutarlılığı (tamper/typo koruması).
	for _, ek := range id.EncKeys {
		if ek.Pubkey == "" {
			return fmt.Errorf("registry.Validate: identity %q enc key empty pubkey: %w", id.ID, ErrRegistryInvalid)
		}
		if ek.KeyID != "" && ek.KeyID != ek.Fingerprint() {
			return fmt.Errorf("registry.Validate: identity %q enc key_id mismatch: %w", id.ID, ErrKeyIDMismatch)
		}
	}
	for _, sk := range id.SigningKeys {
		fp, err := sk.Fingerprint()
		if err != nil {
			return fmt.Errorf("registry.Validate: identity %q signing key: %w", id.ID, ErrRegistryInvalid)
		}
		if sk.KeyID != "" && sk.KeyID != fp {
			return fmt.Errorf("registry.Validate: identity %q signing key_id mismatch: %w", id.ID, ErrKeyIDMismatch)
		}
	}

	switch id.Type {
	case TypeHuman:
		// İnsanlar EN AZ bir aktif device VE bir backup enc anahtarı kaydetmeli;
		// backup her wrap-set'e grant anında dahil edilir (SPEC §4.3 / §3.3.2).
		if !hasActiveEnc(id.EncKeys, EncClassDevice) {
			return fmt.Errorf("registry.Validate: human %q needs an active device enc key: %w", id.ID, ErrRegistryInvalid)
		}
		if !hasEnc(id.EncKeys, EncClassBackup) {
			return fmt.Errorf("registry.Validate: human %q needs a backup enc key: %w", id.ID, ErrRegistryInvalid)
		}
		// İnsanlar bir daily-class (no-presence) imzalama anahtarı kaydetmeli.
		if !hasSigning(id.SigningKeys, SignClassDaily) {
			return fmt.Errorf("registry.Validate: human %q needs a daily signing key: %w", id.ID, ErrRegistryInvalid)
		}
	case TypeMachine:
		// Makine kimliklerinde rotate_by ZORUNLUDUR (enrolled_at + 90g, §4.3).
		if id.RotateBy == nil {
			return fmt.Errorf("registry.Validate: machine %q must set rotate_by: %w", id.ID, ErrRegistryInvalid)
		}
		if !hasActiveEnc(id.EncKeys, EncClassDevice) {
			return fmt.Errorf("registry.Validate: machine %q needs a software enc key: %w", id.ID, ErrRegistryInvalid)
		}
	case TypeEscrow:
		// Escrow tek bir X25519 pubkey kimliğidir; imzalama anahtarı taşımaz ve
		// asla yazar olamaz (SPEC §4.3 / §3.3.4).
		if len(id.SigningKeys) != 0 {
			return fmt.Errorf("registry.Validate: escrow %q must have no signing keys: %w", id.ID, ErrRegistryInvalid)
		}
		if len(id.EncKeys) == 0 {
			return fmt.Errorf("registry.Validate: escrow %q needs an enc key: %w", id.ID, ErrRegistryInvalid)
		}
	default:
		return fmt.Errorf("registry.Validate: identity %q unknown type %q: %w", id.ID, id.Type, ErrRegistryInvalid)
	}
	return nil
}

func hasActiveEnc(ks []EncKey, class string) bool {
	for _, k := range ks {
		if k.Class == class && k.Status == StatusActive {
			return true
		}
	}
	return false
}

func hasEnc(ks []EncKey, class string) bool {
	for _, k := range ks {
		if k.Class == class {
			return true
		}
	}
	return false
}

func hasSigning(ks []SigningKey, class string) bool {
	for _, k := range ks {
		if k.Class == class && k.Status == StatusActive {
			return true
		}
	}
	return false
}

// --- Byte-exact serileştirme + imza/doğrulama (SPEC §3.6, admin-imzalı kayıt) ---

// MarshalCanonical, kayıt anlık görüntüsünü DETERMİNİSTİK baytlar olarak seri
// hale getirir: diziler stabil bir anahtara göre sıralanır, HTML-escape kapalıdır
// ve baytlar BİR KEZ üretilir. DİKKAT: bu YALNIZCA imzalayan tarafın baytları
// üretmesi içindir; doğrulama ASLA yeniden serileştirmez (SPEC §3.6.3).
func (s *Snapshot) MarshalCanonical() ([]byte, error) {
	out := *s
	ids := append([]Identity(nil), s.Identities...)
	sort.Slice(ids, func(i, j int) bool { return ids[i].ID < ids[j].ID })
	out.Identities = ids

	grants := append([]Grant(nil), s.Grants...)
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Principal != grants[j].Principal {
			return grants[i].Principal < grants[j].Principal
		}
		return grants[i].Project < grants[j].Project
	})
	out.Grants = grants

	was := append([]WriterAllow(nil), s.WriterAllowlists...)
	sort.Slice(was, func(i, j int) bool {
		if was[i].Principal != was[j].Principal {
			return was[i].Principal < was[j].Principal
		}
		return was[i].Project < was[j].Project
	})
	out.WriterAllowlists = was

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&out); err != nil {
		return nil, fmt.Errorf("registry.MarshalCanonical: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseSnapshotBody, ham body baytlarını Snapshot'a ayrıştırır. YALNIZCA imza
// doğrulandıktan SONRA çağrılmalıdır (SPEC §3.6.3 doğrulama sırası).
func ParseSnapshotBody(body []byte) (*Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("registry.ParseSnapshotBody: %w", err)
	}
	if s.Schema != SchemaRegistry {
		return nil, fmt.Errorf("registry.ParseSnapshotBody: %q: %w", s.Schema, ErrUnsupportedSchema)
	}
	return &s, nil
}

// SignSnapshot, kaydı kanonik olarak seri hale getirir ve verilen admin
// imzalama anahtar(lar)ıyla TAM baytlar üzerinde imzalar (SPEC §4.5: kayıt
// değişikliği = 1 admin presence imzası; test/araç için N imza desteklenir).
func SignSnapshot(s *Snapshot, keys ...cryptoid.SigningKey) (cryptoid.SignedObject, []byte, error) {
	if len(keys) == 0 {
		return cryptoid.SignedObject{}, nil, fmt.Errorf("registry.SignSnapshot: %w", ErrBadSignatureCount)
	}
	body, err := s.MarshalCanonical()
	if err != nil {
		return cryptoid.SignedObject{}, nil, err
	}
	sigs := make([]cryptoid.Signature, 0, len(keys))
	for _, k := range keys {
		sig, err := k.Sign(body)
		if err != nil {
			return cryptoid.SignedObject{}, nil, fmt.Errorf("registry.SignSnapshot: %w", err)
		}
		sigs = append(sigs, sig)
	}
	return cryptoid.SignedObject{Bytes: body, Sigs: sigs}, body, nil
}

// VerifySnapshot, imzalı bir kayıt anlık görüntüsünü doğrular ve body'yi
// ayrıştırır. Doğrulama SIRASI KATİDİR (SPEC §3.6.3): SHA-256(Bytes) üzerinde
// EN AZ `threshold` FARKLI ve geçerli admin imzası aranır (ring = key_id →
// VerifierKey); ANCAK bundan sonra body parse edilir. Bilinen bir anahtarın
// bozuk imzası tamper'dır ve ErrSigInvalid ile reddedilir.
func VerifySnapshot(obj cryptoid.SignedObject, ring map[string]cryptoid.VerifierKey, threshold int) (*Snapshot, error) {
	if threshold < 1 {
		threshold = 1
	}
	seen := map[string]bool{}
	count := 0
	for _, sig := range obj.Sigs {
		vk, ok := ring[sig.KeyID]
		if !ok {
			continue // yabancı/yetkisiz anahtar → sayılmaz (fail-closed)
		}
		if seen[sig.KeyID] {
			continue // aynı anahtar iki kez sayılmaz
		}
		if err := cryptoid.VerifySignatureEnvelope(obj.Bytes, sig, vk); err != nil {
			continue // geçersiz imza sayılmaz (tamper → eşik altı → red)
		}
		seen[sig.KeyID] = true
		count++
	}
	if count < threshold {
		return nil, ErrBadSignatureCount
	}
	return ParseSnapshotBody(obj.Bytes)
}
