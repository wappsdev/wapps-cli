// Package manifest, wapps-secrets data manifest'inin donmuş (frozen) yapısını
// ve imza/doğrulama/epoch-zinciri yardımcılarını sağlar (SPEC §5.4/§5.5).
//
// Bir data manifest, bir projenin BİR epoch'taki TAM anahtar kümesidir (delta
// DEĞİL). İstemcinin çözmek için ihtiyaç duyduğu her şey (blob bağları, DEK
// wrap'leri, sürümler) ve Worker'ın bir yazım diff'ini yetkilendirmek için
// ihtiyaç duyduğu her şey manifest'in içindedir.
//
// KATİ KURAL (SPEC §3.6.3/§5.4.1): imza, depolanan TAM baytların SHA-256'sı
// üzerinedir. Doğrulayıcı ham baytları hash'ler ve imzayı body JSON'unu PARSE
// ETMEDEN doğrular. Canonical-JSON imzalama sistemin HER YERİNDE YASAKTIR —
// imzalama ile doğrulama arasında hiçbir yeniden-serileştirme adımı yoktur.
// Seri hale getirme baytları BİR KEZ imzalayan tarafından üretilir, sarmalayıcı
// içinde base64 olarak aynen saklanır ve OLDUĞU GİBİ hash'lenir.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// Şema tanımlayıcıları (SPEC §5.4.2, §5.4.4).
const (
	SchemaDataManifest   = "wapps-secrets/data-manifest/v1"
	SchemaCurrentPointer = "wapps-secrets/current/v1"
)

// Manifest-seviyesi hata sözleşmesi (SPEC §5.7). Kripto hataları için
// cryptoid paketinin sentinel'leri yeniden kullanılır.
var (
	// ErrBadSignatureCount: data manifest sigs uzunluğu != 1 (BAD_SIGNATURE_COUNT).
	ErrBadSignatureCount = errors.New("manifest: BAD_SIGNATURE_COUNT")
	// ErrUnsupportedSchema: bilinmeyen schema değeri (UNSUPPORTED_SCHEMA).
	ErrUnsupportedSchema = errors.New("manifest: UNSUPPORTED_SCHEMA")
	// ErrProjectMismatch: body project != beklenen (PROJECT_MISMATCH).
	ErrProjectMismatch = errors.New("manifest: PROJECT_MISMATCH")
	// ErrEpochConflict: epoch != prev+1 veya prevManifestSha256 uyuşmuyor
	// (EPOCH_CONFLICT).
	ErrEpochConflict = errors.New("manifest: EPOCH_CONFLICT")
	// ErrWriterUnknown: sigs[0].key_id trust roster'da çözülemedi.
	ErrWriterUnknown = errors.New("manifest: WRITER_UNKNOWN")
	// ErrManifestTooLarge: imzalı sarmalayıcı 1 MB kapasitesini aştı.
	ErrManifestTooLarge = errors.New("manifest: MANIFEST_TOO_LARGE")
)

// manifestCap, imzalı sarmalayıcı üst sınırı (SPEC §5.7): 1 MB.
const manifestCap = 1_048_576

// SignedObject ve Signature, imzalı sarmalayıcı tipleridir. Kanonik tanımları
// (imza zarfı, SPEC §3.6) cryptoid paketindedir; §5.4.4 bunları manifest'te
// konumlandırır, burada alias'larla yeniden dışa aktarılır.
type (
	SignedObject = cryptoid.SignedObject
	Signature    = cryptoid.Signature
)

// DEKWrap, bir manifest girdisinin DEK wrap-set üyesidir (SPEC §5.4.4).
// Wrap alanı Go JSON'da base64'tür: DEK'in tek-alıcılı age v1 şifrelemesi.
type DEKWrap struct {
	Recipient string `json:"recipient"` // şifreleme-pubkey parmak izi (§3.7)
	Wrap      []byte `json:"wrap"`      // base64; DEK'in X25519 seal'i
}

// RotationMeta, OPSİYONEL yazar-yazımlı rotasyon metadatasıdır (SPEC §5.4.3
// rule 5; şema §8.6.2). Worker tarafından ASLA yorumlanmaz; her manifest baytı
// gibi imzalanır ve girdiyle taşınır. Byte-exact korumak için ham JSON
// passthrough olarak modellenir.
type RotationMeta struct {
	raw json.RawMessage
}

// NewRotationMeta, ham JSON'dan bir RotationMeta kurar.
func NewRotationMeta(raw []byte) *RotationMeta {
	rm := &RotationMeta{raw: append(json.RawMessage(nil), raw...)}
	return rm
}

// Raw, saklanan ham JSON baytlarını döner.
func (r RotationMeta) Raw() json.RawMessage { return r.raw }

func (r RotationMeta) MarshalJSON() ([]byte, error) {
	if len(r.raw) == 0 {
		return []byte("null"), nil
	}
	return r.raw, nil
}

func (r *RotationMeta) UnmarshalJSON(b []byte) error {
	r.raw = append(r.raw[:0], b...)
	return nil
}

// KeyEntry, manifest'teki bir anahtar girdisidir (SPEC §5.4.3/§5.4.4).
type KeyEntry struct {
	KeyName    string        `json:"keyName"`
	KeyVersion uint64        `json:"keyVersion"`
	BlobHash   string        `json:"blobHash"` // depolanan blob objesinin çıplak-hex SHA-256'sı
	Wraps      []DEKWrap     `json:"wraps"`
	Rotation   *RotationMeta `json:"rotation,omitempty"` // §8.6.2
}

// DataManifest, imzalı tutarlılık birimidir (SPEC §5.4.2/§5.4.4).
type DataManifest struct {
	Schema             string     `json:"schema"` // "wapps-secrets/data-manifest/v1"
	Project            string     `json:"project"`
	Epoch              uint64     `json:"epoch"`
	PrevManifestSha256 string     `json:"prevManifestSha256"` // hex; "" iff Epoch == 1
	TrustEpoch         uint64     `json:"trustEpoch"`
	CreatedAt          time.Time  `json:"createdAt"`
	Entries            []KeyEntry `json:"entries"` // KeyName'e göre artan sıralı
}

// MarshalCanonical, manifest body'sini DETERMİNİSTİK baytlar olarak seri hale
// getirir: girdiler KeyName'e göre (bytewise) artan sıralanır, HTML-escape
// kapalıdır ve baytlar BİR KEZ üretilir. DİKKAT: bu YALNIZCA imzalayan tarafın
// baytları üretmesi içindir; doğrulama ASLA yeniden serileştirmez, depolanan
// baytları OLDUĞU GİBİ hash'ler (SPEC §5.4.1).
func (m *DataManifest) MarshalCanonical() ([]byte, error) {
	out := *m
	// Girdileri kopyala ve KeyName'e göre bytewise sırala (stabil diff).
	entries := make([]KeyEntry, len(m.Entries))
	copy(entries, m.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].KeyName < entries[j].KeyName
	})
	out.Entries = entries

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&out); err != nil {
		return nil, fmt.Errorf("manifest.MarshalCanonical: %w", err)
	}
	// json.Encoder her Encode'da sona '\n' ekler; kaldır ki baytlar kesin olsun.
	b := bytes.TrimRight(buf.Bytes(), "\n")
	return b, nil
}

// ParseManifestBody, ham body baytlarını DataManifest'e ayrıştırır. Bu YALNIZCA
// imza doğrulandıktan SONRA çağrılmalıdır (SPEC §3.6.3 doğrulama sırası).
func ParseManifestBody(body []byte) (*DataManifest, error) {
	var m DataManifest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %w", err)
	}
	if m.Schema != SchemaDataManifest {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %q: %w", m.Schema, ErrUnsupportedSchema)
	}
	return &m, nil
}

// SignManifest, manifest body'sini kanonik olarak seri hale getirir, yazarın
// imzalama anahtarıyla TAM baytlar üzerinde imzalar ve imzalı sarmalayıcıyı
// döner (SPEC §5.4.1). Data manifest TAM BİR imza taşır.
func SignManifest(m *DataManifest, key cryptoid.SigningKey) (SignedObject, []byte, error) {
	body, err := m.MarshalCanonical()
	if err != nil {
		return SignedObject{}, nil, err
	}
	sig, err := key.Sign(body)
	if err != nil {
		return SignedObject{}, nil, fmt.Errorf("manifest.SignManifest: %w", err)
	}
	obj := SignedObject{Bytes: body, Sigs: []Signature{sig}}
	return obj, body, nil
}

// MarshalSignedObject, imzalı sarmalayıcıyı R2'ye yazılacak baytlara serileştirir
// ve 1 MB kapasitesini kontrol eder (SPEC §5.7).
func MarshalSignedObject(obj SignedObject) ([]byte, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("manifest.MarshalSignedObject: %w", err)
	}
	if len(raw) > manifestCap {
		return nil, ErrManifestTooLarge
	}
	return raw, nil
}

// ParseSignedObject, depolanan sarmalayıcı baytlarını SignedObject'e ayrıştırır.
func ParseSignedObject(raw []byte) (SignedObject, error) {
	var obj SignedObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return SignedObject{}, fmt.Errorf("manifest.ParseSignedObject: %w", err)
	}
	return obj, nil
}

// WriterKeyring, key_id → doğrulama anahtarı çözümlemesidir (trust roster'ın,
// §4, bu paketin dışındaki bir görünümü). VerifyDataManifest bunu kullanır.
type WriterKeyring map[string]cryptoid.VerifierKey

// VerifyDataManifest, imzalı bir data manifest sarmalayıcısını doğrular ve
// body'yi ayrıştırır. Doğrulama SIRASI KATİDİR (SPEC §3.6.3):
//  1. Tam olarak 1 imza olmalı (yoksa BAD_SIGNATURE_COUNT).
//  2. key_id trust roster'da çözülmeli (yoksa WRITER_UNKNOWN).
//  3. SHA-256(obj.Bytes) üzerinde imza doğrulanmalı — body PARSE EDİLMEDEN.
//  4. ANCAK O ZAMAN body JSON olarak ayrıştırılır.
//
// Herhangi bir imza hatası cryptoid.ErrSigInvalid'dir ve nesne YOK sayılmalıdır
// (fail-closed) — asla eski/imzasız bir nesneye düşülmez.
func VerifyDataManifest(obj SignedObject, ring WriterKeyring) (*DataManifest, error) {
	if len(obj.Sigs) != 1 {
		return nil, ErrBadSignatureCount
	}
	sig := obj.Sigs[0]
	vk, ok := ring[sig.KeyID]
	if !ok {
		return nil, ErrWriterUnknown
	}
	// (3) İmzayı ham depolanan baytlar üzerinde, parse ETMEDEN doğrula.
	if err := cryptoid.VerifySignatureEnvelope(obj.Bytes, sig, vk); err != nil {
		return nil, err
	}
	// (4) Ancak şimdi body'yi ayrıştır.
	return ParseManifestBody(obj.Bytes)
}

// --- Epoch zinciri (SPEC §5.5) ---

// ManifestObjectHash, depolanan imzalı-sarmalayıcı baytlarının çıplak-hex
// SHA-256'sıdır. prevManifestSha256 ve CurrentPointer.ManifestSha256 bu değeri
// taşır — body değil, TAM obje baytları (SPEC §5.4.2/§5.5).
func ManifestObjectHash(storedWrapperBytes []byte) string {
	sum := sha256.Sum256(storedWrapperBytes)
	return hex.EncodeToString(sum[:])
}

// VerifyGenesis, genesis manifest'in zincir kurallarını doğrular (SPEC §5.4.2):
// epoch == 1 ve prevManifestSha256 == "".
func VerifyGenesis(cur *DataManifest) error {
	if cur.Epoch != 1 {
		return fmt.Errorf("manifest.VerifyGenesis: epoch %d != 1: %w", cur.Epoch, ErrEpochConflict)
	}
	if cur.PrevManifestSha256 != "" {
		return fmt.Errorf("manifest.VerifyGenesis: prevManifestSha256 must be empty: %w", ErrEpochConflict)
	}
	return nil
}

// VerifyChainLink, cur'un prev'in halefi olduğunu doğrular (SPEC §5.5):
// cur.Epoch == prevEpoch+1 VE cur.PrevManifestSha256 == SHA-256(prev obje
// baytları). Uyumsuzluk EPOCH_CONFLICT'tir.
func VerifyChainLink(prevStoredWrapperBytes []byte, prevEpoch uint64, cur *DataManifest) error {
	if cur.Epoch != prevEpoch+1 {
		return fmt.Errorf("manifest.VerifyChainLink: epoch %d != %d+1: %w", cur.Epoch, prevEpoch, ErrEpochConflict)
	}
	want := ManifestObjectHash(prevStoredWrapperBytes)
	if cur.PrevManifestSha256 != want {
		return fmt.Errorf("manifest.VerifyChainLink: prevManifestSha256 mismatch: %w", ErrEpochConflict)
	}
	return nil
}

// CheckProject, manifest'in project alanının beklenen path segmentiyle
// eşleştiğini doğrular (SPEC §5.2 rule 1 / §5.4.2).
func CheckProject(cur *DataManifest, expectedProject string) error {
	if cur.Project != expectedProject {
		return fmt.Errorf("manifest.CheckProject: %q != %q: %w", cur.Project, expectedProject, ErrProjectMismatch)
	}
	return nil
}

// CheckEscrowWraps, HER girdinin wrap-set'inde aktif escrow alıcısının
// bulunduğunu doğrular (SPEC §5.4.3 rule 4 / §3.5.4). İstemci tarafı imzadan
// önce bu kontrolü yapmalıdır; eksikse cryptoid.ErrEscrowWrapMissing.
func CheckEscrowWraps(cur *DataManifest, escrowFingerprint string) error {
	for _, e := range cur.Entries {
		found := false
		for _, w := range e.Wraps {
			if w.Recipient == escrowFingerprint {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("manifest.CheckEscrowWraps: entry %q missing escrow wrap: %w", e.KeyName, cryptoid.ErrEscrowWrapMissing)
		}
	}
	return nil
}
