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
	"io"
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
	// ErrTrailingContent: imzalı body'de tek JSON değerinden SONRA fazladan içerik
	// var (COORD c). Worker'ın JSON.parse'ı böyle bir gövdeyi reddeder; Go
	// json.Decoder ise io.EOF kontrol edilmedikçe sessizce kabul ederdi.
	ErrTrailingContent = errors.New("manifest: TRAILING_CONTENT")
	// ErrIntegerOutOfRange: epoch/trustEpoch/keyVersion tamsayısı JS güvenli-tamsayı
	// alanını [0, 2^53-1] aşıyor (COORD a). İki taraf aynı alanı paylaşsın diye.
	ErrIntegerOutOfRange = errors.New("manifest: INTEGER_OUT_OF_RANGE")
	// ErrRequiredArrayInvalid: ZORUNLU imzalı bir dizi alanı (`entries` ve her
	// girdinin `wraps`'ı) JSON `null`, YOK veya bir dizi DEĞİL (COORD b). Worker
	// Array.isArray ile bunları reddeder; encoding/json ise `null`/yokluğu SESSİZCE
	// nil dilime çözer ve döngü onları atlar → Go-kabul/Worker-red bölünmesi.
	// Boş `[]` İZİNLİDİR (Worker de izin verir); yalnızca null/yokluk/non-array red.
	ErrRequiredArrayInvalid = errors.New("manifest: REQUIRED_ARRAY_INVALID")
)

// manifestCap, imzalı sarmalayıcı üst sınırı (SPEC §5.7): 1 MB.
const manifestCap = 1_048_576

// maxSafeInteger, JS Number güvenli-tamsayı üst sınırıdır (2^53 - 1). epoch,
// trustEpoch ve keyVersion bu değeri AŞAMAZ (COORD a): Worker JSON sayılarını
// double olarak okur ve MAX_SAFE_INTEGER üstünü reddeder; Go uint64 daha fazlasını
// tutabildiği için burada açıkça reddedilmeli — böylece iki taraf aynı [0, 2^53-1]
// tamsayı alanını paylaşır.
const maxSafeInteger uint64 = 1<<53 - 1

// SignedObject ve Signature, imzalı sarmalayıcı tipleridir. Kanonik tanımları
// (imza zarfı, SPEC §3.6) cryptoid paketindedir; §5.4.4 bunları manifest'te
// konumlandırır, burada alias'larla yeniden dışa aktarılır.
type (
	SignedObject = cryptoid.SignedObject
	Signature    = cryptoid.Signature
)

// DEKWrap, bir manifest girdisinin DEK wrap-set üyesidir (SPEC §5.4.4).
// Wrap alanı Go JSON'da base64'tür: DEK'in tek-alıcılı age v1 şifrelemesi. KATİ
// KANONİK (B64Strict): wrap-set byte-exact karşılaştırıldığından ve Worker de aynı
// alanı KATİ okuduğundan, non-canonical bir spelling iki tarafta ayrışmamalı (COORD a).
type DEKWrap struct {
	Recipient string             `json:"recipient"` // şifreleme-pubkey parmak izi (§3.7)
	Wrap      cryptoid.B64Strict `json:"wrap"`      // base64 (KATİ KANONİK); DEK'in X25519 seal'i
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
	// KATİ ŞEKİL (strict-shape): tipli decode'dan ÖNCE ham şekil doğrulaması. `entries`
	// ve her girdinin `wraps`'ı JSON dizisi OLMALI (null/yok/non-array RED; boş [] izinli);
	// ayrıca imzalı string alanları (project, prevManifestSha256, createdAt, entries[].
	// keyName/blobHash, wraps[].recipient) MEVCUT JSON string ve uint alanları (epoch,
	// trustEpoch, keyVersion) MEVCUT sayı OLMALI. encoding/json null/yokluğu sessizce
	// ""/0/nil'e çözerdi; Worker str/asUint/Array.isArray ile reddeder → bu gate hizalar.
	// Tek değer okuyan Decoder kullanılır → trailing içeriğe dokunmaz (o COORD c'de).
	if err := validateManifestShape(body); err != nil {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %w", err)
	}
	var m DataManifest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %w", err)
	}
	// COORD (c): tek JSON değerinden SONRA fazladan içerik (token/çöp) reddedilir.
	// İkinci bir Decode io.EOF döndürmeli; başka her şey (yeni değer veya sözdizim
	// hatası) trailing içeriktir. Worker'ın JSON.parse'ı da böyle bir gövdeyi reddeder.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %w", ErrTrailingContent)
	}
	if m.Schema != SchemaDataManifest {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %q: %w", m.Schema, ErrUnsupportedSchema)
	}
	// COORD (a): tamsayı alanları JS güvenli-tamsayı alanını [0, 2^53-1] aşamaz.
	if m.Epoch > maxSafeInteger {
		return nil, fmt.Errorf("manifest.ParseManifestBody: epoch %d exceeds max safe integer: %w", m.Epoch, ErrIntegerOutOfRange)
	}
	if m.TrustEpoch > maxSafeInteger {
		return nil, fmt.Errorf("manifest.ParseManifestBody: trustEpoch %d exceeds max safe integer: %w", m.TrustEpoch, ErrIntegerOutOfRange)
	}
	for _, e := range m.Entries {
		if e.KeyVersion > maxSafeInteger {
			return nil, fmt.Errorf("manifest.ParseManifestBody: keyVersion %d exceeds max safe integer: %w", e.KeyVersion, ErrIntegerOutOfRange)
		}
	}
	// COORD (a): tipli alan kontrolleri yalnızca struct alanlarını kapsar; rotation
	// passthrough (json.RawMessage) içindeki sayılar denetlenmezdi. Worker tüm body
	// metnini tarar → parite için ham body'deki HER sayı token'ı kanonik tamsayı
	// biçiminde + [0, 2^53-1] içinde olmalı.
	if err := cryptoid.AssertCanonicalIntegerJSON(body); err != nil {
		return nil, fmt.Errorf("manifest.ParseManifestBody: %w", err)
	}
	return &m, nil
}

// validateManifestShape, ham body içinde imzalı alanların KATİ şeklini tipli
// decode'dan ÖNCE doğrular: ZORUNLU dizi alanları (`entries` + her girdinin `wraps`'ı)
// JSON dizisi (null/yok/non-array RED; boş [] izinli, Worker Array.isArray paritesi);
// imzalı string alanları MEVCUT JSON string (Worker asString paritesi — null/yokluğu
// encoding/json sessizce ""'e çözerdi); imzalı uint alanları MEVCUT sayı (Worker
// asUint paritesi — yokluğu Go 0'a çözerdi). Tipli decode bu gap'leri sessizce
// yuttuğu için bu kontrol tipli decode'dan ÖNCE gerekir.
func validateManifestShape(body []byte) error {
	// Tek değer okuyan Decoder → trailing içeriğe dokunmaz (o COORD c'de ele alınır).
	var top struct {
		Schema  *json.RawMessage `json:"schema"`
		Project *json.RawMessage `json:"project"`
		Epoch   *json.RawMessage `json:"epoch"`
		PrevSha *json.RawMessage `json:"prevManifestSha256"`
		TrustEp *json.RawMessage `json:"trustEpoch"`
		Created *json.RawMessage `json:"createdAt"`
		Entries *json.RawMessage `json:"entries"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&top); err != nil {
		// Bozuk/gövdesiz JSON: tipli decode zaten reddedecek; burada da red.
		return fmt.Errorf("manifest shape: %w", err)
	}
	// strict-string (Worker asString): schema/project/prevManifestSha256/createdAt.
	// prevManifestSha256 "" olabilir (genesis) ama STRING olmalı; createdAt'in RFC3339
	// katılığı tipli time.Time decode'unda yaptırılır — burada yalnızca VARLIK + string.
	for _, f := range []struct {
		name string
		raw  *json.RawMessage
	}{
		{"schema", top.Schema}, {"project", top.Project}, {"prevManifestSha256", top.PrevSha}, {"createdAt", top.Created},
	} {
		if err := cryptoid.RequireJSONString(f.raw); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	// strict-uint varlığı (Worker asUint): epoch/trustEpoch. Kanoniklik+aralık
	// AssertCanonicalIntegerJSON + range-check'te yaptırılır.
	if err := cryptoid.RequireJSONNumber(top.Epoch); err != nil {
		return fmt.Errorf("epoch: %w", err)
	}
	if err := cryptoid.RequireJSONNumber(top.TrustEp); err != nil {
		return fmt.Errorf("trustEpoch: %w", err)
	}
	// entries: ZORUNLU dizi (manifest.ts `Array.isArray` — null/yok/non-array red).
	if err := requireJSONArray(top.Entries); err != nil {
		return fmt.Errorf("entries: %w", err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(*top.Entries, &entries); err != nil {
		return fmt.Errorf("entries elements: %w", err)
	}
	for i := range entries {
		if err := validateEntryShape(entries[i]); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
	}
	return nil
}

// validateEntryShape, bir manifest girdisinin KATİ şeklini doğrular. `wraps` ZORUNLU
// dizi (ErrRequiredArrayInvalid; entries:[null]/skaler girdi ilk burada yakalanır —
// mevcut testlerle geriye-uyum); keyName/blobHash strict-string; keyVersion strict-uint
// varlığı; her wrap için recipient strict-string ve wrap alanı MEVCUT (null/non-canonical
// wrap tipli B64Strict decode'unda ErrMissingBase64/ErrNonCanonicalBase64 üretir → o
// katmana bırakılır; burada yalnızca YOKLUK yakalanır).
func validateEntryShape(elem json.RawMessage) error {
	var e struct {
		KeyName    *json.RawMessage `json:"keyName"`
		KeyVersion *json.RawMessage `json:"keyVersion"`
		BlobHash   *json.RawMessage `json:"blobHash"`
		Wraps      *json.RawMessage `json:"wraps"`
	}
	// Girdi bir obje olmalı; `null`/dizi/skaler bir girdi (ör. entries:[null]) wraps'ı
	// çözemez → wraps yok → ErrRequiredArrayInvalid (mevcut test paritesi).
	if err := json.Unmarshal(elem, &e); err != nil {
		return ErrRequiredArrayInvalid
	}
	// wraps ÖNCE (entries:[null] → ErrRequiredArrayInvalid geriye-uyum).
	if err := requireJSONArray(e.Wraps); err != nil {
		return fmt.Errorf("wraps: %w", err)
	}
	if err := cryptoid.RequireJSONString(e.KeyName); err != nil {
		return fmt.Errorf("keyName: %w", err)
	}
	if err := cryptoid.RequireJSONString(e.BlobHash); err != nil {
		return fmt.Errorf("blobHash: %w", err)
	}
	if err := cryptoid.RequireJSONNumber(e.KeyVersion); err != nil {
		return fmt.Errorf("keyVersion: %w", err)
	}
	var wraps []json.RawMessage
	if err := json.Unmarshal(*e.Wraps, &wraps); err != nil {
		return fmt.Errorf("wraps: %w", ErrRequiredArrayInvalid)
	}
	for j := range wraps {
		var w struct {
			Recipient *json.RawMessage `json:"recipient"`
			Wrap      *json.RawMessage `json:"wrap"`
		}
		if err := json.Unmarshal(wraps[j], &w); err != nil {
			return fmt.Errorf("wrap %d: %w", j, cryptoid.ErrNotJSONObject)
		}
		if err := cryptoid.RequireJSONString(w.Recipient); err != nil {
			return fmt.Errorf("wrap %d recipient: %w", j, err)
		}
		// wrap YOKLUĞU (missing) yakalanır; null/non-canonical B64Strict'e bırakılır ki
		// mevcut ErrMissingBase64/ErrNonCanonicalBase64 hata sözleşmesi korunsun.
		if w.Wrap == nil {
			return fmt.Errorf("wrap %d wrap: %w", j, cryptoid.ErrNotJSONString)
		}
	}
	return nil
}

// requireJSONArray, bir *json.RawMessage'ın MEVCUT ve JSON dizisi ([) olduğunu
// doğrular. nil pointer = alan YOK; "null" = null; '[' dışı ilk bayt = non-array.
// Hepsi ErrRequiredArrayInvalid. Boş [] geçerlidir. Ham mesaj, dış decode tarafından
// zaten iyi-biçimli tek bir JSON değeri olarak doğrulanmıştır → ilk bayt tip için yeter.
func requireJSONArray(raw *json.RawMessage) error {
	if raw == nil { // alan yok
		return ErrRequiredArrayInvalid
	}
	trimmed := bytes.TrimSpace(*raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || trimmed[0] != '[' {
		return ErrRequiredArrayInvalid
	}
	return nil
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
