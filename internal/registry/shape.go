package registry

// Bu dosya, kayıt tiplerinin (Identity/EncKey/SigningKey/Grant/WriterAllow) KATİ
// ŞEKİL (strict-shape) doğrulamasını sağlar — imzalı bir gövdenin tipli decode'dan
// ÖNCE her alanının doğru JSON tipinde ve VAR olduğunu denetler (TS trust.ts
// `str`/`strArr`/`arr`/`uint` paritesi). Bu şekil-denetimleri HEM trust manifest'i
// (ParseTrustBody, kaydı gömülü taşır) HEM bağımsız kayıt anlık görüntüsü
// (ParseSnapshotBody) tarafından paylaşılır → tek kaynak. Go encoding/json bir
// string alanına null/yokluğu sessizce ""'e, bir []string'e null'ı nil'e çözerdi;
// bu denetimler o "Go-kabul / Worker-red" bölünmesini kapatır.

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// ValidateIdentityShape, bir identity JSON elemanının KATİ şeklini doğrular:
// id/type/status strict-string; enc_keys/signing_keys normalize container-dizi
// (her eleman şekil-denetimli); vouched_by normalize string-dizi (null→[] kabul).
// enrolled_at/rotate_by (nullable-rfc3339) burada denetlenmez — tipli time.Time/
// *time.Time decode'u null'ı kabul, non-string non-null'ı reddeder (TS `idTime`
// paritesi), takvim-katılığı Go time.Parse'ta zaten yaptırılır.
func ValidateIdentityShape(elem json.RawMessage) error {
	var id struct {
		ID          *json.RawMessage `json:"id"`
		Type        *json.RawMessage `json:"type"`
		Status      *json.RawMessage `json:"status"`
		EncKeys     *json.RawMessage `json:"enc_keys"`
		SigningKeys *json.RawMessage `json:"signing_keys"`
		VouchedBy   *json.RawMessage `json:"vouched_by"`
	}
	if err := json.Unmarshal(elem, &id); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	if err := cryptoid.RequireJSONString(id.ID); err != nil {
		return fmt.Errorf("id: %w", err)
	}
	if err := cryptoid.RequireJSONString(id.Type); err != nil {
		return fmt.Errorf("type: %w", err)
	}
	if err := cryptoid.RequireJSONString(id.Status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if err := cryptoid.NullableJSONStringArray(id.VouchedBy); err != nil {
		return fmt.Errorf("vouched_by: %w", err)
	}
	if err := cryptoid.ForEachElemNullable(id.EncKeys, func(j int, e json.RawMessage) error {
		if err := validateEncKeyShape(e); err != nil {
			return fmt.Errorf("enc_keys[%d]: %w", j, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := cryptoid.ForEachElemNullable(id.SigningKeys, func(j int, e json.RawMessage) error {
		if err := validateSigningKeyShape(e); err != nil {
			return fmt.Errorf("signing_keys[%d]: %w", j, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// validateEncKeyShape, bir enc_key elemanının şeklini doğrular: key_id non-empty
// strict-string (F3); class/pubkey/media/status strict-string; added_at strict-uint
// (varlık). pubkey age bech32 recipient string'idir (base64 DEĞİL) → yalnızca
// strict-string yaptırılır, kanoniklik EncKey.Fingerprint'te çözülür.
func validateEncKeyShape(elem json.RawMessage) error {
	var ek struct {
		KeyID   *json.RawMessage `json:"key_id"`
		Class   *json.RawMessage `json:"class"`
		Pubkey  *json.RawMessage `json:"pubkey"`
		Media   *json.RawMessage `json:"media"`
		Status  *json.RawMessage `json:"status"`
		AddedAt *json.RawMessage `json:"added_at"`
	}
	if err := json.Unmarshal(elem, &ek); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	if err := cryptoid.RequireJSONStringNonEmpty(ek.KeyID); err != nil {
		return fmt.Errorf("key_id: %w", err)
	}
	if err := cryptoid.RequireJSONString(ek.Class); err != nil {
		return fmt.Errorf("class: %w", err)
	}
	if err := cryptoid.RequireJSONString(ek.Pubkey); err != nil {
		return fmt.Errorf("pubkey: %w", err)
	}
	if err := cryptoid.RequireJSONString(ek.Media); err != nil {
		return fmt.Errorf("media: %w", err)
	}
	if err := cryptoid.RequireJSONString(ek.Status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if err := cryptoid.RequireJSONNumber(ek.AddedAt); err != nil {
		return fmt.Errorf("added_at: %w", err)
	}
	return nil
}

// validateSigningKeyShape, bir signing_key elemanının şeklini doğrular: key_id
// non-empty strict-string (F3); class/alg/pubkey/media/status strict-string.
// pubkey base64'tür → strict-string burada, KATİ KANONİK base64 SigningKey.
// Fingerprint/DecodePubkey'de (ve validateRegistrySemantics'te) yaptırılır.
func validateSigningKeyShape(elem json.RawMessage) error {
	var sk struct {
		KeyID  *json.RawMessage `json:"key_id"`
		Class  *json.RawMessage `json:"class"`
		Alg    *json.RawMessage `json:"alg"`
		Pubkey *json.RawMessage `json:"pubkey"`
		Media  *json.RawMessage `json:"media"`
		Status *json.RawMessage `json:"status"`
	}
	if err := json.Unmarshal(elem, &sk); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	if err := cryptoid.RequireJSONStringNonEmpty(sk.KeyID); err != nil {
		return fmt.Errorf("key_id: %w", err)
	}
	if err := cryptoid.RequireJSONString(sk.Class); err != nil {
		return fmt.Errorf("class: %w", err)
	}
	if err := cryptoid.RequireJSONString(sk.Alg); err != nil {
		return fmt.Errorf("alg: %w", err)
	}
	if err := cryptoid.RequireJSONString(sk.Pubkey); err != nil {
		return fmt.Errorf("pubkey: %w", err)
	}
	if err := cryptoid.RequireJSONString(sk.Media); err != nil {
		return fmt.Errorf("media: %w", err)
	}
	if err := cryptoid.RequireJSONString(sk.Status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	return nil
}

// ValidateGrantShape, bir grant elemanının şeklini doğrular: principal/project
// strict-string; verbs/keys strict-STRING-DİZİSİ (F2: null/yok/string-dışı eleman
// → red; Go []string null'ı sessizce nil'e çözüp atlardı → Worker `strArr` reddi
// ile ayrışırdı).
func ValidateGrantShape(elem json.RawMessage) error {
	var g struct {
		Principal *json.RawMessage `json:"principal"`
		Project   *json.RawMessage `json:"project"`
		Verbs     *json.RawMessage `json:"verbs"`
		Keys      *json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(elem, &g); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	if err := cryptoid.RequireJSONString(g.Principal); err != nil {
		return fmt.Errorf("principal: %w", err)
	}
	if err := cryptoid.RequireJSONString(g.Project); err != nil {
		return fmt.Errorf("project: %w", err)
	}
	if err := cryptoid.RequireJSONStringArray(g.Verbs); err != nil {
		return fmt.Errorf("verbs: %w", err)
	}
	if err := cryptoid.RequireJSONStringArray(g.Keys); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	return nil
}

// ValidateWriterAllowShape, bir writer_allowlist elemanının şeklini doğrular:
// principal/project strict-string; keys strict-STRING-DİZİSİ (F2).
func ValidateWriterAllowShape(elem json.RawMessage) error {
	var w struct {
		Principal *json.RawMessage `json:"principal"`
		Project   *json.RawMessage `json:"project"`
		Keys      *json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(elem, &w); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	if err := cryptoid.RequireJSONString(w.Principal); err != nil {
		return fmt.Errorf("principal: %w", err)
	}
	if err := cryptoid.RequireJSONString(w.Project); err != nil {
		return fmt.Errorf("project: %w", err)
	}
	if err := cryptoid.RequireJSONStringArray(w.Keys); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	return nil
}

// validateSnapshotShape, bağımsız kayıt anlık görüntüsünün (Snapshot) KATİ
// şeklini doğrular. NOT (matrix §4): Worker'da kayıt-anlık-görüntü parser'ı YOKTUR
// → bu bir consensus yüzeyi DEĞİL, yalnızca Go-içi savunma katmanıdır; yine de
// trust manifest'iyle paylaşılan aynı element-şekil denetimleri uygulanır. schema
// strict-string; identities/grants/writer_allowlists normalize container-dizi
// (null→boş kabul, Go nil slice `null` emit ettiği için ZORUNLU).
func validateSnapshotShape(body []byte) error {
	var top struct {
		Schema      *json.RawMessage `json:"schema"`
		Identities  *json.RawMessage `json:"identities"`
		Grants      *json.RawMessage `json:"grants"`
		WriterAllow *json.RawMessage `json:"writer_allowlists"`
	}
	// Decoder (Unmarshal DEĞİL): tek JSON değeri okur, trailing içeriğe DOKUNMAZ →
	// trailing tespiti ParseSnapshotBody'nin özel EOF kontrolüne bırakılır (o katman
	// ErrTrailingContent döndürür; şekil-denetimi onu maskelemez).
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&top); err != nil {
		return fmt.Errorf("snapshot shape: %w", err)
	}
	if err := cryptoid.RequireJSONString(top.Schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	if err := cryptoid.ForEachElemNullable(top.Identities, func(i int, e json.RawMessage) error {
		if err := ValidateIdentityShape(e); err != nil {
			return fmt.Errorf("identities[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := cryptoid.ForEachElemNullable(top.Grants, func(i int, e json.RawMessage) error {
		if err := ValidateGrantShape(e); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := cryptoid.ForEachElemNullable(top.WriterAllow, func(i int, e json.RawMessage) error {
		if err := ValidateWriterAllowShape(e); err != nil {
			return fmt.Errorf("writer_allowlists[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
