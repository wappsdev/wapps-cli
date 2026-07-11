package trust

// Bu dosya, trust manifest'inin (ve gömülü epoch_reset kaydının) KATİ ŞEKİL
// (strict-shape) doğrulamasını sağlar — tipli decode'dan ÖNCE HER imzalı alanın
// doğru JSON tipinde + VAR olduğunu denetler (TS trust.ts parseTrustBody paritesi:
// str/uint/bool/obj/arr/strArr). Go encoding/json bir string alanına null/yokluğu
// sessizce ""'e, bir bool'a null'ı false'a, bir struct'a null'ı zero'ya, bir slice'a
// null'ı nil'e çözerdi → Worker `str()`/`bool()`/`obj()`/`strArr()` reddiyle "Go-kabul
// / Worker-red" bölünmesi. Bu geçit onu kapatır. Kayıt (identity/grant/writer) element
// şekilleri registry paketinde paylaşılır (ParseSnapshotBody ile tek kaynak).
//
// KRİTİK NORMALİZE semantiği (round-5): admins ve identities[].vouched_by null/yok/[]
// hepsi KABUL + eşdeğer; roots/identities/grants/writer_allowlists container dizileri
// de null'ı KABUL eder (Go MarshalCanonical nil slice'ı `null` emit eder → Go KENDİ
// imzalı çıktısını reddetmemeli). Bu yüzden bunlar strict-array DEĞİL, normalize
// container-dizidir (non-array reddedilir, null kabul edilir; TS `arr()` paritesi).

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/registry"
)

// validateTrustShape, trust manifest gövdesinin KATİ şeklini tipli decode'dan ÖNCE
// doğrular (TS parseTrustBody paritesi). Trailing içerik ÖZEL EOF kontrolüne
// bırakılır (Decoder tek değer okur).
func validateTrustShape(body []byte) error {
	var top struct {
		Schema        *json.RawMessage `json:"schema"`
		AdminEpoch    *json.RawMessage `json:"admin_epoch"`
		PrevTrust     *json.RawMessage `json:"prev_trust_sha256"`
		CreatedAt     *json.RawMessage `json:"created_at"`
		ChangeClass   *json.RawMessage `json:"change_class"`
		BootstrapSolo *json.RawMessage `json:"bootstrap_solo"`
		Quorum        *json.RawMessage `json:"quorum"`
		Roots         *json.RawMessage `json:"roots"`
		Admins        *json.RawMessage `json:"admins"`
		Identities    *json.RawMessage `json:"identities"`
		Grants        *json.RawMessage `json:"grants"`
		WriterAllow   *json.RawMessage `json:"writer_allowlists"`
		ReceiptPub    *json.RawMessage `json:"worker_receipt_pubkey"`
		MintPubs      *json.RawMessage `json:"worker_mint_pubkeys"`
		EpochReset    *json.RawMessage `json:"epoch_reset"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&top); err != nil {
		return fmt.Errorf("trust shape: %w", err)
	}

	// strict-string (TS `str()`): null/yok/non-string → red.
	for _, f := range []struct {
		name string
		raw  *json.RawMessage
	}{
		{"schema", top.Schema},
		{"prev_trust_sha256", top.PrevTrust},
		{"created_at", top.CreatedAt}, // RFC3339 katılığı tipli time.Time decode'unda
		{"change_class", top.ChangeClass},
	} {
		if err := cryptoid.RequireJSONString(f.raw); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	// strict-uint varlığı (TS `uint()` yokluğu reddeder); aralık/kanoniklik
	// AssertCanonicalIntegerJSON + admin_epoch range-check'te yaptırılır.
	if err := cryptoid.RequireJSONNumber(top.AdminEpoch); err != nil {
		return fmt.Errorf("admin_epoch: %w", err)
	}
	// strict-bool (TS `bool()`): bootstrap_solo null/yok/non-bool → red.
	if err := cryptoid.RequireJSONBool(top.BootstrapSolo); err != nil {
		return fmt.Errorf("bootstrap_solo: %w", err)
	}
	// quorum: MEVCUT non-null obje (TS `obj()`) + m/n strict-uint varlığı.
	if err := cryptoid.RequireJSONObject(top.Quorum); err != nil {
		return fmt.Errorf("quorum: %w", err)
	}
	var q struct {
		M *json.RawMessage `json:"m"`
		N *json.RawMessage `json:"n"`
	}
	if err := json.Unmarshal(*top.Quorum, &q); err != nil {
		return fmt.Errorf("quorum: %w", cryptoid.ErrNotJSONObject)
	}
	if err := cryptoid.RequireJSONNumber(q.M); err != nil {
		return fmt.Errorf("quorum.m: %w", err)
	}
	if err := cryptoid.RequireJSONNumber(q.N); err != nil {
		return fmt.Errorf("quorum.n: %w", err)
	}
	// admins: normalize string-dizi (null/yok/[] kabul; string-dışı eleman red).
	if err := cryptoid.NullableJSONStringArray(top.Admins); err != nil {
		return fmt.Errorf("admins: %w", err)
	}
	// roots: normalize container-dizi; her eleman şekil-denetimli (F3 key_id non-empty).
	if err := cryptoid.ForEachElemNullable(top.Roots, func(i int, e json.RawMessage) error {
		if err := validateRootShape(e); err != nil {
			return fmt.Errorf("roots[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	// identities/grants/writer_allowlists: registry ile paylaşılan element şekilleri.
	if err := cryptoid.ForEachElemNullable(top.Identities, func(i int, e json.RawMessage) error {
		if err := registry.ValidateIdentityShape(e); err != nil {
			return fmt.Errorf("identities[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := cryptoid.ForEachElemNullable(top.Grants, func(i int, e json.RawMessage) error {
		if err := registry.ValidateGrantShape(e); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := cryptoid.ForEachElemNullable(top.WriterAllow, func(i int, e json.RawMessage) error {
		if err := registry.ValidateWriterAllowShape(e); err != nil {
			return fmt.Errorf("writer_allowlists[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return err
	}
	// worker_receipt_pubkey: OPSİYONEL tek ReceiptKey (null/yok → KABUL, Go zero-value
	// paritesi); MEVCUT ise KATİ ReceiptKey şekli (TS validateReceiptField). Go tipli
	// decode `kid:null`/`alg:null`'ı zero-string kabul ederdi → Worker `str()` reddiyle
	// bölünürdü (codex round-7).
	if !cryptoid.IsAbsentOrNull(top.ReceiptPub) {
		if err := validateReceiptKeyShape(*top.ReceiptPub); err != nil {
			return fmt.Errorf("worker_receipt_pubkey: %w", err)
		}
	}
	// worker_mint_pubkeys: NORMALİZE dizi (null/yok/[] KABUL); MEVCUT non-null ise dizi
	// OLMALI ve HER eleman KATİ ReceiptKey (null eleman → obj() reddi; codex round-7:
	// Go `[null]`'ı zero ReceiptKey kabul ederdi, TS reddeder).
	if err := cryptoid.ForEachElemNullable(top.MintPubs, func(i int, e json.RawMessage) error {
		if err := validateReceiptKeyShape(e); err != nil {
			return fmt.Errorf("worker_mint_pubkeys[%d]: %w", i, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("worker_mint_pubkeys: %w", err)
	}
	// epoch_reset: OPSİYONEL (null/yok → yok sayılır); MEVCUT ise KATİ şekil (§4.8).
	if !cryptoid.IsAbsentOrNull(top.EpochReset) {
		if err := validateEpochResetShape(top.EpochReset); err != nil {
			return fmt.Errorf("epoch_reset: %w", err)
		}
	}
	return nil
}

// validateReceiptKeyShape, bir ReceiptKey ({kid,alg,jwk}) elemanının TS
// validateReceiptKey paritesini yaptırır: MEVCUT non-null obje; YALNIZCA {kid,alg,jwk}
// anahtarları (unknown → red, exactKeys paritesi); kid/alg VARSA non-null string (yoksa
// serbest — TS `if (o.x !== undefined) str(o.x)`); jwk opak (herhangi JSON, denetlenmez).
func validateReceiptKeyShape(elem json.RawMessage) error {
	re := elem
	if err := cryptoid.RequireJSONObject(&re); err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(elem, &m); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	for k := range m {
		if k != "kid" && k != "alg" && k != "jwk" {
			return fmt.Errorf("unknown field %q: %w", k, cryptoid.ErrNotJSONObject)
		}
	}
	// kid/alg: anahtar VARSA (TS undefined-değil) non-null string olmalı; JSON'da
	// mevcut-null bir anahtar map'te bulunur ("null" değeriyle) → RequireJSONString reddeder.
	if raw, ok := m["kid"]; ok {
		r := raw
		if err := cryptoid.RequireJSONString(&r); err != nil {
			return fmt.Errorf("kid: %w", err)
		}
	}
	if raw, ok := m["alg"]; ok {
		r := raw
		if err := cryptoid.RequireJSONString(&r); err != nil {
			return fmt.Errorf("alg: %w", err)
		}
	}
	return nil
}

// validateRootShape, bir roots[] elemanının şeklini doğrular: key_id non-empty
// strict-string (F3); alg/pubkey/media/holder/status strict-string. pubkey ham 32B
// Ed25519'un base64'üdür → strict-string burada; KATİ KANONİK base64 tipli B64Strict
// decode'unda + buildSignerView'da yaptırılır.
func validateRootShape(elem json.RawMessage) error {
	var r struct {
		KeyID  *json.RawMessage `json:"key_id"`
		Alg    *json.RawMessage `json:"alg"`
		Pubkey *json.RawMessage `json:"pubkey"`
		Media  *json.RawMessage `json:"media"`
		Holder *json.RawMessage `json:"holder"`
		Status *json.RawMessage `json:"status"`
	}
	if err := json.Unmarshal(elem, &r); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	if err := cryptoid.RequireJSONStringNonEmpty(r.KeyID); err != nil {
		return fmt.Errorf("key_id: %w", err)
	}
	for _, f := range []struct {
		name string
		raw  *json.RawMessage
	}{
		{"alg", r.Alg}, {"pubkey", r.Pubkey}, {"media", r.Media}, {"holder", r.Holder}, {"status", r.Status},
	} {
		if err := cryptoid.RequireJSONString(f.raw); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	return nil
}

// validateEpochResetShape, gömülü epoch_reset kaydının KATİ şeklini doğrular (§4.8,
// TS parseEpochReset paritesi): schema/reset_id/reason/snapshot_ref strict-string;
// prior_chain MEVCUT obje; prior_chain.last_admin_epoch strict-uint varlığı;
// prior_chain.last_trust_sha256 strict-string.
func validateEpochResetShape(raw *json.RawMessage) error {
	if err := cryptoid.RequireJSONObject(raw); err != nil {
		return err
	}
	var er struct {
		Schema      *json.RawMessage `json:"schema"`
		ResetID     *json.RawMessage `json:"reset_id"`
		Reason      *json.RawMessage `json:"reason"`
		SnapshotRef *json.RawMessage `json:"snapshot_ref"`
		PriorChain  *json.RawMessage `json:"prior_chain"`
	}
	if err := json.Unmarshal(*raw, &er); err != nil {
		return cryptoid.ErrNotJSONObject
	}
	for _, f := range []struct {
		name string
		raw  *json.RawMessage
	}{
		{"schema", er.Schema}, {"reset_id", er.ResetID}, {"reason", er.Reason}, {"snapshot_ref", er.SnapshotRef},
	} {
		if err := cryptoid.RequireJSONString(f.raw); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	if err := cryptoid.RequireJSONObject(er.PriorChain); err != nil {
		return fmt.Errorf("prior_chain: %w", err)
	}
	var pc struct {
		LastAdminEpoch *json.RawMessage `json:"last_admin_epoch"`
		LastTrustSHA   *json.RawMessage `json:"last_trust_sha256"`
	}
	if err := json.Unmarshal(*er.PriorChain, &pc); err != nil {
		return fmt.Errorf("prior_chain: %w", cryptoid.ErrNotJSONObject)
	}
	if err := cryptoid.RequireJSONNumber(pc.LastAdminEpoch); err != nil {
		return fmt.Errorf("prior_chain.last_admin_epoch: %w", err)
	}
	if err := cryptoid.RequireJSONString(pc.LastTrustSHA); err != nil {
		return fmt.Errorf("prior_chain.last_trust_sha256: %w", err)
	}
	return nil
}
