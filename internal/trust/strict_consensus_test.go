package trust

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// TestParseTrustBody_NonCanonicalRootPubkey (FIX #1): kök anahtar pubkey'i KATİ
// KANONİK base64 (B64Strict) olmalı — Worker buildSignerView de kök pubkey'i
// b64ToBytes ile KATİ çözer; non-canonical bir spelling iki tarafta ayrışmamalı.
func TestParseTrustBody_NonCanonicalRootPubkey(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	r0, r1, r2 := edFromSeed(t, 0x10), edFromSeed(t, 0x11), edFromSeed(t, 0x12)
	m := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	body, err := m.MarshalCanonical()
	require.NoError(t, err)

	// Temiz body parse edilmeli.
	_, err = ParseTrustBody(body)
	require.NoError(t, err)

	// Bir kök pubkey'inin kanonik base64'ünü bul ve gömülü newline enjekte et
	// (encoding/json ATLARDI → gevşek; KATİ decoder REDDEDER).
	pk := base64.StdEncoding.EncodeToString(m.Roots[0].Pubkey)
	require.Contains(t, string(body), `"`+pk+`"`)
	nonCanon := `"` + pk[:4] + `\n` + pk[4:] + `"` // JSON escaped newline → çözünce gerçek \n
	tampered := strings.Replace(string(body), `"`+pk+`"`, nonCanon, 1)

	_, err = ParseTrustBody([]byte(tampered))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64)
}

// TestParseTrustBody_NullRootPubkey (GO-1): kök anahtar pubkey'i JSON `null` OLAMAZ —
// ZORUNLU imzalı bir string alanıdır; Worker parseTrustBody `str(ro.pubkey)` de bir
// string bekler. KATİ ŞEKİL geçidi null'ı (ve yokluğu) MEVCUT-string gereğiyle reddeder
// (ErrNotJSONString), B64Strict'in null-only ErrMissingBase64'ünü ÖNCELER. İki taraf da
// pubkey:null'ı reddeder → consensus korunur (yalnızca iç hata kodu değişir).
func TestParseTrustBody_NullRootPubkey(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	r0, r1, r2 := edFromSeed(t, 0x10), edFromSeed(t, 0x11), edFromSeed(t, 0x12)
	m := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	body, err := m.MarshalCanonical()
	require.NoError(t, err)

	// Bir kök pubkey'inin kanonik base64'ünü JSON `null` ile değiştir.
	pk := base64.StdEncoding.EncodeToString(m.Roots[0].Pubkey)
	require.Contains(t, string(body), `"`+pk+`"`)
	tampered := strings.Replace(string(body), `"`+pk+`"`, `null`, 1)

	_, err = ParseTrustBody([]byte(tampered))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONString)
}

// TestParseTrustBody_AddedAtDomain (FIX #2): admin_epoch dışındaki imzalı tamsayılar
// da (burada enc_keys[].added_at) JS güvenli-tamsayı alanını [0, 2^53-1] paylaşmalı.
// Tipli uint64 alan >2^53'ü tam taşırdı; whole-body tarama (Worker assertCanonical
// IntegerJSON paritesi) bunu yakalar: 2^53-1 kabul, 2^53 red.
func TestParseTrustBody_AddedAtDomain(t *testing.T) {
	build := func(addedAt uint64) []byte {
		a := newAdminHuman(t, "adnan@wapps.dev")
		r0, r1, r2 := edFromSeed(t, 0x10), edFromSeed(t, 0x11), edFromSeed(t, 0x12)
		m := rosterManifest(1, "", ChangeRoster, 2, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
		require.NotEmpty(t, m.Identities[0].EncKeys)
		m.Identities[0].EncKeys[0].AddedAt = addedAt
		body, err := m.MarshalCanonical()
		require.NoError(t, err)
		return body
	}

	// Sınır değeri 2^53-1: kabul.
	_, err := ParseTrustBody(build(uint64(1<<53 - 1)))
	require.NoError(t, err)

	// 2^53: red.
	_, err = ParseTrustBody(build(uint64(1 << 53)))
	assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalJSONNumber)
}

// tamperTrust, temiz bir roster body üretir ve gövde metninde bir alt-dizeyi
// değiştirerek (KATİ-şekil ihlali enjekte etmek için) bozar. ParseTrustBody imza
// doğrulamaz → gövdeyi doğrudan bozmak KATİ-şekil geçidini test etmeye yeter.
func tamperTrust(t *testing.T, old, new string) []byte {
	t.Helper()
	body := trustBodyForParse(t, 1)
	s := string(body)
	require.Contains(t, s, old, "fixture must contain %q", old)
	return []byte(strings.Replace(s, old, new, 1))
}

// TestParseTrustBody_StrictShape (strict-shape): created_at (F1), bootstrap_solo,
// quorum, ve iç string alanlarının KATİ tip/varlık denetimi — Worker str/bool/obj
// paritesi. encoding/json null'ı string→"" / bool→false / struct→zero'ya sessizce
// çözerdi → Go-kabul/Worker-red bölünmesi; KATİ ŞEKİL geçidi bunu kapatır.
func TestParseTrustBody_StrictShape(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want error
	}{
		// F1: created_at null/number → red (Go time.Time null'ı sessizce zero'ya çözerdi).
		{"created_at null", tamperTrust(t, `"created_at":"2026-07-09T12:00:00Z"`, `"created_at":null`), cryptoid.ErrNotJSONString},
		{"created_at number", tamperTrust(t, `"created_at":"2026-07-09T12:00:00Z"`, `"created_at":123`), cryptoid.ErrNotJSONString},
		// bootstrap_solo null / string → red (Go bool null'ı false'a çözerdi).
		{"bootstrap_solo null", tamperTrust(t, `"bootstrap_solo":true`, `"bootstrap_solo":null`), cryptoid.ErrNotJSONBool},
		{"bootstrap_solo string", tamperTrust(t, `"bootstrap_solo":true`, `"bootstrap_solo":"true"`), cryptoid.ErrNotJSONBool},
		// quorum null → red (Go struct null'ı zero {0,0}'a çözerdi).
		{"quorum null", tamperTrust(t, `"quorum":{`, `"quorum":null,"x":{`), cryptoid.ErrNotJSONObject},
		// prev_trust_sha256 null → red (imzalı string).
		{"prev_trust null", tamperTrust(t, `"prev_trust_sha256":""`, `"prev_trust_sha256":null`), cryptoid.ErrNotJSONString},
		// change_class null → red.
		{"change_class null", tamperTrust(t, `"change_class":"roster"`, `"change_class":null`), cryptoid.ErrNotJSONString},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTrustBody(tc.body)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

// TestParseTrustBody_EmptyKeyID_F3 (F3): roots/enc_keys/signing_keys[].key_id BOŞ
// string ("") OLAMAZ — boş key_id, offboard self-authorize authz-deliğini açardı.
// Consensus-safe: TS tarafı da "" reddedecek. Non-empty string zorunlu.
func TestParseTrustBody_EmptyKeyID_F3(t *testing.T) {
	// Bir root key_id'sini "" yap. Fixture'ın root key_id'leri "sha256:..." biçimindedir;
	// gövdedeki ilk `"key_id":"sha256:` başlangıcını boş string yapmak yerine, herhangi bir
	// key_id değerini "" ile değiştirmek için ilk key_id alanını hedefle.
	body := trustBodyForParse(t, 1)
	s := string(body)
	// İlk key_id alanının değerini "" yap (root veya enc/signing — hepsi non-empty olmalı).
	idx := strings.Index(s, `"key_id":"`)
	require.GreaterOrEqual(t, idx, 0)
	end := strings.Index(s[idx+len(`"key_id":"`):], `"`)
	require.GreaterOrEqual(t, end, 0)
	val := s[idx+len(`"key_id":"`) : idx+len(`"key_id":"`)+end]
	tampered := strings.Replace(s, `"key_id":"`+val+`"`, `"key_id":""`, 1)
	_, err := ParseTrustBody([]byte(tampered))
	assert.ErrorIs(t, err, cryptoid.ErrEmptyJSONString)
}

// TestParseTrustBody_NormalizedArraysAccepted (round-5 preserve): admins ve
// identities[].vouched_by için null/yok/[] HEPSİ kabul edilir + eşdeğerdir; ayrıca
// grants/writer_allowlists container'ları null'ı kabul eder (Go nil slice `null` emit
// eder → Go KENDİ çıktısını reddetmemeli). Over-reject = yeni divergence, YASAK.
func TestParseTrustBody_NormalizedArraysAccepted(t *testing.T) {
	// admins:null → kabul.
	_, err := ParseTrustBody(tamperTrust(t, `"admins":["human:adnan@wapps.dev"]`, `"admins":null`))
	require.NoError(t, err)
	// admins:[] → kabul.
	_, err = ParseTrustBody(tamperTrust(t, `"admins":["human:adnan@wapps.dev"]`, `"admins":[]`))
	require.NoError(t, err)
	// grants:null (fixture zaten null emit eder) → kabul: temiz body parse edilmeli.
	body := trustBodyForParse(t, 1)
	require.Contains(t, string(body), `"grants":null`)
	_, err = ParseTrustBody(body)
	require.NoError(t, err)
}

// TestParseTrustBody_ContainerNonArrayRejected: container dizileri null'ı kabul eder
// ama non-array (obje) reddeder (TS arr() paritesi).
func TestParseTrustBody_ContainerNonArrayRejected(t *testing.T) {
	_, err := ParseTrustBody(tamperTrust(t, `"grants":null`, `"grants":{}`))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONArray)
}
