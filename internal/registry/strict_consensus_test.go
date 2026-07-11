package registry

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
)

// TestSigningKey_DecodePubkey_Strict (FIX #1): imzalama-anahtarı pubkey'inin (byte-exact
// string olarak saklanır) HER yorumlaması — DecodePubkey + Fingerprint — KATİ KANONİK
// base64'ten geçmeli. Gevşek bir decode (encoding/json / base64.StdEncoding NON-strict)
// non-canonical bir spelling'i kabul edip Go-kabul/Worker-red bölünmesi yaratırdı.
func TestSigningKey_DecodePubkey_Strict(t *testing.T) {
	key, err := cryptoid.GenerateEd25519()
	require.NoError(t, err)
	sk := NewSigningKeyEntry(key, SignClassDaily, "software")

	// Kanonik pubkey: DecodePubkey ham baytları, Fingerprint doğru parmak izini döner.
	raw, err := sk.DecodePubkey()
	require.NoError(t, err)
	assert.Equal(t, key.PublicKeyBytes(), raw)
	fp, err := sk.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, key.KeyID(), fp)

	// Non-canonical spelling'ler: hem DecodePubkey hem Fingerprint reddeder.
	for _, bad := range []string{
		"//9=",     // non-canonical son-bayt bitleri (StdEncoding KABUL ederdi)
		"aGVsbG8",  // padding'siz
		"BN\nLu==", // gömülü newline (encoding/json ATLARDI)
	} {
		sk.Pubkey = bad
		_, err := sk.DecodePubkey()
		assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64, "DecodePubkey(%q) must reject", bad)
		_, err = sk.Fingerprint()
		assert.ErrorIs(t, err, cryptoid.ErrNonCanonicalBase64, "Fingerprint(%q) must reject", bad)
	}
}

// snapshotBody, geçerli bir kayıt anlık görüntüsünün kanonik gövdesini üretir
// (imza gerekmez; ParseSnapshotBody imza doğrulamaz). Tamper testleri için.
func snapshotBody(t *testing.T) []byte {
	t.Helper()
	human, _ := humanIdentity(t, "adnan@wapps.dev")
	s := &Snapshot{
		Schema:     SchemaRegistry,
		Identities: []Identity{human, machineIdentity(t, "tofu-sync")},
		Grants: []Grant{
			{Principal: human.ID, Project: "vaulter", Verbs: []string{"get"}, Keys: []string{"*"}},
		},
		WriterAllowlists: []WriterAllow{
			{Principal: "machine:tofu-sync", Project: "vaulter", Keys: []string{"TF_OUT"}},
		},
	}
	body, err := s.MarshalCanonical()
	require.NoError(t, err)
	return body
}

// TestParseSnapshotBody_StrictShape (strict-shape, savunma katmanı): identity/grant/
// writer element'lerinin KATİ tip denetimi trust manifest'iyle PAYLAŞILIR — id null
// (strict-string), grants[].verbs null (F2 strArr), key_id "" (F3) reddedilir.
func TestParseSnapshotBody_StrictShape(t *testing.T) {
	tamper := func(old, new string) []byte {
		s := string(snapshotBody(t))
		require.Contains(t, s, old)
		return []byte(strings.Replace(s, old, new, 1))
	}

	// F2: grants[].verbs null → red (strArr; Go []string null'ı nil'e çözüp atlardı).
	_, err := ParseSnapshotBody(tamper(`"verbs":["get"]`, `"verbs":null`))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONStringArray)

	// F2: verbs eleman-string-dışı ([123]) → red.
	_, err = ParseSnapshotBody(tamper(`"verbs":["get"]`, `"verbs":[123]`))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONStringArray)

	// F2: writer_allowlists[].keys null → red.
	_, err = ParseSnapshotBody(tamper(`"keys":["TF_OUT"]`, `"keys":null`))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONStringArray)

	// F3: bir key_id "" → red (non-empty zorunlu).
	body := string(snapshotBody(t))
	idx := strings.Index(body, `"key_id":"`)
	require.GreaterOrEqual(t, idx, 0)
	end := strings.Index(body[idx+len(`"key_id":"`):], `"`)
	val := body[idx+len(`"key_id":"`) : idx+len(`"key_id":"`)+end]
	_, err = ParseSnapshotBody([]byte(strings.Replace(body, `"key_id":"`+val+`"`, `"key_id":""`, 1)))
	assert.ErrorIs(t, err, cryptoid.ErrEmptyJSONString)

	// strict-string: identity id null → red.
	_, err = ParseSnapshotBody(tamper(`"id":"human:adnan@wapps.dev"`, `"id":null`))
	assert.ErrorIs(t, err, cryptoid.ErrNotJSONString)

	// Kontrol: temiz gövde parse edilmeli.
	_, err = ParseSnapshotBody(snapshotBody(t))
	require.NoError(t, err)
}
