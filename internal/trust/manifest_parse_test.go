package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustBodyForParse, ParseTrustBody testleri için tek başına bir roster body üretir
// (imza gerekmez; ParseTrustBody imza doğrulamaz, yalnızca gövdeyi ayrıştırır).
func trustBodyForParse(t *testing.T, epoch uint64) []byte {
	t.Helper()
	a := newAdminHuman(t, "adnan@wapps.dev")
	r0, r1, r2 := edFromSeed(t, 0x10), edFromSeed(t, 0x11), edFromSeed(t, 0x12)
	m := rosterManifest(epoch, "", ChangeRoster, 2, holdingsOf(a.id, r0, r1, r2), []adminHuman{a})
	body, err := m.MarshalCanonical()
	require.NoError(t, err)
	return body
}

// TestParseTrustBody_TrailingContent, imzalı body'den SONRA fazladan içerik
// (geçerli JSON VEYA çöp) reddedildiğini doğrular (COORD c). Worker JSON.parse
// böyle bir gövdeyi reddeder; Go json.Decoder io.EOF kontrol edilmeden kabul ederdi.
func TestParseTrustBody_TrailingContent(t *testing.T) {
	body := trustBodyForParse(t, 1)

	// Temiz body parse edilmeli.
	_, err := ParseTrustBody(body)
	require.NoError(t, err)

	// Sonda geçerli bir JSON değeri → red.
	trailingJSON := append(append([]byte(nil), body...), []byte("\n{}")...)
	_, err = ParseTrustBody(trailingJSON)
	assert.ErrorIs(t, err, ErrTrailingContent)

	// Sonda çöp → red.
	trailingGarbage := append(append([]byte(nil), body...), []byte(" not-json")...)
	_, err = ParseTrustBody(trailingGarbage)
	assert.ErrorIs(t, err, ErrTrailingContent)
}

// TestParseTrustBody_AdminEpochDomain, admin_epoch'un JS güvenli-tamsayı alanıyla
// [0, 2^53-1] sınırlı olduğunu doğrular (COORD a): 2^53-1 kabul, 2^53 red.
func TestParseTrustBody_AdminEpochDomain(t *testing.T) {
	// Sınır değeri (2^53-1) kabul edilmeli.
	okBody := trustBodyForParse(t, uint64(1<<53-1))
	_, err := ParseTrustBody(okBody)
	require.NoError(t, err)

	// 2^53 reddedilmeli.
	overBody := trustBodyForParse(t, uint64(1<<53))
	_, err = ParseTrustBody(overBody)
	assert.ErrorIs(t, err, ErrEpochOutOfRange)
}
