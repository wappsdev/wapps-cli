package rotation

// Ortak test fixture'ları (eski ZK harness'ın KEPT asgari kalıntısı).

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

const testProject = "vaulter-test"

const legacyPass = "correct-horse-battery-staple-16+"

var fixTime = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return fixTime }

// fakeLegacyArchive, tofu-output-şekilli bir legacy age arşivi üretir.
func fakeLegacyArchive(t *testing.T, values map[string]string) []byte {
	t.Helper()
	obj := map[string]map[string]string{}
	for k, v := range values {
		obj[k] = map[string]string{"value": v}
	}
	pt, err := json.Marshal(obj)
	require.NoError(t, err)
	ct, err := ageutil.Encrypt(pt, legacyPass)
	require.NoError(t, err)
	return ct
}
