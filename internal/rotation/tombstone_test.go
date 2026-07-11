package rotation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/ageutil"
)

// TestTombstone_OverwritesLegacyAndStaleReadFailsLoud, tombstone'un legacy arşivin
// ÜZERİNE yazıldığını ve bayat bir checkout'un onu çözünce GÜRÜLTÜLÜ başarısız
// olduğunu (ErrArchiveMigrated) kanıtlar (§10.2.7). Eski değerler kaybolur.
func TestTombstone_OverwritesLegacyAndStaleReadFailsLoud(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "all.enc.age")

	// Başlangıçta gerçek bir arşiv (canlı değerler).
	live := fakeLegacyArchive(t, map[string]string{"DB_URL": "postgres://live"})
	require.NoError(t, os.WriteFile(archive, live, 0o600))

	// Tombstone ile ÜZERİNE yaz.
	pt, err := BuildTombstonePlaintext(testProject, "2026-07-20")
	require.NoError(t, err)
	require.NoError(t, WriteTombstone(archive, pt, legacyPass))

	// Bayat okuma: tombstoned arşivi çözen legacy-yol GÜRÜLTÜLÜ başarısız olur.
	onDisk, err := os.ReadFile(archive)
	require.NoError(t, err)
	_, rerr := ReadLegacyOrMigrated(onDisk, legacyPass)
	require.ErrorIs(t, rerr, ErrArchiveMigrated, "stale checkout fails loud instead of using dead values")

	// Sentinel tespit edilir + eski değer GİTTİ.
	sentinel, migrated, derr := DetectMigrated(onDisk, legacyPass)
	require.NoError(t, derr)
	require.True(t, migrated)
	assert.Equal(t, testProject, sentinel.Project)
	assert.Equal(t, "wapps-secrets", sentinel.Store)

	// LegacyArchive.Values de tombstoned arşivde ErrArchiveMigrated döner (cutover
	// tekrar edilemez).
	_, verr := LegacyArchiveFromBytes(onDisk).Values(legacyPass)
	require.ErrorIs(t, verr, ErrArchiveMigrated)

	// Ham çözüm: yalnızca sentinel var, "DB_URL" YOK.
	raw, derr := ageutil.Decrypt(onDisk, legacyPass)
	require.NoError(t, derr)
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	_, hasOld := m["DB_URL"]
	assert.False(t, hasOld, "old value replaced by the tombstone sentinel")
	_, hasSentinel := m[MigratedSentinelKey]
	assert.True(t, hasSentinel)
}

// TestTombstone_IronRuleGuard, IRON RULE'un (§10.5) kod-yaptırımını kanıtlar:
// legacy'e YAZILABİLECEK tek şey __MIGRATED__ tombstone'udur — rotate edilmiş bir
// gizli değer ErrIronRuleViolation ile reddedilir.
func TestTombstone_IronRuleGuard(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "all.enc.age")

	// Rotate edilmiş bir gizli değeri legacy'e yazmaya çalış → REDDEDİLİR.
	rotatedSecret, err := json.Marshal(map[string]map[string]string{"DB_URL": {"value": "rotated-new-secret"}})
	require.NoError(t, err)
	err = WriteTombstone(archive, rotatedSecret, legacyPass)
	require.ErrorIs(t, err, ErrIronRuleViolation, "a rotated value is NEVER written back to a legacy archive")
	_, statErr := os.Stat(archive)
	assert.True(t, os.IsNotExist(statErr), "guard rejects before writing anything")

	// Guard'ı doğrudan sına: çok-anahtarlı (sentinel + başka) da reddedilir.
	twoKeys, _ := json.Marshal(map[string]any{MigratedSentinelKey: map[string]string{}, "EXTRA": "x"})
	require.ErrorIs(t, guardLegacyWrite(twoKeys), ErrIronRuleViolation)

	// Sadece sentinel → izinli.
	pt, err := BuildTombstonePlaintext(testProject, "2026-07-20")
	require.NoError(t, err)
	require.NoError(t, guardLegacyWrite(pt))
	require.NoError(t, WriteTombstone(archive, pt, legacyPass))
}

// TestBuildTombstone_DecryptsToSentinel, BuildTombstone çıktısının legacy passphrase
// ile __MIGRATED__ sentinel'ine çözüldüğünü kanıtlar.
func TestBuildTombstone_DecryptsToSentinel(t *testing.T) {
	blob, err := BuildTombstone(testProject, "2026-07-20", legacyPass)
	require.NoError(t, err)
	sentinel, migrated, err := DetectMigrated(blob, legacyPass)
	require.NoError(t, err)
	require.True(t, migrated)
	assert.Contains(t, sentinel.Action, "wapps secrets exec")
}
