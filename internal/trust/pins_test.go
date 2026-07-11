package trust

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withCompiledGenesis, derlenmiş genesis paket-global'lerini test için ayarlar
// ve testten sonra eski hallerine döndürür (paralel testleri kirletmemek için
// t.Cleanup).
func withCompiledGenesis(t *testing.T, p Pin) {
	t.Helper()
	prevSHA, prevEpoch := compiledGenesisSHA256, compiledGenesisEpoch
	t.Cleanup(func() {
		compiledGenesisSHA256 = prevSHA
		compiledGenesisEpoch = prevEpoch
	})
	SetCompiledGenesis(p)
}

func TestDefaultPinPath_HonorsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	p, err := DefaultPinPath()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/xdg/wapps/roots.json", p)
}

// TestPinStore_SaveLoadRoundtrip, kaydet→oku round-trip'i ve 0600 modunu test eder.
func TestPinStore_SaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wapps", "roots.json")

	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	store := &PinStore{
		Schema:       PinSchema,
		Genesis:      Pin{AdminEpoch: 1, SHA256: "aa11"},
		LastVerified: Pin{AdminEpoch: 7, SHA256: "bb22", VerifiedAt: &now},
	}
	require.NoError(t, store.Save(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	loaded, err := LoadPinStore(path)
	require.NoError(t, err)
	assert.Equal(t, store.Genesis, loaded.Genesis)
	assert.Equal(t, uint64(7), loaded.LastVerified.AdminEpoch)
	assert.Equal(t, "bb22", loaded.LastVerified.SHA256)
}

// TestLoadPinStore_Missing, dosya yoksa os.ErrNotExist sarmalayan hata döner.
func TestLoadPinStore_Missing(t *testing.T) {
	_, err := LoadPinStore(filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestAdvanceLastVerified_Monotonic, monotonik yüksek-su-işaretini test eder.
func TestAdvanceLastVerified_Monotonic(t *testing.T) {
	store := NewPinStore(Pin{AdminEpoch: 1, SHA256: "g"})
	// last_verified başlangıçta genesis (epoch 1).
	require.Equal(t, uint64(1), store.LastVerified.AdminEpoch)

	// İleri → kabul.
	require.NoError(t, store.AdvanceLastVerified(Pin{AdminEpoch: 3, SHA256: "e3"}))
	assert.Equal(t, uint64(3), store.LastVerified.AdminEpoch)
	assert.NotNil(t, store.LastVerified.VerifiedAt) // otomatik damgalanır

	// Geriye → downgrade.
	err := store.AdvanceLastVerified(Pin{AdminEpoch: 2, SHA256: "e2"})
	assert.ErrorIs(t, err, ErrTrustDowngrade)
	assert.Equal(t, uint64(3), store.LastVerified.AdminEpoch) // değişmedi

	// Aynı epoch, farklı hash → downgrade (fork).
	err = store.AdvanceLastVerified(Pin{AdminEpoch: 3, SHA256: "DIFFERENT"})
	assert.ErrorIs(t, err, ErrTrustDowngrade)

	// Aynı epoch, aynı hash → kabul (idempotent).
	require.NoError(t, store.AdvanceLastVerified(Pin{AdminEpoch: 3, SHA256: "e3"}))
}

// TestCompiledGenesis_InjectAndConflict, gömülü genesis enjeksiyonu +
// çakışma tespitini test eder.
func TestCompiledGenesis_InjectAndConflict(t *testing.T) {
	// Başlangıçta gömülü pin yok.
	compiledGenesisSHA256, compiledGenesisEpoch = "", ""
	_, ok := CompiledGenesis()
	assert.False(t, ok)

	withCompiledGenesis(t, Pin{AdminEpoch: 1, SHA256: "genesis-hash"})
	got, ok := CompiledGenesis()
	require.True(t, ok)
	assert.Equal(t, "genesis-hash", got.SHA256)
	assert.Equal(t, uint64(1), got.AdminEpoch)

	// Uyumlu roots.json → çakışma yok.
	store := NewPinStore(Pin{AdminEpoch: 1, SHA256: "genesis-hash"})
	require.NoError(t, store.CheckGenesisAgainstCompiled())

	// Uyumsuz genesis → pin conflict.
	bad := NewPinStore(Pin{AdminEpoch: 1, SHA256: "OTHER"})
	assert.ErrorIs(t, bad.CheckGenesisAgainstCompiled(), ErrTrustPinConflict)
}

// TestResolveGenesis, roots.json varken/yokken genesis çözümlemesini test eder.
func TestResolveGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roots.json")

	// Gömülü pin yok, dosya yok → pin missing.
	compiledGenesisSHA256, compiledGenesisEpoch = "", ""
	_, err := ResolveGenesis(path)
	assert.ErrorIs(t, err, ErrTrustPinMissing)

	// Gömülü pin var, dosya yok → gömülü genesis'e düş.
	withCompiledGenesis(t, Pin{AdminEpoch: 1, SHA256: "compiled"})
	got, err := ResolveGenesis(path)
	require.NoError(t, err)
	assert.Equal(t, "compiled", got.SHA256)

	// roots.json var ve uyumlu → ondan çöz.
	store := NewPinStore(Pin{AdminEpoch: 1, SHA256: "compiled"})
	require.NoError(t, store.Save(path))
	got, err = ResolveGenesis(path)
	require.NoError(t, err)
	assert.Equal(t, "compiled", got.SHA256)

	// roots.json var ama gömülü ile ÇAKIŞIYOR → pin conflict.
	conflict := NewPinStore(Pin{AdminEpoch: 1, SHA256: "MISMATCH"})
	require.NoError(t, conflict.Save(path))
	_, err = ResolveGenesis(path)
	assert.ErrorIs(t, err, ErrTrustPinConflict)
}

// TestPinStore_EndToEnd_WithChain, doğrulanmış bir zincirden pin'i ilerletip
// diske yazmayı ve tekrar okumayı uçtan uca test eder.
func TestPinStore_EndToEnd_WithChain(t *testing.T) {
	a := newAdminHuman(t, "adnan@wapps.dev")
	roots, gObj, gPin, gm := genesis3of(t, a.id, a)

	e2 := childOf(gm, gObj)
	e2.ChangeClass = ChangeRoster
	e2.Roots = append([]RootKey(nil), gm.Roots...)
	e2.Roots[0].Media = "rotated"
	e2Obj, _ := signRoots(t, e2, roots[0], roots[1])

	head, err := VerifyRosterChain(gPin, gPin, gObj, e2Obj)
	require.NoError(t, err)

	store := NewPinStore(gPin)
	require.NoError(t, store.AdvanceLastVerified(head.Pin()))
	assert.Equal(t, uint64(2), store.LastVerified.AdminEpoch)

	path := filepath.Join(t.TempDir(), "roots.json")
	require.NoError(t, store.Save(path))
	loaded, err := LoadPinStore(path)
	require.NoError(t, err)
	assert.Equal(t, head.BytesSHA256, loaded.LastVerified.SHA256)
	assert.Equal(t, gPin.SHA256, loaded.Genesis.SHA256)
}
