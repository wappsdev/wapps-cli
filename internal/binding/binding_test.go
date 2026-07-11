package binding

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBinding_PinAndCheck(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/repo-pins.json"

	s, err := Load(path) // dosya yok → boş depo
	require.NoError(t, err)

	fp := Fingerprint("git@github.com:wappsdev/vaulter.git")

	// Pinsiz → BINDING_UNPINNED.
	err = s.Check(fp, "vaulter")
	require.True(t, errors.Is(err, ErrUnpinned))

	// İnsan pinler.
	s.Pin(fp, Pin{Repo: "git@github.com:wappsdev/vaulter.git", Project: "vaulter", Backend: "store"})
	require.NoError(t, s.Save(path))

	// Kalıcı: yeniden yükle + eşleşme.
	s2, err := Load(path)
	require.NoError(t, err)
	require.NoError(t, s2.Check(fp, "vaulter"))

	// Farklı proje → mismatch (re-pin insan ister).
	err = s2.Check(fp, "lab")
	require.True(t, errors.Is(err, ErrMismatch))
}

func TestBinding_FingerprintStable(t *testing.T) {
	a := Fingerprint("git@github.com:x/y.git")
	b := Fingerprint("git@github.com:x/y.git")
	c := Fingerprint("/abs/path/to/repo")
	require.Equal(t, a, b)
	require.NotEqual(t, a, c)
	require.Len(t, a, 64) // sha256 hex
}
