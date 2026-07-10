package cache

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache_SaveLoad_CiphertextOnly(t *testing.T) {
	dir := t.TempDir()
	path := PathFor(dir, "vaulter")

	ent := &Entry{
		Project:         "vaulter",
		Epoch:           42,
		ManifestWrapper: []byte(`{"bytes":"deadbeef","sigs":[]}`),
		ETag:            "abc123",
		Blobs:           map[string][]byte{"hash1": []byte("WSB1-ciphertext")},
		TrustChain:      [][]byte{[]byte("trust-epoch-1")},
		TrustEpoch:      1,
		TrustSHA256:     "trusthash",
		FetchedAt:       time.Now().UTC(),
	}
	require.NoError(t, ent.Save(path))

	// Mode 0600.
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	got, err := Load(path)
	require.NoError(t, err)
	require.EqualValues(t, 42, got.Epoch)
	require.Equal(t, "abc123", got.ETag)
	require.Equal(t, []byte("WSB1-ciphertext"), got.Blobs["hash1"])
	require.Equal(t, Schema, got.Schema)
}

func TestCache_LoadMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(PathFor(dir, "nope"))
	require.Error(t, err)
	require.True(t, os.IsNotExist(errUnwrap(err)))
}

func TestCache_Age(t *testing.T) {
	ent := &Entry{FetchedAt: time.Now().Add(-2 * time.Hour)}
	require.InDelta(t, (2 * time.Hour).Seconds(), ent.Age().Seconds(), 5)
}

// errUnwrap, os.ErrNotExist kontrolü için hata zincirini çözer.
func errUnwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if os.IsNotExist(err) {
			return err
		}
		u, ok := err.(unwrapper)
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
	return err
}
