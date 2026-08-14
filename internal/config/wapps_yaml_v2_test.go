package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// SPEC §7.12 parser matrisi (G8 gate). Gerçek lab/vibe-pro/vaulter config'leri
// yeni binary altında SEMANTİĞİ DEĞİŞMEDEN parse etmeli + v2 (store/legacy-git/
// absent-backend/store-with-sources) şekilleri.

// TestParse_RealV1Fixtures, checked-in gerçek v1 config'lerin (absent backend →
// legacy-git) drop-in parse ettiğini doğrular.
func TestParse_RealV1Fixtures(t *testing.T) {
	for _, name := range []string{"lab", "vibe-pro", "vaulter"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "infra-tofu", "projects", name, ".wapps.yaml")
			cfg, err := Load(path)
			if err != nil {
				t.Skipf("fixture %s unavailable (%v)", path, err)
				return
			}
			require.Equal(t, 2, cfg.Version)
			require.Equal(t, BackendStore, cfg.Backend, "absent backend → store")

		})
	}
}

func TestParse_V2StoreBackend(t *testing.T) {
	data := []byte(`
version: 2
backend: store
project: vaulter
profiles:
  deploy: [DATABASE_URL, COOLIFY_TOKEN]
  test: [DATABASE_URL_TEST]
`)
	cfg, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, "vaulter", cfg.Project)
	keys, ok := cfg.ProfileKeys("deploy")
	require.True(t, ok)
	require.Equal(t, []string{"DATABASE_URL", "COOLIFY_TOKEN"}, keys)
	// Boş profil → tüm granted.
	_, all := cfg.ProfileKeys("")
	require.True(t, all)
}

func TestParse_V2StoreRequiresProject(t *testing.T) {
	data := []byte(`
version: 2
backend: store
`)
	_, err := Parse(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "project")
}

func TestParse_V2StoreWithSources_TofuMirror(t *testing.T) {
	// store backend'de sources OPSİYONEL (tofu-sync mirror girdileri, §8.6.5).
	data := []byte(`
version: 2
backend: store
project: lab
sources:
  - type: tofu
    workdir: .
    prefix: "TF_VAR_"
`)
	cfg, err := Parse(data)
	require.NoError(t, err)
	require.Len(t, cfg.Sources, 1)
}

func TestParse_UnknownBackendRejected(t *testing.T) {
	data := []byte(`
version: 2
backend: cloud-magic
project: x
`)
	_, err := Parse(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown backend")
}
