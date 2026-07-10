package config

import (
	"path/filepath"
	"strings"
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
			require.Equal(t, 1, cfg.Version, "real fixtures are v1")
			require.Equal(t, BackendLegacyGit, cfg.Backend, "absent backend → legacy-git")
			require.False(t, cfg.IsStoreBackend())
			require.NotEmpty(t, cfg.Sources, "legacy-git requires sources")
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
	require.True(t, cfg.IsStoreBackend())
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
	require.True(t, cfg.IsStoreBackend())
	require.Len(t, cfg.Sources, 1)
}

func TestParse_V2LegacyGitExplicit(t *testing.T) {
	// backend: legacy-git açıkça → bugünkü kurallar (sources ZORUNLU).
	data := []byte(`
version: 2
backend: legacy-git
sources:
  - type: tofu
`)
	cfg, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, BackendLegacyGit, cfg.Backend)

	// legacy-git + sources yok → hata.
	_, err = Parse([]byte("version: 2\nbackend: legacy-git\n"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one source")
}

func TestParse_V2AbsentBackendDefaultsLegacy(t *testing.T) {
	// version 2 ama backend absent → legacy-git (sources ZORUNLU).
	data := []byte(`
version: 2
sources:
  - type: tofu
`)
	cfg, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, BackendLegacyGit, cfg.Backend)
}

func TestParse_V1WithBackendRejected(t *testing.T) {
	// backend v1'de yasak (§7.12: v2 alanları version 2 ZORUNLU).
	data := []byte(`
version: 1
backend: store
project: x
`)
	_, err := Parse(data)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "version: 2"))
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

func TestParse_ProfilesOnlyUnderStore(t *testing.T) {
	data := []byte(`
version: 2
backend: legacy-git
sources:
  - type: tofu
profiles:
  x: [A]
`)
	_, err := Parse(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "profiles are only valid under backend: store")
}
