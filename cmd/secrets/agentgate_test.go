package secrets

import (
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// --- P1.8: checkRepoBinding service-principal muafiyeti --------------------

// Fresh container'da (pin yok) store-backed config → fail-closed BINDING_UNPINNED.
// setupStoreProject XDG'yi izole eder (boş pin deposu) ve CF env çiftini boşlar.
func TestAgentGate_RepoBinding_UnpinnedFailsClosed(t *testing.T) {
	setupStoreProject(t, "")

	err := checkRepoBinding(false)
	if !clierr.Is(err, clierr.BindingUnpinned) {
		t.Fatalf("unpinned store-backed repo: want BINDING_UNPINNED, got %v", err)
	}
}

// CF Access service-token ÇİFTİ set (service principal, CI) → repo-pin kontrolü
// atlanır; fresh container'da pin olmadan da verb'ler çalışabilmelidir.
func TestAgentGate_RepoBinding_ServiceTokenPairSkipsPin(t *testing.T) {
	setupStoreProject(t, "")
	t.Setenv("CF_ACCESS_CLIENT_ID", "svc-client-id.access")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "svc-client-secret")

	if err := checkRepoBinding(false); err != nil {
		t.Fatalf("service principal must skip repo-pin check, got %v", err)
	}
}

// Çiftin YARISI set ise muafiyet YOK — fail-closed davranış aynen sürer.
// (Yarım çift auth'ta da geçersizdir; pin bypass'ı auth'tan gevşek olamaz.)
func TestAgentGate_RepoBinding_HalfPairStaysFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		secret string
	}{
		{"only id set", "svc-client-id.access", ""},
		{"only secret set", "", "svc-client-secret"},
		{"whitespace-only pair", "   ", "\t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupStoreProject(t, "")
			t.Setenv("CF_ACCESS_CLIENT_ID", tt.id)
			t.Setenv("CF_ACCESS_CLIENT_SECRET", tt.secret)

			err := checkRepoBinding(false)
			if !clierr.Is(err, clierr.BindingUnpinned) {
				t.Fatalf("half/blank service-token pair must stay fail-closed, got %v", err)
			}
		})
	}
}
