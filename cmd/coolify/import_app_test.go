package coolify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportApp_ServerUUIDFromDestination locks the fix for the Phase A bug:
// Coolify v4 nests server_uuid under destination.server.uuid (not top-level),
// so --server-uuid filter must navigate the nested path.
func TestImportApp_ServerUUIDFromDestination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/applications" {
			t.Errorf("Expected /applications, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// Coolify v4 returns a top-level JSON array for /applications (no "data" envelope).
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"uuid": "app-abc",
				"name": "test-app",
				"destination": map[string]interface{}{
					"server": map[string]interface{}{
						"uuid": "srv-target",
					},
				},
			},
			{
				"uuid": "app-other",
				"name": "other-app",
				"destination": map[string]interface{}{
					"server": map[string]interface{}{
						"uuid": "srv-different",
					},
				},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("COOLIFY_URL", srv.URL)
	t.Setenv("COOLIFY_API_TOKEN", "fake")
	tmp := t.TempDir()

	imServerUUID = "srv-target"
	imOutputDir = tmp
	t.Cleanup(func() {
		imServerUUID = ""
		imOutputDir = ""
	})

	if err := importAppCmd.RunE(importAppCmd, []string{}); err != nil {
		t.Fatalf("RunE failed: %v", err)
	}

	imports, err := os.ReadFile(filepath.Join(tmp, "imports.sh"))
	if err != nil {
		t.Fatalf("read imports.sh: %v", err)
	}
	if !strings.Contains(string(imports), "test_app") {
		t.Errorf("expected test_app in imports.sh, got: %s", imports)
	}
	if strings.Contains(string(imports), "other_app") {
		t.Errorf("server-uuid filter leaked other_app into imports.sh: %s", imports)
	}
}
