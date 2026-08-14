package secrets

// projects_test.go, `wapps secrets projects` ailesinin sözleşmesini pinler:
//   - list: store'dan gelen ADları satır başına bir tane basar, sunucu sırasını
//     bozmaz (filtreleme SUNUCUDA yapılır — istemci kendi kendine eleme yapmaz);
//   - list legacy-git'te NOT_AVAILABLE;
//   - rm: onaysız hiçbir şey silmez ve ajan modunda CONTROL_PLANE_REQUIRED.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

func TestRunProjectsList_PrintsNamesOnePerLine(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.projects = []string{"lumira", "navlun-app", "vaulter"}

	var out bytes.Buffer
	if err := runProjectsList(&out); err != nil {
		t.Fatalf("runProjectsList: %v", err)
	}
	if f.projectsCalls != 1 {
		t.Fatalf("Projects should be called exactly once, got %d", f.projectsCalls)
	}
	want := "lumira\nnavlun-app\nvaulter\n"
	if out.String() != want {
		t.Errorf("output: got %q, want %q", out.String(), want)
	}
}

// Görünür proje yoksa çıktı boştur — hata DEĞİL (dar grant meşru bir durum).
func TestRunProjectsList_EmptyIsNotAnError(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.projects = nil

	var out bytes.Buffer
	if err := runProjectsList(&out); err != nil {
		t.Fatalf("empty project list must not be an error, got %v", err)
	}
	if out.String() != "" {
		t.Errorf("expected no output, got %q", out.String())
	}
}

func TestRunProjectsList_LegacyBackend_Refused(t *testing.T) {
	tmp := setupStoreProject(t, "")
	legacy := "version: 2\nbackend: legacy-git\nproject: testproj\ndest: secrets/all.enc.age\n" +
		"sources:\n  - type: file\n    path: .env.shared\n"
	if err := os.WriteFile(filepath.Join(tmp, ".wapps.yaml"), []byte(legacy), 0644); err != nil {
		t.Fatalf("write legacy .wapps.yaml: %v", err)
	}
	f := installFakeStore(t)

	var out bytes.Buffer
	err := runProjectsList(&out)
	if !clierr.Is(err, clierr.NotAvailable) {
		t.Fatalf("legacy backend must refuse with NOT_AVAILABLE, got %v", err)
	}
	if f.projectsCalls != 0 {
		t.Errorf("legacy path must never reach the store, got %d calls", f.projectsCalls)
	}
}

// Onay verilmezse admin store'a HİÇ gidilmez — openAdminStore çağrılmadan önce
// dönülür, yani ağ isteği de kurulmaz.
func TestRunProjectsRm_WithoutConfirmation_Aborts(t *testing.T) {
	for _, answer := range []string{"", "no\n", "y\n"} {
		t.Run("answer="+strings.TrimSpace(answer), func(t *testing.T) {
			setupStoreProject(t, "")
			var out bytes.Buffer
			err := runProjectsRm("vaulter", false, strings.NewReader(answer), &out)
			if err == nil {
				t.Fatal("projects rm must abort when confirmation is not exactly 'yes'")
			}
			if strings.Contains(out.String(), "✓") {
				t.Errorf("aborted rm must not print a success line, got %q", out.String())
			}
		})
	}
}

// Onay istemi projeyi ADIYLA gösterir — operatör neyi sildiğini görmeden onaylamaz.
func TestRunProjectsRm_ConfirmPromptNamesTheProject(t *testing.T) {
	setupStoreProject(t, "")
	var out bytes.Buffer
	_ = runProjectsRm("navlun-app", false, strings.NewReader("no\n"), &out)
	if !strings.Contains(out.String(), "navlun-app") {
		t.Errorf("confirm prompt must name the project, got %q", out.String())
	}
}

// projects ailesi list için serbest; rm YAPRAĞI control-plane olarak reddedilir.
func TestProjects_AgentGate(t *testing.T) {
	if agentPolicy["projects"] != agentmode.PolicyAllow {
		t.Fatalf("projects family must be %q (list is names-only), got %q", agentmode.PolicyAllow, agentPolicy["projects"])
	}
	if err := agentmode.Guard(agentmode.PolicyControl, true); !clierr.Is(err, clierr.ControlPlaneRequired) {
		t.Fatalf("projects rm must be CONTROL_PLANE_REQUIRED in agent mode, got %v", err)
	}
}
