package secrets

// rm_test.go, `wapps secrets rm <KEY>` sözleşmesini pinler:
//   - store'a DELETE gider (doğru proje + anahtar), çıktı yalnızca ADı taşır;
//   - onay verilmeden HİÇBİR silme olmaz (fail-closed);
//   - legacy-git backend'de reddedilir (store'a hiç dokunulmaz);
//   - gate hatası (ör. anahtar zaten yok) aynen yüzeye çıkar, başarı basılmaz;
//   - ajan modunda yapısal olarak reddedilir (merkezi agentPolicy kaydı).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
)

func TestRunRm_YesFlag_DeletesKey(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["NVL_ZITADEL_ONBOARDING_PAT"] = "orphaned-pat"

	var out bytes.Buffer
	if err := runRm("NVL_ZITADEL_ONBOARDING_PAT", true, strings.NewReader(""), &out); err != nil {
		t.Fatalf("runRm: %v", err)
	}

	if len(f.deleteCalls) != 1 {
		t.Fatalf("store Delete should be called exactly once, got %d", len(f.deleteCalls))
	}
	got := f.deleteCalls[0]
	if got.project != "testproj" || got.key != "NVL_ZITADEL_ONBOARDING_PAT" {
		t.Errorf("Delete args: got %+v, want {testproj NVL_ZITADEL_ONBOARDING_PAT}", got)
	}
	if !strings.Contains(out.String(), "NVL_ZITADEL_ONBOARDING_PAT") {
		t.Errorf("output must name the removed key, got %q", out.String())
	}
	// AD görünür, DEĞER asla — get/list ayrımının aynı çizgisi.
	if strings.Contains(out.String(), "orphaned-pat") {
		t.Errorf("output leaked the secret value: %q", out.String())
	}
}

// Onay istendiğinde "yes" yazılırsa silme gerçekleşir.
func TestRunRm_ConfirmYes_DeletesKey(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["STALE_KEY"] = "v"

	var out bytes.Buffer
	if err := runRm("STALE_KEY", false, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatalf("runRm: %v", err)
	}
	if len(f.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(f.deleteCalls))
	}
	if !strings.Contains(out.String(), "STALE_KEY") {
		t.Errorf("confirm prompt + result must name the key, got %q", out.String())
	}
}

// Onay verilmezse hiçbir şey silinmez — fail-closed. Boş girdi (EOF) ve açık
// "no" aynı yola çıkar: silme geri alınamaz, belirsizlik iptal demektir.
func TestRunRm_WithoutConfirmation_DeletesNothing(t *testing.T) {
	for _, answer := range []string{"", "no\n", "y\n", "YES\n"} {
		t.Run("answer="+strings.TrimSpace(answer), func(t *testing.T) {
			setupStoreProject(t, "")
			f := installFakeStore(t)
			f.values["STALE_KEY"] = "v"

			var out bytes.Buffer
			err := runRm("STALE_KEY", false, strings.NewReader(answer), &out)
			if err == nil {
				t.Fatal("rm must abort when confirmation is not exactly 'yes'")
			}
			if len(f.deleteCalls) != 0 {
				t.Errorf("aborted rm must not call Delete, got %+v", f.deleteCalls)
			}
		})
	}
}

// legacy-git backend'de rm yoktur: store'a hiç gidilmez, kurtarma yolu söylenir.
func TestRunRm_LegacyBackend_Refused(t *testing.T) {
	tmp := setupStoreProject(t, "")
	// backend satırını legacy'ye çevir (setupStoreProject store yazmıştı).
	legacy := "version: 2\nbackend: legacy-git\nproject: testproj\ndest: secrets/all.enc.age\n" +
		"sources:\n  - type: file\n    path: .env.shared\n"
	if err := os.WriteFile(filepath.Join(tmp, ".wapps.yaml"), []byte(legacy), 0644); err != nil {
		t.Fatalf("write legacy .wapps.yaml: %v", err)
	}
	f := installFakeStore(t)

	var out bytes.Buffer
	err := runRm("SOME_KEY", true, strings.NewReader(""), &out)
	if !clierr.Is(err, clierr.NotAvailable) {
		t.Fatalf("legacy backend must refuse with NOT_AVAILABLE, got %v", err)
	}
	if len(f.deleteCalls) != 0 {
		t.Errorf("legacy path must never reach the store, got %+v", f.deleteCalls)
	}
}

// Gate hatası (ör. anahtar zaten yok → NOT_FOUND) aynen yüzer; "✓" basılmaz.
func TestRunRm_StoreErrorPropagates(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.writeErr = clierr.Newf(clierr.NotFound, "delete GONE_KEY: key GONE_KEY not found")

	var out bytes.Buffer
	err := runRm("GONE_KEY", true, strings.NewReader(""), &out)
	if !clierr.Is(err, clierr.NotFound) {
		t.Fatalf("store NOT_FOUND must surface unchanged, got %v", err)
	}
	if strings.Contains(out.String(), "✓") {
		t.Errorf("failed rm must not print a success line, got %q", out.String())
	}
}

// rm, merkezi ajan-modu kaydında REFUSED olmalı — silme geri alınamaz.
func TestRm_AgentModeRefused(t *testing.T) {
	if agentPolicy["rm"] != agentmode.PolicyRefuseAgent {
		t.Fatalf("rm must be registered as %q, got %q", agentmode.PolicyRefuseAgent, agentPolicy["rm"])
	}
	if err := agentmode.Guard(agentPolicy["rm"], true); !clierr.Is(err, clierr.AgentModeRefused) {
		t.Fatalf("agent-mode rm must be refused, got %v", err)
	}
}
