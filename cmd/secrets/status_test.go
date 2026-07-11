package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGatherStatus_SafeWithNoState, hiçbir yerel durum yokken status hard-fail
// ETMEZ ve makul varsayılanlar döner (fail-safe).
func TestGatherStatus_SafeWithNoState(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp) // .wapps.yaml yok → project ""
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("WAPPS_STATUS_NO_PROBE", "1") // CI: dış host'a dokunma

	rep := gatherStatus()
	if rep.Online {
		t.Errorf("online should be false with probing disabled")
	}
	if rep.SessionValid {
		t.Errorf("session should be invalid with no session file")
	}
	if rep.EpochPin != 0 {
		t.Errorf("epoch_pin should be 0 with no pin, got %d", rep.EpochPin)
	}
}

// TestReadSession_ValidAndExpired, v2 oturum dosyasının (session/<host>.json)
// geçerli/expired durumları.
func TestReadSession_ValidAndExpired(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("WAPPS_SESSION_TOKEN", "")
	t.Setenv("WAPPS_SECRETS_GATE", "https://gw.meapps.dev")
	dir := filepath.Join(tmp, "wapps", "session")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	write := func(exp int64) {
		b, _ := json.Marshal(map[string]any{"token": "tok-bytes", "expires_at": exp})
		if err := os.WriteFile(filepath.Join(dir, "gw.meapps.dev.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Geçerli oturum.
	write(time.Now().Add(time.Hour).Unix())
	valid, rem := readSession()
	if !valid || rem <= 0 {
		t.Errorf("expected a valid session with positive remaining, got valid=%v rem=%d", valid, rem)
	}

	// Expired oturum.
	write(time.Now().Add(-time.Hour).Unix())
	valid, _ = readSession()
	if valid {
		t.Errorf("expired session must read as invalid")
	}
}
