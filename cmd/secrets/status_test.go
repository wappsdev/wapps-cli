package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGatherStatus_SafeWithNoState, hiçbir yerel durum yokken status hard-fail
// ETMEZ ve makul varsayılanlar döner (§7.10 fail-safe).
func TestGatherStatus_SafeWithNoState(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp) // .wapps.yaml yok → project ""
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("WAPPS_SECRETS_GATE", "") // dış host'a dokunma

	rep := gatherStatus()
	if rep.Online {
		t.Errorf("online should be false with no gate configured")
	}
	if rep.SessionValid {
		t.Errorf("session should be invalid with no session file")
	}
	if rep.EpochPin != 0 {
		t.Errorf("epoch_pin should be 0 with no pin, got %d", rep.EpochPin)
	}
	if rep.CacheAge != -1 {
		t.Errorf("cache_age should be -1 (absent) with no project/cache, got %d", rep.CacheAge)
	}
	if rep.IdentityPresent {
		t.Errorf("identity should be absent")
	}
}

// TestReadSession_ValidAndExpired, oturum dosyasının geçerli/expired durumları.
func TestReadSession_ValidAndExpired(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	dir := filepath.Join(tmp, "wapps")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Geçerli oturum.
	write := func(exp int64) {
		b, _ := json.Marshal(map[string]int64{"expires_at": exp})
		if err := os.WriteFile(filepath.Join(dir, "session.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
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

// TestIdentityPresent, kimlik işaret dosyasının varlığını yansıtır.
func TestIdentityPresent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	if identityPresent() {
		t.Fatalf("no identity marker → false")
	}
	dir := filepath.Join(tmp, "wapps")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "identity.json"), []byte("{}"), 0o600)
	if !identityPresent() {
		t.Fatalf("identity marker present → true")
	}
}
