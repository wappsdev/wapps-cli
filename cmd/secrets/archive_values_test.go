package secrets

// StoreValues (P1.7 re-point) testleri: `wapps deploy`ın credential fallback'i
// artık age arşivi değil, server-decrypt store'dur. Best-effort sözleşme
// (config yok / legacy → nil,nil) + ad-düzlemi kesişimi (var olmayan adaylar
// NOT_FOUND üretmez, boş kesişim value.read okuması yapmaz) kanıtlanır.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// TestStoreValues_SubsetIntersection: istenen aday anahtarlardan yalnızca
// store'da VAR olanlar okunur — bulk read'e eksik anahtar sızmaz (all-or-nothing
// §7.6 NOT_FOUND tuzağı), dönen harita yalnızca mevcut değerleri taşır.
func TestStoreValues_SubsetIntersection(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["DEPLOY_PROXY_TOKEN_VAULTER"] = "tok-store"
	f.values["DEPLOY_PROXY_CF_ACCESS_CLIENT_ID"] = "id-store"

	got, err := StoreValues(
		"DEPLOY_PROXY_TOKEN_VAULTER", "DEPLOY_PROXY_TOKEN", "PROXY_TOKEN",
		"DEPLOY_PROXY_CF_ACCESS_CLIENT_ID",
	)
	if err != nil {
		t.Fatalf("StoreValues: %v", err)
	}
	if got["DEPLOY_PROXY_TOKEN_VAULTER"] != "tok-store" || got["DEPLOY_PROXY_CF_ACCESS_CLIENT_ID"] != "id-store" {
		t.Errorf("values: %v", got)
	}
	if _, ok := got["PROXY_TOKEN"]; ok {
		t.Error("missing keys must be absent from the result, not present-empty")
	}
	if f.keysCalls != 1 {
		t.Errorf("name-plane Keys should be consulted exactly once, got %d", f.keysCalls)
	}
	if len(f.readCalls) != 1 {
		t.Fatalf("expected exactly 1 bulk read, got %d", len(f.readCalls))
	}
	// Read yalnızca MEVCUT anahtarları istemeli.
	want := []string{"DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "DEPLOY_PROXY_TOKEN_VAULTER"}
	gotKeys := append([]string{}, f.readCalls[0].keys...)
	sort.Strings(gotKeys)
	if len(gotKeys) != len(want) || gotKeys[0] != want[0] || gotKeys[1] != want[1] {
		t.Errorf("read keys: got %v, want %v", gotKeys, want)
	}
	if f.readCalls[0].project != "testproj" {
		t.Errorf("read project: %q", f.readCalls[0].project)
	}
}

// TestStoreValues_EmptyIntersection_NoRead: hiçbir aday store'da yoksa boş harita
// döner ve value.read HİÇ yapılmaz (audit'e okuma düşmez).
func TestStoreValues_EmptyIntersection_NoRead(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["UNRELATED_KEY"] = "x"

	got, err := StoreValues("DEPLOY_PROXY_TOKEN_VAULTER", "PROXY_TOKEN")
	if err != nil {
		t.Fatalf("StoreValues: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty map, got %v", got)
	}
	if len(f.readCalls) != 0 {
		t.Errorf("no value.read must happen on empty intersection, got %d", len(f.readCalls))
	}
}

// TestStoreValues_NoConfig_NilNil: .wapps.yaml yok → (nil, nil), store'a hiç
// dokunulmaz — çağıran (deploy) hatasız env-only çözümlemeye düşer.
func TestStoreValues_NoConfig_NilNil(t *testing.T) {
	t.Chdir(t.TempDir())
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })
	f := installFakeStore(t)

	got, err := StoreValues("DEPLOY_PROXY_TOKEN_VAULTER")
	if err != nil || got != nil {
		t.Fatalf("want (nil, nil) without config, got (%v, %v)", got, err)
	}
	if f.keysCalls != 0 || len(f.readCalls) != 0 {
		t.Error("store must not be touched without a backend:store config")
	}
}

// TestStoreValues_LegacyConfig_NilNil: legacy-git .wapps.yaml → (nil, nil);
// deploy'ın arşiv yolu P1.7 ile emekli — legacy config'te fallback env'dir.
func TestStoreValues_LegacyConfig_NilNil(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })
	if err := os.WriteFile(filepath.Join(tmp, ".wapps.yaml"), []byte("version: 1\nsources:\n  - type: tofu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := installFakeStore(t)

	got, err := StoreValues("DEPLOY_PROXY_TOKEN_VAULTER")
	if err != nil || got != nil {
		t.Fatalf("want (nil, nil) for legacy config, got (%v, %v)", got, err)
	}
	if f.keysCalls != 0 || len(f.readCalls) != 0 {
		t.Error("store must not be touched for a legacy-git config")
	}
}

// TestStoreValues_ReadErrorPropagates: gerçek bir okuma hatası (örn. grant reddi)
// aynen yüzer — çağıran bunu exit-2 notu olarak gösterir, değer içermez.
func TestStoreValues_ReadErrorPropagates(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)
	f.values["DEPLOY_PROXY_TOKEN_VAULTER"] = "tok"
	f.readErr = clierr.New(clierr.GrantDenied, "denied on key")

	_, err := StoreValues("DEPLOY_PROXY_TOKEN_VAULTER")
	if !clierr.Is(err, clierr.GrantDenied) {
		t.Fatalf("want GRANT_DENIED to propagate, got %v", err)
	}
}
