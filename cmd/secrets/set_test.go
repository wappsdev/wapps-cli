package secrets

// set_test.go, `wapps secrets set <KEY>` sözleşmesini pinler: değer --from-file
// ya da no-echo prompt ile yakalanır ve tek-anahtar PUT ile store'a yazılır.
// Değer ASLA argv'de taşınmaz ve ASLA stdout'a düşmez.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// happyPathPrompt, TTY'den başarılı bir okumayı taklit eder.
func happyPathPrompt(val string) func(string) (string, bool, error) {
	return func(string) (string, bool, error) { return val, true, nil }
}

func TestRunSet_WritesToStore(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	if err := runSet("DB_PASSWORD", setOptions{promptValue: happyPathPrompt("hunter2")}); err != nil {
		t.Fatalf("runSet: %v", err)
	}
	if len(f.setCalls) != 1 {
		t.Fatalf("expected exactly one Set call, got %d", len(f.setCalls))
	}
	got := f.setCalls[0]
	if got.project != "testproj" || got.key != "DB_PASSWORD" || got.value != "hunter2" {
		t.Errorf("Set args: got %+v", got)
	}
}

// --from-file: değer argv'ye ve shell geçmişine hiç girmez (§7.9.3 kalıbı).
func TestRunSet_FromFile(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	path := filepath.Join(t.TempDir(), "v")
	if err := os.WriteFile(path, []byte("from-file-value\n"), 0600); err != nil {
		t.Fatalf("write value file: %v", err)
	}
	if err := runSet("API_KEY", setOptions{fromFile: path}); err != nil {
		t.Fatalf("runSet --from-file: %v", err)
	}
	if len(f.setCalls) != 1 || f.setCalls[0].value != "from-file-value" {
		t.Fatalf("trailing newline must be stripped; got %+v", f.setCalls)
	}
}

func TestRunSet_RequiresWappsYAML(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	SetConfigPath("")
	t.Cleanup(func() { SetConfigPath("") })

	err := runSet("K", setOptions{promptValue: happyPathPrompt("v")})
	if err == nil || !strings.Contains(err.Error(), ".wapps.yaml") {
		t.Fatalf("missing config must be named in the error, got %v", err)
	}
}

// Boş değer reddedilir: bir sırrı yanlışlıkla silmenin sessiz yolu olmamalı.
func TestRunSet_RejectsEmptyValue(t *testing.T) {
	setupStoreProject(t, "")
	f := installFakeStore(t)

	err := runSet("K", setOptions{promptValue: happyPathPrompt("")})
	if err == nil {
		t.Fatal("empty value must be rejected")
	}
	if len(f.setCalls) != 0 {
		t.Errorf("rejected set must not reach the store, got %+v", f.setCalls)
	}
}

func TestRunSet_EmptyKeyArgument(t *testing.T) {
	setupStoreProject(t, "")
	installFakeStore(t)
	if err := runSet("", setOptions{promptValue: happyPathPrompt("v")}); err == nil {
		t.Fatal("empty KEY must be rejected")
	}
}
