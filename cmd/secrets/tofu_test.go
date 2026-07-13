package secrets

// tofu_test.go — `wapps tofu` birinci-sınıf sarımının (runTofu) davranış kanıtı.
// runTofu, exec ailesinin ORTAK yolunu (runExec) prefix="" (VERBATIM) + intent
// "dev" ile çağırır; bu testler o sözleşmeyi hem legacy-git hem store backend'de
// doğrular: (a) komut adı "tofu" + argüman passthrough AYNEN, (b) VERBATIM prefix
// (çift-prefix YOK), (c) scrubber sızıntıyı *** yapar.

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// TestRunTofu_PassesTofuNameAndArgsVerbatim — sarım komut adını "tofu" olarak
// sabitler ve kullanıcı argümanlarını (-target, -var, -input=false ...) runner'a
// AYNEN, sırasını koruyarak geçirir.
func TestRunTofu_PassesTofuNameAndArgsVerbatim(t *testing.T) {
	cases := []struct {
		name     string
		tofuArgs []string
	}{
		{"init", []string{"init"}},
		{"plan-target", []string{"plan", "-target=module.gate"}},
		{"apply-flags", []string{"apply", "-input=false", "-auto-approve"}},
		{"var-pairs", []string{"plan", "-var", "region=eu", "-var", "env=prod"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			execTestSetup(t, nil)
			r := &fakeRunner{returnCode: 0}
			if err := runTofu(c.tofuArgs, false, io.Discard, io.Discard, r.runner); err != nil {
				t.Fatalf("runTofu: %v", err)
			}
			if r.gotName != "tofu" {
				t.Errorf("command name: got %q, want tofu", r.gotName)
			}
			if len(r.gotArgs) != len(c.tofuArgs) {
				t.Fatalf("args length: got %d (%v), want %d (%v)", len(r.gotArgs), r.gotArgs, len(c.tofuArgs), c.tofuArgs)
			}
			for i, a := range c.tofuArgs {
				if r.gotArgs[i] != a {
					t.Errorf("args[%d]: got %q, want %q", i, r.gotArgs[i], a)
				}
			}
		})
	}
}

// TestRunTofu_VerbatimPrefix — TUZAK'ın kanıtı: store/legacy arşivi anahtarları
// TAM isimle tutar (TF_VAR_*, AWS_*). Sarım prefix="" enjekte ettiği için child
// env'de anahtarlar AYNEN görünür — ne çift-prefix (TF_VAR_TF_VAR_) ne de yabancı
// bir prefix (TF_VAR_AWS_) eklenir.
func TestRunTofu_VerbatimPrefix(t *testing.T) {
	execTestSetup(t, map[string]string{
		"TF_VAR_foo":            "bar",
		"AWS_ACCESS_KEY_ID":     "AKIA123",
		"AWS_SECRET_ACCESS_KEY": "shh",
	})

	r := &fakeRunner{returnCode: 0}
	if err := runTofu([]string{"plan"}, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("runTofu: %v", err)
	}

	want := map[string]string{
		"TF_VAR_foo":            "bar",
		"AWS_ACCESS_KEY_ID":     "AKIA123",
		"AWS_SECRET_ACCESS_KEY": "shh",
	}
	for k, v := range want {
		found := false
		for _, e := range r.gotEnv {
			if e == k+"="+v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("verbatim env missing %s=%s\nenv: %v", k, v, r.gotEnv)
		}
	}
	// Çift/yabancı prefix ASLA üretilmemeli.
	for _, e := range r.gotEnv {
		if strings.HasPrefix(e, "TF_VAR_TF_VAR_") {
			t.Errorf("double-prefixed entry: %q", e)
		}
		if strings.HasPrefix(e, "TF_VAR_AWS_") {
			t.Errorf("foreign-prefixed entry: %q", e)
		}
	}
}

// TestRunTofu_ScrubsInjectedValueFromChildOutput — §7.4.3: değeri echo'layan bir
// tofu çıktısı (örn. hata mesajında bir credential) yakalanan stdout'a değeri
// SIZDIRAMAZ; scrubber onu *** yapar.
func TestRunTofu_ScrubsInjectedValueFromChildOutput(t *testing.T) {
	secret := "AKIA_supersecret_tofu_1234567890"
	execTestSetup(t, map[string]string{"AWS_ACCESS_KEY_ID": secret})

	var out bytes.Buffer
	leaky := func(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
		var val string
		for _, e := range env {
			if after, ok := strings.CutPrefix(e, "AWS_ACCESS_KEY_ID="); ok {
				val = after
			}
		}
		// Parçalı yazım: flush edilmezse scrubber tamponunda sızıntı kalırdı.
		_, _ = stdout.Write([]byte("Error: invalid credential " + val))
		_, _ = stdout.Write([]byte(" (403)\n"))
		return 0, nil
	}

	if err := runTofu([]string{"plan"}, false, &out, io.Discard, leaky); err != nil {
		t.Fatalf("runTofu: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("SECRET LEAKED into transcript: %q", out.String())
	}
	if !strings.Contains(out.String(), "***") {
		t.Fatalf("expected *** redaction, got: %q", out.String())
	}
}

// TestRunTofu_RunnerZeroReturnsNil — runner 0 dönerse sarım normal (nil) döner.
// (nonzero exit os.Exit ile alt-sürecinkine yansır — süreci sonlandırdığı için
// birim testinde doğrulanamaz; runExec'in exit-code yolu exec_test.go kapsamında.)
func TestRunTofu_RunnerZeroReturnsNil(t *testing.T) {
	execTestSetup(t, nil)
	r := &fakeRunner{returnCode: 0}
	if err := runTofu([]string{"validate"}, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("runTofu should return nil on exit 0: %v", err)
	}
}

// TestRunTofu_StoreBackend_VerbatimInjection — store backend yolunda da VERBATIM
// prefix sözleşmesi korunur: store PLAINTEXT değerleri (TF_VAR_*, AWS_*) child
// env'e AYNEN enjekte edilir, çift-prefix eklenmez.
func TestRunTofu_StoreBackend_VerbatimInjection(t *testing.T) {
	setupStoreProject(t, "")
	// F1: runTofu artık checkRepoBinding uygular; bu test injection sözleşmesini
	// gate'in ÖTESİNDE doğrular → service-principal muafiyetiyle (CF Access
	// service-token çifti) pin kontrolünü geç.
	t.Setenv("CF_ACCESS_CLIENT_ID", "svc-client-id.access")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "svc-client-secret")
	f := installFakeStore(t)
	f.values["TF_VAR_region"] = "eu-central"
	f.values["AWS_ACCESS_KEY_ID"] = "AKIA_store"

	r := &fakeRunner{returnCode: 0}
	if err := runTofu([]string{"apply"}, false, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("runTofu (store): %v", err)
	}
	if r.gotName != "tofu" {
		t.Errorf("command name: got %q, want tofu", r.gotName)
	}
	if len(f.readCalls) != 1 {
		t.Fatalf("store Read should be called once, got %d", len(f.readCalls))
	}
	want := map[string]string{
		"TF_VAR_region":     "eu-central",
		"AWS_ACCESS_KEY_ID": "AKIA_store",
	}
	for k, v := range want {
		found := false
		for _, e := range r.gotEnv {
			if e == k+"="+v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("store verbatim env missing %s=%s\nenv: %v", k, v, r.gotEnv)
		}
	}
	for _, e := range r.gotEnv {
		if strings.HasPrefix(e, "TF_VAR_TF_VAR_") {
			t.Errorf("double-prefixed entry (store): %q", e)
		}
	}
}

// --- F1 (confused-deputy) regression -----------------------------------------

// TestRunTofu_StoreBackend_UnpinnedRefused — F1'in KAPANDIĞININ kanıtı. `wapps tofu`
// root'a mount'lu olduğundan SecretsCmd.PersistentPreRunE gate'i (binding pin)
// çalışmazdı; runTofu artık checkRepoBinding'i açıkça uygular. Store-backed +
// UNPINNED repo → tıpkı `wapps secrets exec` gibi BINDING_UNPINNED ile REDDEDİLİR;
// secret'lar hiç okunmaz, runner çağrılmaz (exfiltration bloke).
func TestRunTofu_StoreBackend_UnpinnedRefused(t *testing.T) {
	for _, isAgent := range []bool{false, true} {
		name := "interactive"
		if isAgent {
			name = "agent"
		}
		t.Run(name, func(t *testing.T) {
			setupStoreProject(t, "") // boş pin deposu + CF env çifti boş
			f := installFakeStore(t)
			f.values["TF_VAR_region"] = "eu-central"

			r := &fakeRunner{returnCode: 0}
			err := runTofu([]string{"apply"}, isAgent, io.Discard, io.Discard, r.runner)
			if !clierr.Is(err, clierr.BindingUnpinned) {
				t.Fatalf("unpinned store-backed tofu: want BINDING_UNPINNED, got %v", err)
			}
			if len(f.readCalls) != 0 {
				t.Errorf("secrets must NOT be read when binding is unpinned, got %d reads", len(f.readCalls))
			}
			if r.gotName != "" {
				t.Errorf("runner must NOT be invoked when refused, got name %q", r.gotName)
			}
		})
	}
}

// TestRunTofu_AgentMode_ServiceTokenPasses — ajan modunda (isAgent=true) `wapps tofu`
// HÂLÂ serbesttir (PolicyAllow → Guard geçer); service-token çifti (CI service
// principal, P1.8) pin kontrolünü muaf tutar → gate'i geçip runner'a ulaşır.
// Bu, F1 fix'inin CI service-principal yolunu bozmadığını kanıtlar.
func TestRunTofu_AgentMode_ServiceTokenPasses(t *testing.T) {
	setupStoreProject(t, "")
	t.Setenv("CF_ACCESS_CLIENT_ID", "svc-client-id.access")
	t.Setenv("CF_ACCESS_CLIENT_SECRET", "svc-client-secret")
	f := installFakeStore(t)
	f.values["TF_VAR_region"] = "eu-central"

	r := &fakeRunner{returnCode: 0}
	if err := runTofu([]string{"apply"}, true, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("agent-mode tofu with service-token pair must pass gate, got %v", err)
	}
	if r.gotName != "tofu" {
		t.Errorf("runner should have run tofu, got %q", r.gotName)
	}
}

// TestRunTofu_LegacyBackend_GateNoop — legacy-git backend'de checkRepoBinding
// no-op'tur; gate eklendikten sonra da legacy yol (pin GEREKTİRMEZ) ajan modunda
// dahi serbest çalışır — mevcut legacy testleriyle birlikte F1 fix'inin legacy'yi
// bozmadığını doğrular.
func TestRunTofu_LegacyBackend_GateNoop(t *testing.T) {
	execTestSetup(t, map[string]string{"TF_VAR_foo": "bar"})
	r := &fakeRunner{returnCode: 0}
	if err := runTofu([]string{"plan"}, true, io.Discard, io.Discard, r.runner); err != nil {
		t.Fatalf("legacy-git tofu gate must be no-op, got %v", err)
	}
	if r.gotName != "tofu" {
		t.Errorf("runner should have run tofu, got %q", r.gotName)
	}
}
