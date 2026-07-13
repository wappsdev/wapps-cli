package secrets

// dr_bootstrap_test — plan P1.3 test matrisi: agent-refusal, skip-if-set,
// tam env isimleri, preflight fail, scrub, exit-code propagation, sıfır temp
// dosya. fakeRunner (exec_test.go) + scripted prompt seam'i kullanılır.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/tofu"
)

// scriptedPrompt, bootstrapPrompt seam'inin sahtesidir: prompt metninin ilk
// kelimesi env ADIDIR ("%s — %s (Enter = skip): " formatı); values'tan değer
// döner (yoksa "" → skip) ve her çağrının adını kaydeder.
type scriptedPrompt struct {
	values map[string]string
	calls  []string
	err    error
}

func (s *scriptedPrompt) fn(prompt string) (string, bool, error) {
	fields := strings.Fields(prompt)
	if len(fields) == 0 {
		return "", true, fmt.Errorf("empty prompt")
	}
	name := fields[0]
	s.calls = append(s.calls, name)
	if s.err != nil {
		return "", true, s.err
	}
	return s.values[name], true, nil
}

// withBootstrapPrompt, seam'i test süresince değiştirir ve geri alır.
func withBootstrapPrompt(t *testing.T, fn func(string) (string, bool, error)) {
	t.Helper()
	old := bootstrapPrompt
	bootstrapPrompt = fn
	t.Cleanup(func() { bootstrapPrompt = old })
}

// emptyLookup, hiçbir env değişkeni set değilmiş gibi davranır.
func emptyLookup(string) string { return "" }

// promptablePlanNames, katalogdaki promptable adları katalog sırasında döner.
func promptablePlanNames() []string {
	var out []string
	for _, v := range tofu.BootstrapEnvVars {
		if v.Promptable() {
			out = append(out, v.Name)
		}
	}
	return out
}

// fullPromptValues, her promptable katalog girdisine benzersiz sahte değer üretir.
func fullPromptValues() map[string]string {
	vals := make(map[string]string)
	for _, n := range promptablePlanNames() {
		vals[n] = "val-" + strings.ToLower(n)
	}
	return vals
}

// --- agent-refusal -----------------------------------------------------------

// Ajan modunda verb, TEK BİR PROMPT bile atmadan ve child SPAWN ETMEDEN reddedilir.
func TestDrBootstrap_AgentRefusal(t *testing.T) {
	p := &scriptedPrompt{values: fullPromptValues()}
	withBootstrapPrompt(t, p.fn)

	r := &fakeRunner{returnCode: 0}
	err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, true, /*isAgent*/
		io.Discard, io.Discard, emptyLookup, r.runner)
	if err == nil {
		t.Fatal("expected AGENT_MODE_REFUSED in agent mode")
	}
	if !clierr.Is(err, clierr.AgentModeRefused) {
		t.Fatalf("wrong code: %v", err)
	}
	if len(p.calls) != 0 {
		t.Errorf("prompt must NEVER fire in agent mode, got calls: %v", p.calls)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must never spawn in agent mode, got: %q", r.gotName)
	}
}

// --- tam env isimleri + constant asla promptlanmaz ----------------------------

// Boş env'de: her promptable katalog girdisi TAM ADIYLA promptlanır (katalog
// sırasında), sabitler (AWS_REGION=auto) promptlanmadan enjekte edilir ve
// child env'i tüm NAME=value çiftlerini içerir. Hiçbir değer out/errW'ye sızmaz.
func TestDrBootstrap_PromptsExactEnvNamesAndInjects(t *testing.T) {
	vals := fullPromptValues()
	p := &scriptedPrompt{values: vals}
	withBootstrapPrompt(t, p.fn)

	var out, errW bytes.Buffer
	r := &fakeRunner{returnCode: 0}
	if err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, &out, &errW, emptyLookup, r.runner); err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}

	// Prompt çağrıları TAM olarak promptable katalog adları, katalog sırasında.
	want := promptablePlanNames()
	if len(p.calls) != len(want) {
		t.Fatalf("prompt calls: got %v, want %v", p.calls, want)
	}
	for i, n := range want {
		if p.calls[i] != n {
			t.Errorf("prompt[%d]: got %q, want %q", i, p.calls[i], n)
		}
	}
	for _, c := range p.calls {
		if c == "AWS_REGION" {
			t.Error("constant AWS_REGION must NEVER be prompted")
		}
	}

	// Child env'i: her promptlanan değer + sabit AWS_REGION=auto.
	envSet := make(map[string]bool, len(r.gotEnv))
	for _, e := range r.gotEnv {
		envSet[e] = true
	}
	for n, v := range vals {
		if !envSet[n+"="+v] {
			t.Errorf("child env missing %s=%s", n, v)
		}
	}
	if !envSet["AWS_REGION=auto"] {
		t.Error("child env missing constant AWS_REGION=auto")
	}

	// Değerler wapps'ın KENDİ çıktısına asla yazılmaz (adlar serbest).
	for _, v := range vals {
		if strings.Contains(out.String(), v) || strings.Contains(errW.String(), v) {
			t.Fatalf("secret VALUE leaked into wapps output")
		}
	}
}

// --- skip-if-set ---------------------------------------------------------------

// Env'de zaten set olan değişken promptlanmaz ve YENİDEN enjekte edilmez —
// child onu parent env kalıtımıyla alır.
func TestDrBootstrap_SkipIfSet(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "from-shell-akid")
	t.Setenv("TF_VAR_hcloud_token", "from-shell-hcloud")

	vals := fullPromptValues()
	p := &scriptedPrompt{values: vals}
	withBootstrapPrompt(t, p.fn)

	var errW bytes.Buffer
	r := &fakeRunner{returnCode: 0}
	if err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, io.Discard, &errW, os.Getenv, r.runner); err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}

	for _, c := range p.calls {
		if c == "AWS_ACCESS_KEY_ID" || c == "TF_VAR_hcloud_token" {
			t.Errorf("already-set var %s must not be prompted", c)
		}
	}
	// Kalıtım: t.Setenv gerçek env'e yazdı → child env'inde shell değeri var,
	// prompt değeri YOK (yeniden enjeksiyon yapılmadı).
	sawShell := false
	for _, e := range r.gotEnv {
		if e == "AWS_ACCESS_KEY_ID=from-shell-akid" {
			sawShell = true
		}
		if e == "AWS_ACCESS_KEY_ID="+vals["AWS_ACCESS_KEY_ID"] {
			t.Errorf("already-set var must not be re-injected: %s", e)
		}
	}
	if !sawShell {
		t.Error("child env must inherit the shell value of AWS_ACCESS_KEY_ID")
	}
	if !strings.Contains(errW.String(), "AWS_ACCESS_KEY_ID: already set") {
		t.Errorf("expected skip note (name only), got: %q", errW.String())
	}
	if strings.Contains(errW.String(), "from-shell-akid") {
		t.Fatal("skip note must never print the VALUE")
	}
}

// --- preflight -------------------------------------------------------------------

// Enter=skip ile backend kontratından bir değişken eksik kalırsa preflight
// child SPAWN EDİLMEDEN düşer ve eksik adı söyler.
func TestDrBootstrap_PreflightFailsOnMissingRequired(t *testing.T) {
	vals := fullPromptValues()
	delete(vals, "TF_VAR_state_passphrase") // scripted prompt "" döner → skip
	p := &scriptedPrompt{values: vals}
	withBootstrapPrompt(t, p.fn)

	r := &fakeRunner{returnCode: 0}
	err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, io.Discard, io.Discard, emptyLookup, r.runner)
	if err == nil {
		t.Fatal("expected preflight error for missing TF_VAR_state_passphrase")
	}
	if !strings.Contains(err.Error(), "TF_VAR_state_passphrase") {
		t.Errorf("error should name the missing var, got: %v", err)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not spawn on preflight failure, got: %q", r.gotName)
	}
}

// --skip-preflight, kontrat eksik olsa da komutu çalıştırır (non-tofu komutlar).
func TestDrBootstrap_SkipPreflightRuns(t *testing.T) {
	vals := fullPromptValues()
	delete(vals, "TF_VAR_state_passphrase")
	p := &scriptedPrompt{values: vals}
	withBootstrapPrompt(t, p.fn)

	r := &fakeRunner{returnCode: 0}
	if err := runDrBootstrap([]string{"some-tool"}, nil, true /*skipPreflight*/, false,
		io.Discard, io.Discard, emptyLookup, r.runner); err != nil {
		t.Fatalf("runDrBootstrap --skip-preflight: %v", err)
	}
	if r.gotName != "some-tool" {
		t.Errorf("command not run: got %q", r.gotName)
	}
}

// --- --var birleşimi ---------------------------------------------------------------

// --var ekleri promptlanır + enjekte edilir; katalogla çakışan --var adı
// İKİNCİ kez promptlanmaz (union semantiği).
func TestDrBootstrap_ExtraVarUnion(t *testing.T) {
	vals := fullPromptValues()
	vals["TF_VAR_extra_token"] = "val-extra"
	p := &scriptedPrompt{values: vals}
	withBootstrapPrompt(t, p.fn)

	r := &fakeRunner{returnCode: 0}
	err := runDrBootstrap([]string{"tofu", "apply"},
		[]string{"TF_VAR_extra_token", "TF_VAR_hcloud_token"}, // ikincisi katalogta ZATEN var
		false, false, io.Discard, io.Discard, emptyLookup, r.runner)
	if err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}

	found := false
	for _, e := range r.gotEnv {
		if e == "TF_VAR_extra_token=val-extra" {
			found = true
		}
	}
	if !found {
		t.Error("--var TF_VAR_extra_token must be prompted and injected")
	}
	hcloudPrompts := 0
	for _, c := range p.calls {
		if c == "TF_VAR_hcloud_token" {
			hcloudPrompts++
		}
	}
	if hcloudPrompts != 1 {
		t.Errorf("catalog-overlapping --var must be prompted exactly once, got %d", hcloudPrompts)
	}
}

// --- scrub ------------------------------------------------------------------------

// Enjekte edilen bir token'ı echo'layan child, o değeri transcript'e SIZDIRAMAZ (§7.4.3).
func TestDrBootstrap_ScrubsChildOutput(t *testing.T) {
	vals := fullPromptValues()
	secret := vals["TF_VAR_cloudflare_api_token"]
	p := &scriptedPrompt{values: vals}
	withBootstrapPrompt(t, p.fn)

	var out bytes.Buffer
	leaky := func(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
		_, _ = stdout.Write([]byte("using token " + secret + "\n"))
		return 0, nil
	}
	if err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, &out, io.Discard, emptyLookup, leaky); err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatalf("TOKEN LEAKED into transcript: %q", out.String())
	}
	if !strings.Contains(out.String(), "***") {
		t.Fatalf("expected redaction ***, got: %q", out.String())
	}
}

// Kalıtılan (skip-if-set) promptable bir token'ı echo'layan child de o değeri
// SIZDIRAMAZ — "echo eden apply *** basar" garantisi kalıtılan token'lar için de
// tutar (fresh-eyes P3 fix: promptable inherited değer scrub setine eklenir).
func TestDrBootstrap_ScrubsInheritedToken(t *testing.T) {
	const inherited = "hcloudtok_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	t.Setenv("TF_VAR_hcloud_token", inherited)

	p := &scriptedPrompt{values: fullPromptValues()}
	withBootstrapPrompt(t, p.fn)

	var out bytes.Buffer
	leaky := func(name string, args, env []string, stdout, stderr io.Writer) (int, error) {
		_, _ = stdout.Write([]byte("inherited token " + inherited + "\n"))
		return 0, nil
	}
	if err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, &out, io.Discard, os.Getenv, leaky); err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}
	if strings.Contains(out.String(), inherited) {
		t.Fatalf("INHERITED TOKEN LEAKED into transcript: %q", out.String())
	}
	if !strings.Contains(out.String(), "***") {
		t.Fatalf("expected redaction ***, got: %q", out.String())
	}
}

// --- epilogue ---------------------------------------------------------------------

// Başarılı bitişte farklılaştırılmış burn epilogue'u basılır: burn-now /
// burn-after / do-not-burn ayrımı + TF_VAR_state_passphrase unset hatırlatması
// (TF_ENCRYPTION DEĞİL) + §5.5 zarf re-seal hatırlatması.
func TestDrBootstrap_BurnEpilogueOnSuccess(t *testing.T) {
	p := &scriptedPrompt{values: fullPromptValues()}
	withBootstrapPrompt(t, p.fn)

	var errW bytes.Buffer
	r := &fakeRunner{returnCode: 0}
	if err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, io.Discard, &errW, emptyLookup, r.runner); err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}

	got := errW.String()
	for _, want := range []string{
		"BURN NOW", "BURN AFTER", "DO NOT BURN",
		"unset TF_VAR_state_passphrase",
		"NOT the TF_ENCRYPTION",
		"RE-SEAL",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("epilogue missing %q; got:\n%s", want, got)
		}
	}
}

// Runner hatasında (spawn fail) epilogue BASILMAZ ve hata sarılıp döner —
// iş bitmedi, burn talimatı erken verilmez.
func TestDrBootstrap_NoEpilogueOnRunnerError(t *testing.T) {
	p := &scriptedPrompt{values: fullPromptValues()}
	withBootstrapPrompt(t, p.fn)

	var errW bytes.Buffer
	r := &fakeRunner{returnErr: errors.New("spawn failed")}
	err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, io.Discard, &errW, emptyLookup, r.runner)
	if err == nil {
		t.Fatal("expected runner error to propagate")
	}
	if !strings.Contains(err.Error(), "spawn failed") {
		t.Errorf("runner error should propagate, got: %v", err)
	}
	if strings.Contains(errW.String(), "BURN NOW") {
		t.Error("burn epilogue must not print when the command failed to run")
	}
}

// Prompt hatası (örn. kapalı TTY) clierr ile sarılır (Unwrap zinciri korunur,
// mesaj değişken ADINI söyler); child spawn edilmez.
func TestDrBootstrap_PromptErrorPropagates(t *testing.T) {
	sentinel := errors.New("tty closed")
	p := &scriptedPrompt{err: sentinel}
	withBootstrapPrompt(t, p.fn)

	r := &fakeRunner{returnCode: 0}
	err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false, io.Discard, io.Discard, emptyLookup, r.runner)
	if err == nil {
		t.Fatal("expected prompt error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("prompt error should stay in the Unwrap chain, got: %v", err)
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("error should name the var being read, got: %v", err)
	}
	if r.gotName != "" {
		t.Errorf("subprocess must not spawn after prompt failure, got: %q", r.gotName)
	}
}

// --- exit-code propagation -----------------------------------------------------------

// Sıfır-dışı child exit kodu, wapps process'inin exit koduna AYNEN yansır
// (runWithInjectedEnv os.Exit sözleşmesi). os.Exit test process'ini öldürdüğü
// için standart alt-süreç kalıbı kullanılır: test kendi binary'sini yalnızca bu
// testi çalıştıracak şekilde yeniden exec eder; çocukta tüm bootstrap
// değişkenleri env'de set (skip-if-set → prompt yok) ve fakeRunner 7 döner.
func TestDrBootstrap_ExitCodePropagation(t *testing.T) {
	if os.Getenv("WAPPS_TEST_DR_BOOTSTRAP_EXIT_CHILD") == "1" {
		r := &fakeRunner{returnCode: 7}
		err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false,
			io.Discard, io.Discard, os.Getenv, r.runner)
		// Buraya düşmek propagation'ın KIRIK olduğunu gösterir (os.Exit(7) beklenirdi).
		fmt.Println("UNREACHABLE:", err)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestDrBootstrap_ExitCodePropagation$")
	env := append(os.Environ(), "WAPPS_TEST_DR_BOOTSTRAP_EXIT_CHILD=1")
	for _, v := range tofu.BootstrapEnvVars {
		val := v.Constant
		if val == "" {
			val = "x-" + strings.ToLower(v.Name)
		}
		env = append(env, v.Name+"="+val)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("want child exit code 7, got err=%v output=%s", err, out)
	}
}

// --- sıfır temp dosya ------------------------------------------------------------------

// Tam başarılı bir akış, HOME'a ve cwd'ye TEK BİR DOSYA bile yazmaz — değerler
// yalnızca process env'inde yaşar (§3.3: diske/store'a/pin'e asla).
func TestDrBootstrap_ZeroTempFiles(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(work)

	p := &scriptedPrompt{values: fullPromptValues()}
	withBootstrapPrompt(t, p.fn)

	r := &fakeRunner{returnCode: 0}
	if err := runDrBootstrap([]string{"tofu", "apply"}, nil, false, false,
		io.Discard, io.Discard, emptyLookup, r.runner); err != nil {
		t.Fatalf("runDrBootstrap: %v", err)
	}

	for _, dir := range []string{home, work} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		if len(entries) != 0 {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("dr bootstrap wrote files under %s: %v", dir, names)
		}
	}
}

// --- boş args guard'ı --------------------------------------------------------------------

func TestDrBootstrap_EmptyArgsErrors(t *testing.T) {
	p := &scriptedPrompt{values: fullPromptValues()}
	withBootstrapPrompt(t, p.fn)

	err := runDrBootstrap(nil, nil, false, false, io.Discard, io.Discard, emptyLookup, (&fakeRunner{}).runner)
	if err == nil {
		t.Fatal("expected error for empty args")
	}
	if len(p.calls) != 0 {
		t.Errorf("prompt must not fire without a command, got: %v", p.calls)
	}
}
