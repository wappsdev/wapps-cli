package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

// envelopeWire, SPEC §7.5 tek-satır JSON zarfının test tarafındaki karşılığıdır
// (clierr'ın kendi tipini kullanmıyoruz: zarf bir SÖZLEŞME, üretim tipiyle
// birlikte sessizce değişmemeli).
type envelopeWire struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	Recovery  string `json:"recovery"`
	Retryable bool   `json:"retryable"`
}

// İnsan modu AYNEN kalır: bir cümle + kurtarma oku. Bir insanın cümle gördüğü
// yere JSON satırı basmak regresyondur; bu test onu bayt düzeyinde kilitler.
func TestReportError_HumanKeepsSentenceAndRecoveryArrow(t *testing.T) {
	var buf bytes.Buffer
	reportError(&buf, clierr.New(clierr.BindingUnpinned, "repo not pinned"), false)

	want := "Error: BINDING_UNPINNED: repo not pinned\n" +
		"  → run wapps secrets trust-repo in a terminal\n"
	if got := buf.String(); got != want {
		t.Fatalf("human error output changed\n got: %q\nwant: %q", got, want)
	}
}

// Kurtarma metni olmayan (clierr olmayan) bir hata insan modunda tek satır.
func TestReportError_HumanPlainErrorHasNoArrow(t *testing.T) {
	var buf bytes.Buffer
	reportError(&buf, errors.New("some raw error"), false)

	if got, want := buf.String(), "Error: some raw error\n"; got != want {
		t.Fatalf(" got: %q\nwant: %q", got, want)
	}
}

// Ajan modu: TEK satır JSON, insan süslemesi YOK. Bir cümleyi ayrıştırmaya
// çalışmak sözleşmenin var olma sebebi.
func TestReportError_AgentGetsSingleJSONLine(t *testing.T) {
	var buf bytes.Buffer
	reportError(&buf, clierr.New(clierr.BindingUnpinned, "repo not pinned"), true)

	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("envelope must be exactly one line, got %d newlines: %q", n, out)
	}
	if strings.Contains(out, "Error:") || strings.Contains(out, "→") {
		t.Fatalf("agent output must carry no human decoration: %q", out)
	}

	var w envelopeWire
	if err := json.Unmarshal([]byte(out), &w); err != nil {
		t.Fatalf("agent output must be JSON: %v (%q)", err, out)
	}
	if w.Error != "BINDING_UNPINNED" {
		t.Errorf("error code = %q, want BINDING_UNPINNED", w.Error)
	}
	if w.Message != "repo not pinned" {
		t.Errorf("message = %q, want %q", w.Message, "repo not pinned")
	}
	if w.Recovery != "run wapps secrets trust-repo in a terminal" {
		t.Errorf("recovery = %q, want the registry line", w.Recovery)
	}
	if w.Retryable {
		t.Errorf("BINDING_UNPINNED is not retryable")
	}
}

// clierr olmayan bir hata da zarfa girer (fail-closed: INTERNAL).
func TestReportError_AgentWrapsPlainErrorAsInternal(t *testing.T) {
	var buf bytes.Buffer
	reportError(&buf, errors.New("some raw error"), true)

	var w envelopeWire
	if err := json.Unmarshal(buf.Bytes(), &w); err != nil {
		t.Fatalf("agent output must be JSON: %v (%q)", err, buf.String())
	}
	if w.Error != "INTERNAL" {
		t.Errorf("error code = %q, want INTERNAL", w.Error)
	}
	if w.Message != "some raw error" {
		t.Errorf("message = %q, want the raw error text", w.Message)
	}
}

// nil hata iki modda da HİÇBİR ŞEY basmaz (Execute'ın başarı yolu sessiz).
func TestReportError_NilPrintsNothing(t *testing.T) {
	for _, agent := range []bool{false, true} {
		var buf bytes.Buffer
		reportError(&buf, nil, agent)
		if buf.Len() != 0 {
			t.Errorf("agent=%v: nil error printed %q", agent, buf.String())
		}
	}
}

// UÇTAN UCA: gerçek Execute() yolu. os.Exit test sürecini öldürdüğü için bu
// estate'in alt-süreç kalıbı kullanılır (bkz. dr_bootstrap_test.go). Çocuğun
// stdin'i TTY değil → ajan modu; yani sahadaki bir pipeline'ın gördüğü şey
// birebir budur: çıkış kodu 1 ve stderr'de TEK satır zarf.
func TestExecute_AgentModeEmitsEnvelopeEndToEnd(t *testing.T) {
	if os.Getenv("WAPPS_TEST_ERROR_ENVELOPE_CHILD") == "1" {
		rootCmd.AddCommand(&cobra.Command{
			Use:    "boom-test",
			Hidden: true,
			RunE: func(*cobra.Command, []string) error {
				return clierr.New(clierr.GrantDenied, "no policy row for DB_PASSWORD")
			},
		})
		rootCmd.SetArgs([]string{"boom-test"})
		Execute()
		// Buraya düşmek Execute'ın hatayı YUTTUĞU anlamına gelir.
		os.Exit(0)
	}

	child := exec.Command(os.Args[0], "-test.run", "^TestExecute_AgentModeEmitsEnvelopeEndToEnd$")
	child.Env = append(os.Environ(),
		"WAPPS_TEST_ERROR_ENVELOPE_CHILD=1",
		"WAPPS_NO_UPDATE_CHECK=1", // güncelleme/skill bildirimleri de stderr'e yazar
	)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	err := child.Run()

	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("want child exit code 1, got err=%v stderr=%q", err, stderr.String())
	}

	out := stderr.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stderr must be exactly one envelope line, got: %q", out)
	}
	var w envelopeWire
	if uerr := json.Unmarshal([]byte(out), &w); uerr != nil {
		t.Fatalf("stderr must be the JSON envelope: %v (%q)", uerr, out)
	}
	if w.Error != "GRANT_DENIED" {
		t.Errorf("error code = %q, want GRANT_DENIED", w.Error)
	}
	if w.Recovery == "" {
		t.Errorf("envelope must name a recovery; got empty")
	}
}

// Ajan modunda stderr BİR SÖZLEŞME KANALI: üzerine düşen her ek satır tek-satır
// zarfı ayrıştıran tarafı bozar. "Yeni sürüm var" / "skill tazelendi" gibi
// insan bildirimleri bugüne dek yalnızca stderr'in TTY olmasına bakıyordu — ama
// stderr bir terminal İKEN stdin bir pipe olabilir (`cat cfg | wapps ...`), ve o
// bağlamda okuyucu bir ajandır.
func TestHumanNoticesEnabled(t *testing.T) {
	tests := []struct {
		name                            string
		noUpdateCheck, stderrTTY, agent bool
		want                            bool
	}{
		{"human terminal", false, true, false, true},
		{"agent with TTY stderr but piped stdin", false, true, true, false},
		{"piped stderr", false, false, false, false},
		{"opted out", true, true, false, false},
		{"agent, no TTY, opted out", true, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := humanNoticesEnabled(tc.noUpdateCheck, tc.stderrTTY, tc.agent)
			if got != tc.want {
				t.Errorf("humanNoticesEnabled(%v,%v,%v) = %v, want %v",
					tc.noUpdateCheck, tc.stderrTTY, tc.agent, got, tc.want)
			}
		})
	}
}
