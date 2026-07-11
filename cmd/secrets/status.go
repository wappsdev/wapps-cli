package secrets

// status — makine-okunur oturum/store durumu. v2'de (server-decrypt SPEC §7):
// ciphertext cache SİLİNDİ (§0.2, cache_age yok), yerel kimlik deposu SİLİNDİ
// (identity_present yok — kimlik = CF Access oturumu). status HER modda ve her
// ağ durumunda güvenlidir: plaintext'e dokunmaz, asla hard-fail etmez.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Machine-readable gate/session state (safe in every mode)",
	Long: `Report {online, session_valid, session_expires_in, epoch_pin}. status is SAFE
in every mode and every network state — it never touches plaintext and never fails
hard; it is the first command an agent runs when anything else errors.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rep := gatherStatus()
		// status ASLA hard-fail etmez: her zaman raporu basıp nil döner.
		if statusJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			_ = enc.Encode(rep)
			return nil
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "online:           %v\n", rep.Online)
		fmt.Fprintf(w, "session_valid:    %v\n", rep.SessionValid)
		fmt.Fprintf(w, "session_expires:  %ds\n", rep.SessionExpiresIn)
		fmt.Fprintf(w, "epoch_pin:        %d\n", rep.EpochPin)
		return nil
	},
}

// StatusReport, makine-okunur durum şemasıdır. session_expires_in SANİYE;
// epoch_pin per-proje pinlenmiş data epoch'u (rollback tripwire'ı, §7.4).
type StatusReport struct {
	Online           bool   `json:"online"`
	SessionValid     bool   `json:"session_valid"`
	SessionExpiresIn int64  `json:"session_expires_in"`
	EpochPin         uint64 `json:"epoch_pin"`
}

// gatherStatus, YEREL durumdan (+ kısa bir gate probu) raporu toplar. Hiçbir
// adım hata FIRLATMAZ — bilinmeyen alanlar false/0 kalır (fail-safe).
func gatherStatus() StatusReport {
	rep := StatusReport{
		Online:   probeGate(),
		EpochPin: readEpochPin(statusProject()),
	}
	rep.SessionValid, rep.SessionExpiresIn = readSession()
	return rep
}

// statusProject, store-backed .wapps.yaml'dan proje adını döner (yoksa "").
func statusProject() string {
	cfg, err := loadOrNil(wappsConfigPath())
	if err != nil || cfg == nil || !cfg.IsStoreBackend() {
		return ""
	}
	return cfg.Project
}

// probeGate, gate'e kısa bir prob atar; HERHANGİ bir HTTP yanıtı (401 dahil) →
// online. Taşıma hatası/timeout → offline. WAPPS_SECRETS_GATE açıkça boşaltılmışsa
// yine varsayılan gate'e gidilir; CI'da dış çağrıyı önlemek için
// WAPPS_STATUS_NO_PROBE=1 deterministik olarak offline döndürür.
func probeGate() bool {
	if os.Getenv("WAPPS_STATUS_NO_PROBE") == "1" {
		return false
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(session.GateURL() + "/v1/whoami")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// readEpochPin, epochs.json'dan projenin data epoch pin'ini okur (yoksa 0).
func readEpochPin(project string) uint64 {
	if project == "" {
		return 0
	}
	path, err := store.DefaultEpochPinPath()
	if err != nil {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var p struct {
		Pins map[string]uint64 `json:"pins"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return 0
	}
	return p.Pins[project]
}

// readSession, oturum geçerliliği + kalan saniye (status için). Out-of-band env
// token'ı expiry'siz de geçerlidir (kalan 0 raporlanır). Yoksa/expired → (false, 0).
func readSession() (bool, int64) {
	s, ok := session.Load(session.GateHost())
	if !ok {
		return false, 0
	}
	now := time.Now()
	if s.Expired(now) {
		return false, 0
	}
	if s.ExpiresAt == 0 {
		return true, 0
	}
	return true, int64(s.TTL(now).Seconds())
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "emit the machine-readable JSON schema")
	SecretsCmd.AddCommand(statusCmd)
}
