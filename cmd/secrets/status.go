package secrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/cache"
	"github.com/wappsdev/wapps-cli/internal/store"
)

var statusJSON bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Machine-readable store/session/cache state (§7.10)",
	Long: `Report {online, session_valid, session_expires_in, epoch_pin, cache_age,
identity_present}. status is SAFE in every mode and every network state — it never
touches plaintext and never fails hard; it is the first command an agent runs when
anything else errors.`,
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
		fmt.Fprintf(w, "cache_age:        %ds\n", rep.CacheAge)
		fmt.Fprintf(w, "identity_present: %v\n", rep.IdentityPresent)
		return nil
	},
}

// StatusReport, §7.10 normatif şemasıdır (tam alan adları). session_expires_in
// ve cache_age SANİYE; epoch_pin per-proje pinlenmiş data epoch'u.
type StatusReport struct {
	Online           bool   `json:"online"`
	SessionValid     bool   `json:"session_valid"`
	SessionExpiresIn int64  `json:"session_expires_in"`
	EpochPin         uint64 `json:"epoch_pin"`
	CacheAge         int64  `json:"cache_age"`
	IdentityPresent  bool   `json:"identity_present"`
}

// gatherStatus, YEREL durumdan (ağ dokunuşu opsiyonel) raporu toplar. Hiçbir
// adım hata FIRLATMAZ — bilinmeyen alanlar false/0 kalır (§7.10 fail-safe).
func gatherStatus() StatusReport {
	project := statusProject()
	rep := StatusReport{
		Online:          probeGate(),
		EpochPin:        readEpochPin(project),
		CacheAge:        readCacheAge(project),
		IdentityPresent: identityPresent(),
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

// probeGate, gate'e (WAPPS_SECRETS_GATE set ise) kısa bir prob atar; HERHANGİ bir
// HTTP yanıtı (401 dahil) → online. Taşıma hatası/timeout → offline. WAPPS_SECRETS_GATE
// yoksa deterministik olarak false (dış host'a dokunmadan) — CI-güvenli.
func probeGate() bool {
	gate := os.Getenv("WAPPS_SECRETS_GATE")
	if gate == "" {
		return false
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(gate + "/v1/trust/current")
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

// readCacheAge, projenin ciphertext önbelleğinin yaşını saniye döner (yoksa -1).
func readCacheAge(project string) int64 {
	if project == "" {
		return -1
	}
	dir, err := cache.DefaultDir()
	if err != nil {
		return -1
	}
	ent, err := cache.Load(cache.PathFor(dir, project))
	if err != nil {
		return -1
	}
	return int64(ent.Age().Seconds())
}

// identityPresent, yerel bir enrolled çözme kimliği yüklenebiliyor mu (§7.10).
// G8'de kimlik deposu henüz yok → bir işaret dosyasının varlığı kontrol edilir
// (~/.config/wapps/identity.json); yoksa false. (Enroll = G9.)
func identityPresent() bool {
	dir, err := wappsHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, "identity.json"))
	return err == nil
}

// readSession, oturum dosyasından (login stub yazar) geçerlilik + kalan saniye.
// Yoksa/expired → (false, 0). (login = thin stub, canlı CF Access gerektirir.)
func readSession() (bool, int64) {
	dir, err := wappsHomeDir()
	if err != nil {
		return false, 0
	}
	data, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		return false, 0
	}
	var s struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return false, 0
	}
	rem := s.ExpiresAt - time.Now().Unix()
	if rem <= 0 {
		return false, 0
	}
	return true, rem
}

// wappsHomeDir, ~/.config/wapps döner (XDG onurlandırılır).
func wappsHomeDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "wapps"), nil
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "emit the machine-readable JSON schema (§7.10)")
	SecretsCmd.AddCommand(statusCmd)
}
