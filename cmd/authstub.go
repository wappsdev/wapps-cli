package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

// whoami, login ve `token exchange` root-seviyesi verb'lerdir (SPEC §7.2).
// whoami her modda güvenlidir; login + token exchange CANLI CF Access gerektirir
// ve bu build'de THIN STUB'dır (doğru şekil + net NOT_AVAILABLE-in-CI mesajı).
// Tam implementasyon G9 (enroll/oturum) kapsamındadır.

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show local identity + roster pin (safe in every mode, §7.2)",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		home, err := trust.DefaultPinPath()
		if err == nil {
			if ps, perr := trust.LoadPinStore(home); perr == nil {
				fmt.Fprintf(w, "trust genesis pin:  admin_epoch=%d\n", ps.Genesis.AdminEpoch)
				fmt.Fprintf(w, "trust last-verified: admin_epoch=%d\n", ps.LastVerified.AdminEpoch)
			} else {
				fmt.Fprintln(w, "trust pins:          not initialized (run a fetch or wapps secrets enroll)")
			}
		}
		if identityMarkerPresent() {
			fmt.Fprintln(w, "identity:            enrolled (local decryption identity present)")
		} else {
			fmt.Fprintln(w, "identity:            not enrolled (run wapps secrets enroll in a terminal — G9)")
		}
		// bootstrap_solo, canlı roster'dan türetilir; loud render için roster fetch
		// gerekir (§7.2). Yerel-only whoami bunu fetch'siz bilemez → net not.
		fmt.Fprintln(w, "bootstrap_solo:      derived from the live roster (see wapps secrets status / a fetch)")
		return nil
	},
}

func identityMarkerPresent() bool {
	dir := wappsConfigDir()
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "identity.json"))
	return err == nil
}

func wappsConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wapps")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "wapps")
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "CF Access read-AUD login (24h session) — THIN STUB (needs a browser)",
	Long: `login performs the CF Access read-AUD browser flow to establish a 24h
session. It requires a live Cloudflare Access WebAuthn ceremony and a browser, so
it is NOT AVAILABLE in CI / agent contexts. Full flow ships with the session
manager (G9).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if agentmode.IsAgent() {
			return clierr.New(clierr.NotAvailable, "login requires a browser CF Access flow; not available in CI/agent mode")
		}
		return clierr.New(clierr.NotAvailable, "login is not wired in this build (needs a live CF Access browser flow); tracked for G9")
	},
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Machine-token operations (CI)",
}

var tokenExchangeCmd = &cobra.Command{
	Use:   "exchange",
	Short: "Exchange the per-repo CF Access service token for a scoped token — THIN STUB",
	Long: `token exchange swaps the per-repo CF Access service-token pair
(CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET) for a ≤10-min scoped machine
token via POST /v1/token (§6). It needs a live gate + valid service token, so it
is a THIN STUB here with the correct shape and a clear NOT_AVAILABLE message.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("CF_ACCESS_CLIENT_ID") == "" || os.Getenv("CF_ACCESS_CLIENT_SECRET") == "" {
			return clierr.New(clierr.TokenExchangeFailed, "CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET not set")
		}
		return clierr.New(clierr.NotAvailable, "token exchange needs a live gate + POST /v1/token; not wired in this build (tracked for the CI machine path)")
	},
}

func init() {
	tokenCmd.AddCommand(tokenExchangeCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(tokenCmd)
}
