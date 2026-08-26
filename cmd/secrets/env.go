package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/atomicfile"
)

var (
	envWritePath string
	envPrefix    string
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Emit the project's secrets as .envrc-style export lines",
	Long: `Emit the project's secrets as 'export KEY=VALUE' lines.

By default writes to stdout (printable). Use --write <file> to write to a
file silently (AI-safe path — no secret value reaches stdout, terminal,
or LLM transcript).

Keys are emitted under the name they are stored with. --prefix prepends
something to every key; it is idempotent, so a key that already starts with
the prefix is emitted unchanged.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// env'in print-form'u (--write yok) gizli DÜZ METİN basar → ajan modunda
		// YAPISAL red; env --write FILE serbest kalır (§7.4.2).
		if envWritePath == "" {
			if err := agentmode.Guard(agentmode.PolicyRefuseAgent, agentmode.IsAgent()); err != nil {
				return err
			}
		}
		return runEnv(envWritePath, envPrefix, os.Stdout)
	},
}

// runEnv is the testable entry point for `wapps secrets env`.
//
// writePath: when non-empty, env output is written to this file (0600,
// atomic temp+rename) and stdoutW receives nothing. When empty, output
// goes to stdoutW. The AI-safe pattern (P4 from /office-hours, refined
// in eng review D9) requires this — agents call `env --write` so that
// secret values never reach stdout/transcript/log.
//
// prefix: prepended to every key on emit. Varsayılan BOŞ: anahtarlar store'da
// nihai env-var adıyla durur (TF_VAR_cloudflare_api_token, AWS_ACCESS_KEY_ID),
// dolayısıyla eklenecek bir şey yoktur.
func runEnv(writePath, prefix string, stdoutW io.Writer) error {
	cfg, err := requireStoreConfig("env")
	if err != nil {
		return err
	}
	return runEnvStore(cfg, writePath, prefix, stdoutW)
}

// writeEnvFileAtomic, env çıktısını writePath'e ATOMİK ve 0600 ile yazar.
//
// NEDEN atomicfile.Write — ve neden ARTIK kendi yazıcısı DEĞİL: burada eskiden
// ikinci bir "atomik yazıcı" duruyordu ve depoda ZATEN duran birinden üç
// noktada ayrılıyordu. Üçüncüsü bir GÜVENLİK kusuruydu:
//
//   atomicfile.Write          eski yazıcı (burası)
//   -----------------------   ---------------------------------------------
//   `.<ad>.<rastgele>.tmp`    `<hedef>.tmp` — SABİT, tahmin edilebilir ad
//   O_EXCL (CreateTemp)       O_CREATE|O_TRUNC — VAR OLANI yeniden kullanır
//   mod açıkça uygulanır      0600 İSTENİR ama var olan dosyanın modu KALIR
//   fsync VAR                 fsync YOK
//
// open(2): "the mode argument shall be ignored if the file exists". Yani
// hedefin yanında önceden duran 0644 modlu bir `<hedef>.tmp` varsa istenen
// 0600 HİÇ uygulanmıyor, O_TRUNC içeriği siliyor, düz metin sır oraya
// yazılıyor ve rename onu hedefe taşıyor → DÜNYA-OKUNUR SIR DOSYASI. Rastgele
// ad + O_EXCL bu pencerenin tamamını kapatır: bayat dosya artık HİÇ açılmıyor.
//
// HATA METNİ geçici dosyanın adını TAŞIMAZ: o ad rastgeledir, yani aynı hata
// iki koşuda iki farklı cümle üretirdi. Adlandırılan şey HEDEF — kullanıcının
// yazdığı ve tanıyabileceği yol.
func writeEnvFileAtomic(writePath string, valuesJSON []byte, prefix string) error {
	// Biçimlendirme ÖNCE tampona: bir ayrıştırma hatası halinde diskte hiçbir
	// şey oluşmaz (eski yazıcı önce dosyayı açıp sonra siliyordu).
	var buf bytes.Buffer
	if err := writeTofuOutputsAsEnv(valuesJSON, prefix, &buf); err != nil {
		return err
	}
	if err := atomicfile.Write(writePath, buf.Bytes(), 0600); err != nil {
		// PathError'ın içindeki errno alınır; sarmalayan metin rastgele temp
		// adını taşıyor ve deterministik değil.
		var pe *os.PathError
		if errors.As(err, &pe) {
			return fmt.Errorf("env: write %s: %v", writePath, pe.Err)
		}
		return fmt.Errorf("env: write %s: %v", writePath, err)
	}
	return nil
}

// envName applies the source prefix to a key idempotently: a key that already
// starts with the prefix is emitted verbatim, never double-prefixed. This keeps
// a mixed key set correct — Tofu outputs are stored bare (e.g. coolify_uuid →
// TF_VAR_coolify_uuid) while file-source secrets carried in already prefixed
// (e.g. TF_VAR_gemini_api_key) round-trip unchanged instead of becoming
// TF_VAR_TF_VAR_gemini_api_key. An empty prefix emits every key as-is.
func envName(prefix, key string) string {
	if prefix == "" || strings.HasPrefix(key, prefix) {
		return key
	}
	return prefix + key
}

// writeTofuOutputsAsEnv parses tofu-output-shaped JSON and emits
// `export <prefix><key>='<value>'` lines to w. Output keys are sorted for
// deterministic output (important for tests + git diff stability).
//
// Value type dispatch:
//   - string → emit unquoted shell value (with single-quote escaping)
//   - list/map/bool/number/null → emit raw JSON inside single quotes. Tofu
//     re-parses TF_VAR_<name> as JSON, so non-string types round-trip without
//     loss. This is what fixes Bug 1 (forcing string here used to crash on
//     vaulter_traefik_cert_paths and other list outputs).
func writeTofuOutputsAsEnv(jsonInput []byte, prefix string, w io.Writer) error {
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(jsonInput, &outputs); err != nil {
		return fmt.Errorf("env: parse values: %w", err)
	}

	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		raw := outputs[k].Value
		trimmed := bytes.TrimSpace(raw)
		name := envName(prefix, k)

		// JSON null: emit literal 'null' so the user can see it explicitly.
		// Otherwise json.Unmarshal would silently zero the destination string
		// and we'd lose the signal.
		if string(trimmed) == "null" {
			fmt.Fprintf(w, "export %s='null'\n", name)
			continue
		}

		// String: emit unquoted shell value with single-quote escape.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			escaped := strings.ReplaceAll(s, "'", "'\\''")
			fmt.Fprintf(w, "export %s='%s'\n", name, escaped)
			continue
		}

		// Non-string (list/map/bool/number): emit compact JSON inside single
		// quotes so Tofu re-parses it without whitespace artifacts. This fixes
		// Bug 1 — non-string outputs no longer crash unmarshal.
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			// Fallback: raw isn't valid JSON but reached us anyway. Strip
			// whitespace and emit literally so the user can debug.
			compact.WriteString(strings.TrimSpace(string(raw)))
		}
		escaped := strings.ReplaceAll(compact.String(), "'", "'\\''")
		fmt.Fprintf(w, "export %s='%s'\n", name, escaped)
	}
	return nil
}

func init() {
	envCmd.Flags().StringVar(&envWritePath, "write", "",
		"write env output to this file (0600, atomic) instead of stdout; AI-safe path that never prints values")
	envCmd.Flags().StringVar(&envPrefix, "prefix", "",
		"prefix prepended to each KEY (default: none — keys are stored under their final name)")
	SecretsCmd.AddCommand(envCmd)
}
