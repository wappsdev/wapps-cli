// Package deploy wires `wapps deploy` — the first-class client for the
// company-deploy-proxy, so deploying a service outside CI (manual ops,
// break-glass, an AI agent) has a supported path instead of hand-reconstructing
// the pipeline's inline curl + gathering creds from two Tofu states.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wappsdev/wapps-cli/cmd/secrets"
	deploypkg "github.com/wappsdev/wapps-cli/internal/deploy"
)

var (
	flagRepo     string
	flagWait     bool
	flagTimeout  int
	flagInterval int
	flagEP       string
	flagJSON     bool
)

// repoAliases maps the ergonomic --repo flag to the Tofu registry key (used by
// the deferred tier-3 tofu fallback) and validates --repo. The only real alias
// is vaulter → vaulter-api; the rest are identity. The env token key uses the
// FLAG value upper-cased (DEPLOY_PROXY_TOKEN_<REPO>), not the registry key.
var repoAliases = map[string]string{
	"vaulter":             "vaulter-api",
	"royco":               "royco",
	"supply-pro":          "supply-pro",
	"streamkit":           "streamkit",
	"stitchsense":         "stitchsense",
	"labellens-api":       "labellens-api",
	"kreeva-web":          "kreeva-web",
	"vibe-studio-backend": "vibe-studio-backend",
}

// DeployCmd is `wapps deploy <service>`.
var DeployCmd = &cobra.Command{
	Use:   "deploy <service>",
	Short: "Deploy a service through the company-deploy-proxy",
	Long: `Trigger a redeploy of a service via the company-deploy-proxy — the only
supported path for the root-level vaulter trio (proxy/db-admin/migrator) and
gateway, whose scoped Coolify tokens intentionally cannot deploy via the direct
Coolify API.

Credentials (proxy token + Cloudflare Access service-token) resolve env-first,
then the config-resolved archive (never printed):

  DEPLOY_PROXY_TOKEN_<REPO>             (or DEPLOY_PROXY_TOKEN / PROXY_TOKEN)
  DEPLOY_PROXY_CF_ACCESS_CLIENT_ID      (or CF_ACCESS_CLIENT_ID)
  DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET  (or CF_ACCESS_CLIENT_SECRET)
  DEPLOY_PROXY_EP                       (default https://deploy-proxy.meapps.dev)

Examples:
  wapps deploy migrator --repo vaulter --wait
  wapps deploy gateway  --repo vaulter --wait
  wapps deploy auth     --json

Exit codes: 0 ok · 1 usage · 2 creds · 3 auth/scope · 4 CF Access · 5 network ·
6 proxy/upstream · 7 timeout · 8 deploy failed.`,
	Args: cobra.ExactArgs(1),
	// SilenceErrors/Usage: this command prints its own messages and owns its
	// exit code (callers depend on the 0-8 contract), so cobra must not also
	// print or override it.
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := deployOptions{
			service:  args[0],
			repo:     flagRepo,
			wait:     flagWait,
			timeout:  time.Duration(flagTimeout) * time.Second,
			interval: time.Duration(flagInterval) * time.Second,
			ep:       flagEP,
			asJSON:   flagJSON,
		}
		os.Exit(runDeploy(opts, cmd.OutOrStdout(), cmd.ErrOrStderr()))
		return nil
	},
}

type deployOptions struct {
	service  string
	repo     string
	wait     bool
	timeout  time.Duration
	interval time.Duration
	ep       string
	asJSON   bool
}

// jsonResult is the --json output shape (§1.4). Never contains secrets.
type jsonResult struct {
	Service        string `json:"service"`
	Repo           string `json:"repo"`
	DeploymentUUID string `json:"deployment_uuid,omitempty"`
	Status         string `json:"status,omitempty"`
	Outcome        string `json:"outcome"`
	ExitCode       int    `json:"exit_code"`
}

// runDeploy is the testable core: it returns the process exit code and writes
// all human/JSON output. No os.Exit here so tests can assert the code.
func runDeploy(opts deployOptions, out, errW io.Writer) int {
	res := jsonResult{Service: opts.service, Repo: opts.repo, Outcome: "error"}

	finish := func(code int, outcome, humanMsg string) int {
		res.ExitCode = code
		res.Outcome = outcome
		if opts.asJSON {
			line, _ := json.Marshal(res)
			fmt.Fprintln(out, string(line))
		} else if humanMsg != "" {
			w := out
			if code != deploypkg.ExitOK {
				w = errW
			}
			fmt.Fprintln(w, humanMsg)
		}
		return code
	}

	// 1. Local validation — no network on a bad repo/service (exit 1).
	if _, ok := repoAliases[opts.repo]; !ok {
		return finish(deploypkg.ExitUsage, "error",
			fmt.Sprintf("usage: unknown repo %q (known: %s)", opts.repo, knownRepos()))
	}
	if err := deploypkg.ValidateServiceName(opts.service); err != nil {
		return finish(deploypkg.ExitUsage, "error", err.Error())
	}

	// 2. Credentials (env → archive). exit 2 if unresolved.
	creds, missing, archErr := resolveCreds(opts.repo, opts.ep)
	if missing != "" {
		msg := fmt.Sprintf("error: could not resolve %s (tried env, archive)", missing)
		if archErr != nil {
			// A present-but-undecryptable archive (wrong passphrase / corrupt)
			// is distinct from a missing key — say so (the error names no value).
			msg += fmt.Sprintf("\n  note: archive present but could not be read: %v", archErr)
		}
		return finish(deploypkg.ExitCreds, "error", msg)
	}

	client := deploypkg.New(creds, opts.repo)
	ctx := context.Background()

	if !opts.asJSON {
		fmt.Fprintf(out, "Deploying %q (repo %s) via %s …\n", opts.service, opts.repo, creds.Endpoint)
	}

	// 3. Trigger.
	uuid, derr := client.Trigger(ctx, opts.service)
	if derr != nil {
		return finish(derr.Code, "error", derr.Error())
	}
	res.DeploymentUUID = uuid

	if !opts.wait {
		return finish(deploypkg.ExitOK, "triggered",
			fmt.Sprintf("%s: triggered (%s)", opts.service, uuid))
	}

	// 4. Wait.
	timeout := opts.timeout
	if timeout <= 0 {
		timeout = 1200 * time.Second
	}
	interval := opts.interval
	if interval <= 0 {
		interval = deploypkg.DefaultPollInterval
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Under --json the poll lines would corrupt the single-object stdout
	// contract (§1.4); discard them — the final JSON carries the last status.
	statusW := out
	if opts.asJSON {
		statusW = io.Discard
	}
	status, werr := client.Wait(waitCtx, uuid, opts.service, interval, timeout, statusW)
	res.Status = status
	if werr != nil {
		outcome := "error"
		switch werr.Code {
		case deploypkg.ExitTimeout:
			outcome = "timeout"
		case deploypkg.ExitFailed:
			outcome = "failed"
		}
		return finish(werr.Code, outcome, werr.Error())
	}
	return finish(deploypkg.ExitOK, "success",
		fmt.Sprintf("✓ %s deployed (%s)", opts.service, status))
}

// resolveCreds resolves the four values env-first then archive (tier-3 auto-tofu
// is deferred — the archive, via P2, is the operator single-source; the env
// covers CI). Returns the creds, the name of the first missing required key for
// the exit-2 message (never a value) if any, and a non-nil archErr when the
// archive was present but could not be decrypted/parsed (wrong passphrase /
// corrupt) — distinct from a benign absent archive, so the caller can tell the
// operator which it is. A genuinely broken archive does NOT abort resolution:
// env-first means env may still supply every credential.
func resolveCreds(repo, epOverride string) (creds deploypkg.Creds, missing string, archErr error) {
	suffix := strings.ToUpper(strings.ReplaceAll(repo, "-", "_"))
	tokenKeys := []string{"DEPLOY_PROXY_TOKEN_" + suffix, "DEPLOY_PROXY_TOKEN", "PROXY_TOKEN"}
	cfIDKeys := []string{"DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_ID"}
	cfSecretKeys := []string{"DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "CF_ACCESS_CLIENT_SECRET"}
	epKeys := []string{"DEPLOY_PROXY_EP"}

	// One archive read for every candidate key. A decrypt/parse failure is kept
	// (archErr) but does not block env-only resolution.
	all := append(append(append(append([]string{}, tokenKeys...), cfIDKeys...), cfSecretKeys...), epKeys...)
	archive, archErr := secrets.ArchiveValues(all...)

	resolve := func(keys []string) string {
		for _, k := range keys { // env tier first, in priority order
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
		for _, k := range keys { // then archive tier
			if v := archive[k]; v != "" {
				return v
			}
		}
		return ""
	}

	creds = deploypkg.Creds{
		Token:          resolve(tokenKeys),
		CFAccessID:     resolve(cfIDKeys),
		CFAccessSecret: resolve(cfSecretKeys),
		Endpoint:       epOverride,
	}
	if creds.Endpoint == "" {
		creds.Endpoint = resolve(epKeys)
	}
	if creds.Endpoint == "" {
		creds.Endpoint = deploypkg.DefaultEndpoint
	}

	switch {
	case creds.Token == "":
		missing = "DEPLOY_PROXY_TOKEN_" + suffix
	case creds.CFAccessID == "":
		missing = "DEPLOY_PROXY_CF_ACCESS_CLIENT_ID"
	case creds.CFAccessSecret == "":
		missing = "DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET"
	}
	return creds, missing, archErr
}

func knownRepos() string {
	names := make([]string, 0, len(repoAliases))
	for k := range repoAliases {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func init() {
	DeployCmd.Flags().StringVar(&flagRepo, "repo", "vaulter", "Logical repo whose scoped token + app subset to use")
	DeployCmd.Flags().BoolVar(&flagWait, "wait", false, "Poll until the deployment finishes (or fails/times out)")
	DeployCmd.Flags().IntVar(&flagTimeout, "timeout", 1200, "Seconds to wait with --wait before timing out (must stay < 90m)")
	DeployCmd.Flags().IntVar(&flagInterval, "poll-interval", 15, "Seconds between status polls under --wait")
	DeployCmd.Flags().StringVar(&flagEP, "ep", "", "Deploy-proxy base URL (default DEPLOY_PROXY_EP or "+deploypkg.DefaultEndpoint+")")
	DeployCmd.Flags().BoolVar(&flagJSON, "json", false, "Emit one machine-readable JSON line instead of human status (still AI-safe)")
}
