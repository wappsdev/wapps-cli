package secrets

// wapps dr accept-epoch-reset — epoch-reset seremonisi (mimari §5.5, plan P1.5).
//
// Epoch pin'i (internal/store/epochpin.go) tam olarak şunu yakalamak için var:
// değiştirilmiş / yeniden kurulmuş (substituted/rebuilt) bir store. Pin'i
// indirmenin TEK meşru yolu bu verb'dür ve kural serttir (kritik H4):
//
//  1. Canlı audit-chain head'i gate'ten çekilir (GET /v1/audit/head, P1.4).
//  2. Operatör, kâğıt zarftaki head hash'inin İLK 12 hex karakterini YAZAR —
//     kâğıt değeri yazmak out-of-band doğrulamanın kendisidir (y/n DEĞİL).
//  3. Uyuşmazlık → HARD ABORT: store substitution varsayılır, incident açılır
//     (risk register #8). Bayrak asla "hata gidersin diye" verilmez.
//  4. Eşleşme → TEK bir Keys() çağrısı AcceptEpochReset:true ile yapılır; pin
//     sunulan epoch'a iner ve kalıcılaşır. Okuma X-Wapps-Intent: epoch-reset
//     ile etiketlenir (§6.4).
//
// AcceptEpochReset bayrağı exec/apply/get yollarına ASLA threadlenmez — yalnızca
// bu seremoninin 4. adımındaki tek çağrı içinde yaşar.

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/wappsdev/wapps-cli/internal/agentmode"
	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/session"
	"github.com/wappsdev/wapps-cli/internal/store"
)

var drEpochResetProject string

// epochResetStore, seremoninin gate'ten ihtiyaç duyduğu asgari yüzeydir
// (consumer-side interface — *store.WorkerStore uygular; testte fake).
type epochResetStore interface {
	AuditHead(ctx context.Context) (seq uint64, hash string, err error)
	Keys(ctx context.Context, project string) (*store.KeysResult, error)
}

// openEpochResetStore, PAKET-DÜZEYİ SEAM: seremoni istemcisini kurar.
// acceptReset yalnızca doğrulama SONRASI tek Keys() çağrısı için true olur —
// bayrak başka hiçbir store kurulumuna sızmaz (openWorkerStore'a bak: exec/
// apply/get her zaman default-false Config kullanır).
var openEpochResetStore = func(acceptReset bool) (epochResetStore, error) {
	doer, err := session.HTTPClient()
	if err != nil {
		return nil, err
	}
	return store.New(store.Config{
		BaseURL:          session.GateURL(),
		Doer:             doer,
		Auth:             session.Auth(),
		AcceptEpochReset: acceptReset,
	}), nil
}

// epochResetPrompt, kâğıt head hash'i prompt'unun PAKET-DÜZEYİ seam'idir
// (dr split/bootstrap kalıbı; testte scripted prompt). Yazılan 12-hex bir sır
// değildir ama aynı promptValueNoEcho helper'ı yeniden kullanılır — ortak imza
// + TTY tespiti hazır, yeni bir prompt yüzeyi açılmaz.
var epochResetPrompt = promptValueNoEcho

// headPrefixLen, operatörün kâğıttan yazdığı hex önekinin uzunluğu.
const headPrefixLen = 12

var hex12Re = regexp.MustCompile(`^[0-9a-f]{12}$`)

var drAcceptEpochResetCmd = &cobra.Command{
	Use:   "accept-epoch-reset --project <p>",
	Short: "TTY-only ceremony: verify the audit head against the PAPER envelope, then lower the epoch pin (§5.5)",
	Long: `accept-epoch-reset is the ONLY legitimate way to lower a project's local epoch
pin (rollback tripwire, internal/store/epochpin.go). It exists for ONE scenario:
the store was LEGITIMATELY rebuilt (F5) and clients must re-accept it.

The ceremony (§5.5, risk register #8):
  1. fetches the LIVE audit-chain head from the gate,
  2. asks you to TYPE the first 12 hex chars of the head hash FROM THE PAPER
     ENVELOPE (typing the paper value IS the out-of-band verification),
  3. on mismatch it HARD-ABORTS — store substitution is assumed; open an incident,
  4. on match it performs ONE pin-lowering read tagged X-Wapps-Intent: epoch-reset.

REFUSED in agent mode. The accept flag is never available on exec/apply/get.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runDrAcceptEpochReset(drEpochResetProject, agentmode.IsAgent(),
			cmd.OutOrStdout(), cmd.ErrOrStderr())
	},
}

// runDrAcceptEpochReset, seremoninin test edilebilir çekirdeğidir.
func runDrAcceptEpochReset(project string, isAgent bool, out, errW io.Writer) error {
	// (0) TTY-only guard HER ŞEYDEN ÖNCE: ajan modunda tek bir gate çağrısı /
	// prompt bile olmadan reddedilir (kritik H4 — sosyal mühendislik kolu).
	if err := agentmode.Guard(agentmode.PolicyTTY, isAgent); err != nil {
		return err
	}
	if project == "" {
		return clierr.New(clierr.Internal, "dr accept-epoch-reset: --project is required")
	}
	ctx := context.Background()

	// (1) Canlı audit head + mevcut pinned/served durumu (default-false store —
	// bu ön kontrol pin'i ASLA indiremez).
	st, err := openEpochResetStore(false)
	if err != nil {
		return err
	}
	seq, hash, err := st.AuditHead(ctx)
	if err != nil {
		return err
	}
	if len(hash) < headPrefixLen {
		return clierr.Newf(clierr.Internal, "dr accept-epoch-reset: gate returned a malformed head hash (len %d)", len(hash))
	}

	// Ön kontrol: served >= pinned ise indirilecek bir şey yok — seremoni no-op.
	if _, kerr := st.Keys(ctx, project); kerr == nil {
		fmt.Fprintf(out, "epoch pin for %q is already <= the served epoch — nothing to reset.\n", project)
		return nil
	} else if !clierr.Is(kerr, clierr.EpochDowngrade) {
		return kerr
	} else {
		// EPOCH_DOWNGRADE mesajı pinned/served çiftini içerir — operatöre durum
		// özeti olarak basılır (plan P1.5: "print pinned/served/head").
		fmt.Fprintf(out, "gate state: %s\n", kerr.Error())
	}
	fmt.Fprintf(out, "live audit head: seq=%d hash=%s\n\n", seq, hash)

	// (2) Out-of-band doğrulama: kâğıt zarftaki head hash'inin ilk 12 hex'i
	// YAZILIR (ekrandan kopyalamak doğrulama DEĞİLDİR — zarfı açın).
	fmt.Fprintln(errW, "Open the PAPER envelope (§5.3 kit). Do NOT copy from this screen —")
	fmt.Fprintln(errW, "type the value recorded on paper at the last successful dr verify.")
	typed, _, perr := epochResetPrompt(fmt.Sprintf("First %d hex chars of the PAPER head hash: ", headPrefixLen))
	if perr != nil {
		return clierr.Wrapf(clierr.Internal, perr, "dr accept-epoch-reset: read paper head prefix")
	}
	typed = strings.ToLower(strings.TrimSpace(typed))
	if !hex12Re.MatchString(typed) {
		return clierr.Newf(clierr.Internal,
			"dr accept-epoch-reset: expected exactly %d hex chars from the paper envelope", headPrefixLen)
	}
	if typed != strings.ToLower(hash[:headPrefixLen]) {
		// (3) HARD ABORT: pin'e DOKUNULMAZ, accepting store hiç kurulmaz.
		return clierr.New(clierr.EpochDowngrade,
			"paper head hash does NOT match the live audit head — store substitution assumed; open an incident (risk register #8)").
			WithRecovery("do NOT retry with a different value; verify custodian envelopes and open an incident (§5.5)")
	}

	// (4) Eşleşme: TEK pin-indiren Keys() çağrısı (AcceptEpochReset:true;
	// X-Wapps-Intent: epoch-reset etiketi store istemcisinde eklenir).
	acc, err := openEpochResetStore(true)
	if err != nil {
		return err
	}
	res, err := acc.Keys(ctx, project)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ epoch pin for %q reset to served epoch %d (audit head seq=%d verified against paper).\n",
		project, res.Epoch, seq)
	fmt.Fprintln(out, "NEXT: re-record the CURRENT head hash on paper and re-seal the envelopes (§5.5 verify→paper→seal loop).")
	return nil
}

func init() {
	drAcceptEpochResetCmd.Flags().StringVar(&drEpochResetProject, "project", "", "project whose epoch pin will be reset")
	DrCmd.AddCommand(drAcceptEpochResetCmd)
}
