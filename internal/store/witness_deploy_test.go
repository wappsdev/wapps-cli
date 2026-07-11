package store

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
	"github.com/wappsdev/wapps-cli/internal/intent"
)

// intent.Witness'i store'un deploy fresh-or-fail yolunda (read.go) tükettiğini
// kanıtlar (SPEC §7.3.4 / §9.3.4): tanık epoch > çekilen → WITNESS_CONTRADICTION;
// tanık erişilemez → WITNESS_UNREACHABLE (fail-closed, F6). Gerçek HTTPWitness
// implementasyonu ayrıca internal/witness'te CheckWitness ile test edilir; bu
// test store'un KABLOSUNU (cfg.Witness consumption) doğrular.

// fixedWitness, deterministik bir intent.Witness stub'ıdır.
type fixedWitness struct {
	epoch uint64
	err   error
}

func (w fixedWitness) HeadEpoch() (uint64, error) { return w.epoch, w.err }

// storeWithWitness, verilen tanıkla (aynı fakeWorker + dizin) bir store kurar.
func (f *fixture) storeWithWitness(t *testing.T, w intent.Witness) *WorkerStore {
	t.Helper()
	dir := f.storeDir(t)
	return New(Config{
		BaseURL:      f.server.srv.URL,
		Doer:         f.server.srv.Client(),
		PinPath:      dir + "/roots.json",
		CacheDir:     dir + "/cache",
		EpochPinPath: dir + "/epochs.json",
		Witness:      w,
		Now:          f.server.now,
	})
}

func TestFetch_DeployWitnessContradiction(t *testing.T) {
	f := newFixture(t)
	_ = f.seed(t) // epoch1 → pin=1
	st := f.storeWithWitness(t, fixedWitness{epoch: 9})
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Deploy})
	require.True(t, clierr.Is(err, clierr.WitnessContradiction), "witness epoch 9 > fetched 1 must hard-fail: %v", err)
}

func TestFetch_DeployWitnessUnreachableFailsClosed(t *testing.T) {
	f := newFixture(t)
	_ = f.seed(t)
	st := f.storeWithWitness(t, fixedWitness{err: errors.New("witness origin unreachable")})
	_, err := st.Fetch(context.Background(), testProject, FetchOpts{Intent: intent.Deploy})
	require.True(t, clierr.Is(err, clierr.WitnessUnreachable), "witness-unreachable under deploy must fail closed: %v", err)
}
