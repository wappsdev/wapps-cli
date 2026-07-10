package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func req(exec Executor, project, key string, params map[string]string) Request {
	p := map[string]string{"project": project, "key": key}
	for k, v := range params {
		p[k] = v
	}
	return Request{Project: project, Key: key, Params: p, Exec: exec, Now: fixedNow}
}

// TestRecipe_DBRolePhase1_Order, db-role/phase1'in adım sırasını kanıtlar: mint →
// ALTER ROLE → env push → RESTART → probe. gateway-last + DESUPER_PHASE=phase1
// semantiği params ile Executor'a taşınır; ordering worklist topolojisinde uygulanır.
func TestRecipe_DBRolePhase1_Order(t *testing.T) {
	m := NewMockExecutor()
	r := dbRolePhase1{}
	rq := req(m, testProject, "DB_URL", map[string]string{"verify": "deploy-verification"})

	newVal, err := r.Rotate(context.Background(), rq)
	require.NoError(t, err)
	require.NotEmpty(t, newVal, "db-role recipe mints a fresh password")

	require.NoError(t, r.Apply(context.Background(), rq, newVal))
	require.NoError(t, r.Verify(context.Background(), rq, newVal))

	assert.Equal(t, []string{"mint", "alter-role", "push-env", "restart", "probe"},
		m.OpsFor(testProject, "DB_URL"), "ALTER ROLE first, then env push, then MANDATORY restart, then probe")
}

// TestRecipe_CoolifyStart_RestartMandatory, coolify-env/start'ın env push'tan SONRA
// ZORUNLU /start yaptığını kanıtlar (Coolify v4: env değişikliği restart olmadan
// etki etmez, §8.6.1).
func TestRecipe_CoolifyStart_RestartMandatory(t *testing.T) {
	m := NewMockExecutor()
	r := coolifyStart{}
	rq := req(m, testProject, "VITE_API_URL", nil)
	newVal, err := r.Rotate(context.Background(), rq)
	require.NoError(t, err)
	require.NoError(t, r.Apply(context.Background(), rq, newVal))
	require.NoError(t, r.Verify(context.Background(), rq, newVal))

	ops := m.OpsFor(testProject, "VITE_API_URL")
	assert.Equal(t, []string{"mint", "push-env", "restart", "probe"}, ops)
	// env push MUTLAKA restart'tan önce.
	assert.Less(t, indexOf(ops, "push-env"), indexOf(ops, "restart"), "env PATCH before mandatory /start")
}

// TestRecipe_WorkerSecret_DualKid, worker-secret'ın dual-kid rotasyonu yaptığını
// (yeni kid ile SetWorkerSecret) kanıtlar (§9).
func TestRecipe_WorkerSecret_DualKid(t *testing.T) {
	m := NewMockExecutor()
	r := workerSecret{}
	rq := req(m, testProject, "GATE_MINT_KEY", map[string]string{"kid": "v2"})
	newVal, err := r.Rotate(context.Background(), rq)
	require.NoError(t, err)
	require.NoError(t, r.Apply(context.Background(), rq, newVal))

	steps := m.AllOps()
	var found bool
	for _, s := range steps {
		if s.Op == "worker-secret" {
			assert.Equal(t, "v2", s.Kid, "dual-kid: new kid set while old stays valid")
			found = true
		}
	}
	assert.True(t, found, "worker-secret set via the Workers-scoped deploy path")
}

// TestRecipe_CFManual_RequiresConfirmation, cf-manual'ın insan onay token'ı OLMADAN
// CONSUMER_UPDATED'te reddettiğini (ErrConfirmationRequired) ve HİÇBİR otomatik
// yürütme yapmadığını kanıtlar (§8.6.4). Onayla → geçer.
func TestRecipe_CFManual_RequiresConfirmation(t *testing.T) {
	m := NewMockExecutor()
	r := manualRecipe{typ: RecipeCFManual, dashboard: "Cloudflare"}
	assert.True(t, r.Manual())

	rq := req(m, testProject, "CF_API_TOKEN", map[string]string{"dashboard_url": "https://dash.cloudflare.com"})

	// Onay YOK → reddedilir, sıfır yan-etki.
	err := r.Apply(context.Background(), rq, nil)
	require.ErrorIs(t, err, ErrConfirmationRequired)
	assert.Empty(t, m.AllOps(), "manual recipe performs NO auto-execution without confirmation")

	// Talimat üretir (değer içermez).
	assert.Contains(t, r.Instructions(rq), "MANUAL rotation")
	assert.Contains(t, r.Instructions(rq), "CF_API_TOKEN")

	// Onayla → geçer.
	rq.Confirm = "human-attested"
	require.NoError(t, r.Apply(context.Background(), rq, nil))
}

// TestStubExecutor_LiveNotWired, gerçek-Executor stub'ının her adımda açıkça
// ErrLiveExecutionNotWired döndüğünü kanıtlar (CANLI yürütme insan-eliyle, DEFER).
func TestStubExecutor_LiveNotWired(t *testing.T) {
	s := StubExecutor{}
	_, err := s.MintSecret(context.Background(), "db-password", nil)
	require.ErrorIs(t, err, ErrLiveExecutionNotWired)
	require.ErrorIs(t, s.AlterDBRole(context.Background(), nil, nil), ErrLiveExecutionNotWired)
	require.ErrorIs(t, s.PushCoolifyEnv(context.Background(), nil, nil), ErrLiveExecutionNotWired)
	require.ErrorIs(t, s.RestartCoolifyApp(context.Background(), nil), ErrLiveExecutionNotWired)
	require.ErrorIs(t, s.SetWorkerSecret(context.Background(), nil, nil, "k"), ErrLiveExecutionNotWired)
	require.ErrorIs(t, s.Probe(context.Background(), "smoke", nil), ErrLiveExecutionNotWired)
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}
