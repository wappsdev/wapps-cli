package rotation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// StubExecutor, gerçek-Executor YER-TUTUCUSUDUR (DEFER): CANLI yürütme — gerçek
// Postgres (vaulter-db-admin job), Coolify API (base64 env-PATCH + /start), CF
// Worker/Access — prod/hesaba karşı İNSAN-ELİYLE koşulur. Her adım açık bir
// ErrLiveExecutionNotWired döner ki motor test-edilebilir kalsın ve canlı yol
// asla sessizce "başardı" demesin.
//
// TODO(G14+): bu stub'ı gerçek adapter'larla değiştir:
//   - AlterDBRole → internal/... vaulter-db-admin job (DESUPER_PHASE=phase1)
//   - PushCoolifyEnv/RestartCoolifyApp → internal/coolify (base64 PATCH + /start)
//   - SetWorkerSecret → Workers-scoped deploy token (dual-kid)
//   - Probe → deploy-verification recipe (prod smoke)
type StubExecutor struct{}

func (StubExecutor) MintSecret(context.Context, string, map[string]string) ([]byte, error) {
	return nil, ErrLiveExecutionNotWired
}

func (StubExecutor) AlterDBRole(context.Context, map[string]string, []byte) error {
	return ErrLiveExecutionNotWired
}

func (StubExecutor) PushCoolifyEnv(context.Context, map[string]string, []byte) error {
	return ErrLiveExecutionNotWired
}

func (StubExecutor) RestartCoolifyApp(context.Context, map[string]string) error {
	return ErrLiveExecutionNotWired
}

func (StubExecutor) SetWorkerSecret(context.Context, map[string]string, []byte, string) error {
	return ErrLiveExecutionNotWired
}

func (StubExecutor) Probe(context.Context, string, map[string]string) error {
	return ErrLiveExecutionNotWired
}

var _ Executor = StubExecutor{}

// --- MockExecutor (test) ----------------------------------------------------

// MockStep, MockExecutor'ın kaydettiği tek bir yan-etkili adımdır (sıra + değer-
// varlığı iddiaları için). Gizli değer KAYDEDİLMEZ; yalnızca uzunluğu.
type MockStep struct {
	Op      string // "mint" | "alter-role" | "push-env" | "restart" | "worker-secret" | "probe"
	Project string
	Key     string
	Kid     string // worker-secret dual-kid
	Probe   string
	ValLen  int // yeni değerin uzunluğu (değerin kendisi değil)
}

// MockExecutor, Executor'ın deterministik test uygulamasıdır: her adımı SIRALI
// kaydeder (phase1-first/gateway-last + env-sonra-start iddiaları için) ve
// belirli bir probe'u başarısız kılacak biçimde yapılandırılabilir (resume testi).
type MockExecutor struct {
	mu    sync.Mutex
	Steps []MockStep

	// FailProbeFor, bu (project,key) için Probe'u bir kez başarısız kılar (interrupt
	// simülasyonu). Boşsa hiçbir probe başarısız olmaz.
	FailProbeFor map[string]bool
	// Healed, true olduğunda FailProbeFor artık uygulanmaz (resume iyileşmesi).
	Healed bool

	// Ctx alanları (recipe'lerin params'ından okunur) — iddialar için.
	seq int
}

// NewMockExecutor, boş bir mock kurar.
func NewMockExecutor() *MockExecutor {
	return &MockExecutor{FailProbeFor: map[string]bool{}}
}

func (m *MockExecutor) record(s MockStep) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.Steps = append(m.Steps, s)
}

// OpsFor, verilen (project,key) için kaydedilen adım Op'larını SIRAYLA döner.
func (m *MockExecutor) OpsFor(project, key string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, s := range m.Steps {
		if s.Project == project && s.Key == key {
			out = append(out, s.Op)
		}
	}
	return out
}

// AllOps, tüm adım Op'larını global SIRAYLA döner (ordering iddiaları için).
func (m *MockExecutor) AllOps() []MockStep {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MockStep, len(m.Steps))
	copy(out, m.Steps)
	return out
}

func (m *MockExecutor) MintSecret(_ context.Context, kind string, params map[string]string) ([]byte, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	val := []byte(kind + "-" + hex.EncodeToString(b))
	m.record(MockStep{Op: "mint", Project: params["project"], Key: params["key"], ValLen: len(val)})
	return val, nil
}

func (m *MockExecutor) AlterDBRole(_ context.Context, params map[string]string, newSecret []byte) error {
	m.record(MockStep{Op: "alter-role", Project: params["project"], Key: params["key"], ValLen: len(newSecret)})
	return nil
}

func (m *MockExecutor) PushCoolifyEnv(_ context.Context, params map[string]string, newSecret []byte) error {
	m.record(MockStep{Op: "push-env", Project: params["project"], Key: params["key"], ValLen: len(newSecret)})
	return nil
}

func (m *MockExecutor) RestartCoolifyApp(_ context.Context, params map[string]string) error {
	m.record(MockStep{Op: "restart", Project: params["project"], Key: params["key"]})
	return nil
}

func (m *MockExecutor) SetWorkerSecret(_ context.Context, params map[string]string, newSecret []byte, kid string) error {
	m.record(MockStep{Op: "worker-secret", Project: params["project"], Key: params["key"], Kid: kid, ValLen: len(newSecret)})
	return nil
}

func (m *MockExecutor) Probe(_ context.Context, probe string, params map[string]string) error {
	pk := params["project"] + "\x00" + params["key"]
	m.mu.Lock()
	fail := m.FailProbeFor[pk] && !m.Healed
	m.mu.Unlock()
	m.record(MockStep{Op: "probe", Project: params["project"], Key: params["key"], Probe: probe})
	if fail {
		return fmt.Errorf("rotation/mock: probe %q failed for %s (injected)", probe, pk)
	}
	return nil
}

var _ Executor = (*MockExecutor)(nil)
