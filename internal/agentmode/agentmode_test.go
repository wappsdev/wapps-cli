package agentmode

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/clierr"
)

func detector(env map[string]string, tty bool) Detector {
	return Detector{
		Env:           func(k string) string { return env[k] },
		StdinIsTTY:    func() bool { return tty },
		AllowOverride: true,
	}
}

func TestIsAgent_Detection(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		tty  bool
		want bool
	}{
		{"human TTY no markers", nil, true, false},
		{"non-TTY always agent", nil, false, true},
		{"CLAUDECODE marker", map[string]string{"CLAUDECODE": "1"}, true, true},
		{"CI marker", map[string]string{"CI": "true"}, true, true},
		{"woodpecker marker", map[string]string{"WOODPECKER": "true"}, true, true},
		{"override honored on TTY", map[string]string{"WAPPS_AGENT_MODE": "0"}, true, false},
		{"override IGNORED on non-TTY", map[string]string{"WAPPS_AGENT_MODE": "0"}, false, true},
		{"override cannot beat marker+non-TTY", map[string]string{"WAPPS_AGENT_MODE": "0", "CI": "1"}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, detector(tc.env, tc.tty).IsAgent())
		})
	}
}

func TestGuard_Policies(t *testing.T) {
	// İnsan modu: her politika serbest.
	require.NoError(t, Guard(PolicyRefuseAgent, false))
	require.NoError(t, Guard("", false))

	// Ajan modu.
	require.NoError(t, Guard(PolicyAllow, true))

	err := Guard(PolicyRefuseAgent, true)
	require.True(t, clierr.Is(err, clierr.AgentModeRefused))

	err = Guard(PolicyControl, true)
	require.True(t, clierr.Is(err, clierr.ControlPlaneRequired))

	err = Guard(PolicyTTY, true)
	require.True(t, clierr.Is(err, clierr.AgentModeRefused))

	// Annotation'sız (fail-closed) → REFUSED.
	err = Guard("", true)
	require.True(t, clierr.Is(err, clierr.AgentModeRefused), "unannotated verb must fail closed in agent mode")

	err = Guard("some_future_policy", true)
	require.True(t, clierr.Is(err, clierr.AgentModeRefused), "unknown policy must fail closed")
}
