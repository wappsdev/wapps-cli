package clierr

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wappsdev/wapps-cli/internal/safelog"
)

type wire struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	Recovery  string `json:"recovery"`
	Retryable bool   `json:"retryable"`
}

func TestEmit_Envelope(t *testing.T) {
	var buf bytes.Buffer
	Emit(&buf, New(BindingUnpinned, "repo not pinned"))

	var w wire
	require.NoError(t, json.Unmarshal(buf.Bytes(), &w))
	require.Equal(t, "BINDING_UNPINNED", w.Error)
	require.Equal(t, "run wapps secrets trust-repo in a terminal", w.Recovery)
	require.False(t, w.Retryable)
	// Tek satır.
	require.Equal(t, 1, bytes.Count(buf.Bytes(), []byte("\n")))
}

func TestEmit_RetryableCode(t *testing.T) {
	var buf bytes.Buffer
	Emit(&buf, New(OfflineWriteBlocked, "worker down"))
	var w wire
	require.NoError(t, json.Unmarshal(buf.Bytes(), &w))
	require.True(t, w.Retryable)
	require.Contains(t, w.Recovery, "never queued")
}

func TestEmit_NeverLeaksSecretValue(t *testing.T) {
	secret := "sk_live_" + "AbCdEf0123456789XyZmixedCASE"
	var buf bytes.Buffer
	// safelog.Wrap ile sarılan bir değer [REDACTED] olur.
	Emit(&buf, Newf(Internal, "failed to store %s", safelog.Wrap(secret)))
	require.NotContains(t, buf.String(), secret)
	require.Contains(t, buf.String(), safelog.Redacted)
}

func TestEmit_SanitizesExternalTokenInMessage(t *testing.T) {
	// Dış kaynaktan gelen (Worker/HTML) yüksek-entropili token mesaja sızarsa
	// RedactPatterns onu kısaltır.
	token := "AbCdEf0123456789GhIjKlMnOpQrStUv"
	var buf bytes.Buffer
	Emit(&buf, Newf(Internal, "upstream said: %s", token))
	require.NotContains(t, buf.String(), token)
}

func TestEmit_WrapsPlainError(t *testing.T) {
	var buf bytes.Buffer
	Emit(&buf, errors.New("some raw error"))
	var w wire
	require.NoError(t, json.Unmarshal(buf.Bytes(), &w))
	require.Equal(t, "INTERNAL", w.Error)
}

func TestIs(t *testing.T) {
	err := New(CASConflict, "race")
	require.True(t, Is(err, CASConflict))
	require.False(t, Is(err, AuthExpired))
	require.False(t, Is(errors.New("x"), CASConflict))
}

func TestWithRecovery(t *testing.T) {
	err := New(CASConflict, "race").WithRecovery("re-run foo; writers: a@1, b@2")
	var buf bytes.Buffer
	Emit(&buf, err)
	require.Contains(t, buf.String(), "writers: a@1, b@2")
}
