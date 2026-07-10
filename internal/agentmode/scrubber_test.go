package agentmode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScrubber_RedactsExactValue, temel agent-safety kanıtı: enjekte edilen bir
// gizli değeri echo'layan çıktı `***` olur; değer ASLA görünmez.
func TestScrubber_RedactsExactValue(t *testing.T) {
	secret := "postgres://user:sup3rs3cr3t@db/prod"
	var buf bytes.Buffer
	s := NewScrubber(&buf, []string{secret})

	_, err := s.Write([]byte("connecting to " + secret + " now\n"))
	require.NoError(t, err)
	require.NoError(t, s.Flush())

	out := buf.String()
	require.NotContains(t, out, secret, "secret value must never reach output")
	require.Contains(t, out, Redaction)
	require.Contains(t, out, "connecting to *** now")
}

// TestScrubber_SplitAcrossChunks, chunk sınırında bölünen bir değerin yine
// yakalandığını doğrular (rolling boundary buffer).
func TestScrubber_SplitAcrossChunks(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	var buf bytes.Buffer
	s := NewScrubber(&buf, []string{secret})

	// Değeri iki Write arasında böl.
	_, err := s.Write([]byte("key=AKIAIOSF"))
	require.NoError(t, err)
	_, err = s.Write([]byte("ODNN7EXAMPLE done"))
	require.NoError(t, err)
	require.NoError(t, s.Flush())

	out := buf.String()
	require.NotContains(t, out, secret, "split value must still be redacted")
	require.Equal(t, "key=*** done", out)
}

// TestScrubber_ManyTinyChunks, değerin bayt-bayt gelmesi durumunda da yakalar.
func TestScrubber_ManyTinyChunks(t *testing.T) {
	secret := "s3cr3t-token-value-XYZ"
	var buf bytes.Buffer
	s := NewScrubber(&buf, []string{secret})

	payload := "before " + secret + " after"
	for i := 0; i < len(payload); i++ {
		_, err := s.Write([]byte{payload[i]})
		require.NoError(t, err)
	}
	require.NoError(t, s.Flush())

	out := buf.String()
	require.NotContains(t, out, secret)
	require.Equal(t, "before *** after", out)
}

// TestScrubber_MultipleValuesLongestFirst, örtüşen değerlerde en uzunu redakte
// eder ve hepsini gizler.
func TestScrubber_MultipleValuesLongestFirst(t *testing.T) {
	var buf bytes.Buffer
	s := NewScrubber(&buf, []string{"secret", "topsecret", "pw"})
	_, err := s.Write([]byte("a=topsecret b=secret c=pw"))
	require.NoError(t, err)
	require.NoError(t, s.Flush())
	out := buf.String()
	require.NotContains(t, out, "topsecret")
	require.NotContains(t, out, "secret")
	require.False(t, strings.Contains(out, "=pw"), "short value pw must also be redacted: %q", out)
}

// TestScrubber_Passthrough, değer yoksa çıktı aynen geçer.
func TestScrubber_Passthrough(t *testing.T) {
	var buf bytes.Buffer
	s := NewScrubber(&buf, nil)
	_, err := s.Write([]byte("no secrets here\n"))
	require.NoError(t, err)
	require.NoError(t, s.Flush())
	require.Equal(t, "no secrets here\n", buf.String())
}

// TestScrubber_EmptyAndDupeValuesIgnored, boş/tekrar değerler elenir.
func TestScrubber_EmptyAndDupeValuesIgnored(t *testing.T) {
	var buf bytes.Buffer
	s := NewScrubber(&buf, []string{"", "x", "x"})
	_, err := s.Write([]byte("y=x z"))
	require.NoError(t, err)
	require.NoError(t, s.Flush())
	require.Equal(t, "y=*** z", buf.String())
}

// TestScrubber_ValueAtVeryEnd, değer akışın en sonundaysa Flush'ta yakalanır.
func TestScrubber_ValueAtVeryEnd(t *testing.T) {
	secret := "trailing-secret-1234"
	var buf bytes.Buffer
	s := NewScrubber(&buf, []string{secret})
	_, err := s.Write([]byte("val=" + secret))
	require.NoError(t, err)
	require.NoError(t, s.Flush())
	require.Equal(t, "val=***", buf.String())
	require.NotContains(t, buf.String(), secret)
}
