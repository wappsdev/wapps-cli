package safelog

import (
	"errors"
	"strings"
	"testing"
)

func TestWrap_RedactsInErrorf(t *testing.T) {
	secret := "supersecretvalue123"
	err := Errorf("decrypt failed for %s", Wrap(secret))
	msg := err.Error()
	if strings.Contains(msg, secret) {
		t.Errorf("secret leaked into error: %s", msg)
	}
	if !strings.Contains(msg, Redacted) {
		t.Errorf("expected [REDACTED] marker, got: %s", msg)
	}
}

func TestWrap_DoesNotAffectNonWrappedArgs(t *testing.T) {
	err := Errorf("path %s and secret %s", "/home/user/app", Wrap("token-abc-123"))
	msg := err.Error()
	if !strings.Contains(msg, "/home/user/app") {
		t.Errorf("non-secret path got redacted: %s", msg)
	}
	if strings.Contains(msg, "token-abc-123") {
		t.Errorf("wrapped secret leaked: %s", msg)
	}
}

func TestWrap_PreservesErrorWrapping(t *testing.T) {
	inner := errors.New("io: EOF")
	err := Errorf("read failed for %s: %w", Wrap("payload"), inner)
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is should still find wrapped error after safelog.Errorf")
	}
}

func TestWrap_StringerAlsoRedacts(t *testing.T) {
	// If someone passes a Wrap'd value to fmt.Sprintf by mistake, the
	// Stringer interface still produces [REDACTED] — defense in depth.
	s := Wrap("leaky-token").String()
	if s != Redacted {
		t.Errorf("Stringer should produce [REDACTED], got %q", s)
	}
}

func TestSprintf_RedactsWrap(t *testing.T) {
	s := Sprintf("oauth=%s", Wrap("xyz"))
	if strings.Contains(s, "xyz") {
		t.Errorf("Sprintf leaked: %q", s)
	}
}

func TestRedactPatterns_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	in := "error from API: token " + jwt + " expired"
	out := RedactPatterns(in)
	if strings.Contains(out, jwt) {
		t.Errorf("JWT not redacted: %s", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Errorf("expected [REDACTED] marker, got: %s", out)
	}
	if !strings.Contains(out, "error from API:") || !strings.Contains(out, "expired") {
		t.Errorf("non-secret context lost: %s", out)
	}
}

func TestRedactPatterns_LongMixedToken(t *testing.T) {
	token := "AKIAIOSFODNN7EXAMPLEKEY12"
	in := "AWS error: invalid key " + token
	out := RedactPatterns(in)
	if strings.Contains(out, token) {
		t.Errorf("mixed-case token not redacted: %s", out)
	}
}

func TestRedactPatterns_PreservesPaths(t *testing.T) {
	// All-lowercase paths must NOT be redacted (false positive risk).
	in := "could not open /home/user/long/path/to/config/file.yaml"
	out := RedactPatterns(in)
	if out != in {
		t.Errorf("path got redacted unexpectedly:\nin:  %s\nout: %s", in, out)
	}
}

func TestRedactPatterns_PreservesShortIdentifiers(t *testing.T) {
	// Short tokens (UUIDs, config keys) survive — too risky to redact at
	// <24 chars since UUIDs and many normal identifiers fall in that range.
	in := "user_id=abc123 session_id=ghj456"
	out := RedactPatterns(in)
	if out != in {
		t.Errorf("short identifier got redacted:\nin:  %s\nout: %s", in, out)
	}
}

func TestRedactPatterns_PreservesAllLowerOrAllUpper(t *testing.T) {
	// All-lowercase: likely word or path. All-uppercase: likely env var name.
	// Neither should be redacted by the heuristic.
	cases := []string{
		"averylongallloweridentifierwithnocapsordigits",
		"VERYLONGALLUPPERIDENTIFIERWITHNOLOWERSORDIGITS",
	}
	for _, in := range cases {
		out := RedactPatterns(in)
		if out != in {
			t.Errorf("single-class identifier got redacted:\nin:  %s\nout: %s", in, out)
		}
	}
}

func TestRedactPatterns_NoMatch_PassesThrough(t *testing.T) {
	in := "plain English error message with no secrets"
	out := RedactPatterns(in)
	if out != in {
		t.Errorf("plain text was modified: %s", out)
	}
}

func TestPrintf_RedactsWrap(t *testing.T) {
	// We can't easily capture os.Stdout from inside this test without
	// extra plumbing — Printf is verified indirectly through Sprintf
	// (same sanitize path).
	s := Sprintf("DEBUG: %s", Wrap("x"))
	if strings.Contains(s, "x") && len(s) > 5 {
		// Only flag if the literal "x" appears not as part of a larger word.
		// The string "x" might match accidentally; check for [REDACTED].
		if !strings.Contains(s, Redacted) {
			t.Errorf("redaction missing in Sprintf path: %q", s)
		}
	}
}
