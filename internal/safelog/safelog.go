// Package safelog provides explicit redaction primitives for error messages
// and log output in secret-handling code paths.
//
// Design choice (post-Codex challenge in eng-review D11): we EXPLICITLY mark
// secret-bearing args via Wrap() rather than auto-redact strings via heuristic
// regex. Reasons:
//
//   - Heuristic auto-redact has false positives (long paths get redacted) AND
//     false negatives (short tokens slip through). Both create false
//     confidence: developers see "[REDACTED]" appear in some messages and
//     assume safelog handles every case.
//   - Explicit Wrap() forces the developer to think "is this value a secret?"
//     at the call site. The compiler and code review can both catch a missing
//     Wrap() on a value-bearing arg.
//
// Narrow scope (per D11): only cmd/secrets/*, internal/source/*, and
// internal/ageutil/* should depend on this package. cmd/coolify/, cmd/git/,
// cmd/doctor.go don't handle secret values and stay free of safelog churn.
//
// Usage:
//
//	import "github.com/wappsdev/wapps-cli/internal/safelog"
//
//	if err := decrypt(value); err != nil {
//	    return safelog.Errorf("decrypt failed for %s: %w",
//	        safelog.Wrap(value), err)
//	}
//
// Without Wrap, safelog.Errorf behaves identically to fmt.Errorf — there's
// no implicit redaction. The package exists to give you a one-line way to
// redact when you DO have a secret-bearing arg.
package safelog

import (
	"fmt"
	"regexp"
)

// Redacted is the literal string substituted for a Wrap'd value. Tests can
// match against this constant to confirm redaction happened.
const Redacted = "[REDACTED]"

// secretArg is the marker type for explicitly-redacted args. It is unexported
// — callers create instances via Wrap() so the only way to mark "redact this"
// is the one approved API.
type secretArg struct {
	// length is preserved for diagnostics — "value of length 32 failed
	// parse" is useful without leaking the value itself.
	length int
}

// Wrap marks v as secret-bearing. Errorf/Logf substitute [REDACTED] when
// they encounter a secretArg in their args list. Other formatters (plain
// fmt.Errorf, log.Printf) see the marker's String() method which also
// returns [REDACTED], so accidental misuse still redacts.
//
// Edge case: an empty Wrap("") still redacts, since the developer's intent
// was clearly "treat as secret."
func Wrap(v string) secretArg {
	return secretArg{length: len(v)}
}

// String implements fmt.Stringer. If a developer accidentally passes a
// Wrap'd value to fmt.Errorf/Printf (instead of safelog.Errorf), the
// fmt.Stringer interface still produces [REDACTED] — defense in depth.
func (s secretArg) String() string {
	return Redacted
}

// Errorf is fmt.Errorf with secretArg substitution. Args that are
// secretArg are replaced with [REDACTED] before format runs. All other
// args pass through unchanged.
//
// Note: %w error wrapping still works (errors.Is/As over the result).
func Errorf(format string, args ...interface{}) error {
	return fmt.Errorf(format, sanitize(args)...)
}

// Sprintf is fmt.Sprintf with secretArg substitution.
func Sprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, sanitize(args)...)
}

// Printf is fmt.Printf with secretArg substitution. Use for stdout/stderr
// diagnostic output that might be transcript-captured.
func Printf(format string, args ...interface{}) {
	fmt.Printf(format, sanitize(args)...)
}

func sanitize(args []interface{}) []interface{} {
	out := make([]interface{}, len(args))
	for i, a := range args {
		if _, ok := a.(secretArg); ok {
			out[i] = Redacted
			continue
		}
		out[i] = a
	}
	return out
}

// RedactPatterns is a defense-in-depth helper for strings that may contain
// embedded secrets from EXTERNAL sources (third-party API errors, captured
// log lines). Substitutes common secret-shaped tokens with [REDACTED:N]
// (where N is length, preserved for diagnostics).
//
// Patterns matched:
//   - JWT: 3 base64-url segments separated by dots, each >= 8 chars
//   - Long high-entropy tokens: 24+ chars of [A-Za-z0-9_+/=-] with mixed case
//
// NOT matched (intentional — too high false-positive rate):
//   - Short tokens (<24 chars) — may be config values, UUIDs, etc.
//   - All-lowercase or all-uppercase strings — likely identifiers
//   - Strings containing spaces, slashes, or quotes — likely paths/sentences
//
// This is best-effort. Always prefer Wrap() at known-secret call sites.
func RedactPatterns(s string) string {
	// JWT first (most specific pattern).
	s = jwtRegex.ReplaceAllString(s, Redacted)
	// Then long mixed-case tokens.
	s = mixedTokenRegex.ReplaceAllStringFunc(s, func(match string) string {
		if !hasMixedCase(match) {
			return match
		}
		return fmt.Sprintf("[REDACTED:%d]", len(match))
	})
	return s
}

var (
	jwtRegex = regexp.MustCompile(`[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	// 24+ chars: long enough to be unlikely as a normal word, short enough
	// to catch typical API tokens.
	mixedTokenRegex = regexp.MustCompile(`\b[A-Za-z0-9_+/=-]{24,}\b`)
)

func hasMixedCase(s string) bool {
	var hasLower, hasUpper, hasDigit bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	// "Mixed" = at least two of (lower, upper, digit). All-lowercase paths
	// like /home/user/project survive; mixed tokens like AKIAIOSFODNN7EXAMPLE
	// get redacted.
	classes := 0
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	return classes >= 2
}
