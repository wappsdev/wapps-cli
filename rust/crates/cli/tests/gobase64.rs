// Go's `base64.RawURLEncoding.DecodeString`, the decoder behind `wapps login`'s
// JWT checks (looksLikeJWT + session.ParseClaims).
//
// Every expected value below was measured from a Go 1.26 program, not
// remembered. The three surprises it pins:
//   * '\r' and '\n' are SKIPPED, anywhere in the input (Go's decoder ignores
//     them for every encoding);
//   * trailing bits are NOT checked (the encoding is not Strict): "YR" decodes
//     to "a" just like "YQ";
//   * padding is not optional but FORBIDDEN: "eyJhIjoxfQ==" is an error.
use wapps::gobase64::{raw_url_decode, std_decode};

fn ok(s: &str, want: &[u8]) {
    assert_eq!(raw_url_decode(s).as_deref(), Some(want), "input {s:?}");
}

fn bad(s: &str) {
    assert_eq!(raw_url_decode(s), None, "input {s:?} must be rejected");
}

#[test]
fn decodes_unpadded_url_alphabet_input() {
    ok("", b"");
    ok("e30", b"{}");
    ok("eyJhIjoxfQ", b"{\"a\":1}");
    ok("ab", b"i");
    ok("abc", b"i\xb7");
    ok("abcd", b"i\xb7\x1d");
    ok("-_-_", b"\xfb\xff\xbf");
}

#[test]
fn padding_and_the_standard_alphabet_are_rejected() {
    bad("eyJhIjoxfQ==");
    bad("eyJhIjoxfQ=");
    bad("====");
    bad("ab=c");
    bad("+/+/");
}

#[test]
fn a_dangling_single_character_is_rejected() {
    bad("a");
    bad("Y");
    bad("abcde");
}

#[test]
fn newlines_are_skipped_not_rejected() {
    ok("ab\ncd", b"i\xb7\x1d");
    ok("a\r\nb", b"i");
    ok("e30\n", b"{}");
    ok("\n", b"");
}

#[test]
fn trailing_bits_are_not_checked() {
    ok("YQ", b"a");
    ok("YR", b"a");
}

// The padded standard decoder moved here from drverb.rs unchanged; `dr
// restore` keeps its strictness (a newline is an error there).
#[test]
fn the_std_decoder_kept_its_strictness() {
    assert_eq!(std_decode("e30=").as_deref(), Some(&b"{}"[..]));
    assert_eq!(std_decode("e30"), None);
    assert_eq!(std_decode("e30=\n"), None);
}
