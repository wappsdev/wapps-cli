// Zarfin BAYT sozlesmesi (SPEC'in CLI hata zarfi): stderr'e TEK satir JSON.
// Oracle Go'nun `encoding/json`'i; bu testlerdeki beklenen dizeler Go ikilisinden
// pty altinda OLCULEREK alindi.
use wapps::clierr::{self, Code};

#[test]
fn envelope_is_one_json_line_with_go_field_order() {
    let e = clierr::Error::new(Code::AgentModeRefused,
        "surface refused in agent mode (prints secret values or is irreversible)");
    let mut buf = Vec::new();
    clierr::emit(&mut buf, &e);
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "{\"error\":\"AGENT_MODE_REFUSED\",\"message\":\"surface refused in agent mode (prints secret values or is irreversible)\",\"recovery\":\"use exec/apply; a human can run get in a terminal\",\"retryable\":false}\n"
    );
}

// OLCULEN AYRISMA: Go'nun encoding/json'i `<`, `>`, `&`, U+2028 ve U+2029'u
// kacisla yaziyor; serde_json'in varsayilani YAZMIYOR. Sahada kurulu ikililer
// birinci bicimi uretiyor, o yuzden Rust tarafi Go'yu taklit ediyor.
#[test]
fn go_escapes_angle_brackets_ampersand_and_line_separators() {
    let e = clierr::Error::new(Code::Internal, "unknown flag: --<a>&b");
    let mut buf = Vec::new();
    clierr::emit(&mut buf, &e);
    let s = String::from_utf8(buf).unwrap();
    // Go ikilisinden OLCULEN bayt dizisi.
    assert!(s.contains(r"unknown flag: --\u003ca\u003e\u0026b"), "got: {s}");
    assert!(!s.contains("--<a>&b"), "ham hali kalmamali: {s}");
}

#[test]
fn line_and_paragraph_separators_are_escaped_like_go() {
    let e = clierr::Error::new(Code::Internal, "a\u{2028}b\u{2029}c");
    let mut buf = Vec::new();
    clierr::emit(&mut buf, &e);
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("a\\u2028b\\u2029c"), "got: {s}");
}
