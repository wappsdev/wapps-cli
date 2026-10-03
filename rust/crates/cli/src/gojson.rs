// gojson, Go `encoding/json` behavior on top of serde_json: Go's escaping on
// output, and Go's struct-decoding rules on input (see the second section).
//
// WHY ESCAPING: the installed `wapps` binaries produce the envelope with Go,
// and Go escapes `<`, `>`, `&` (HTML safety) and U+2028/U+2029 (JSONP safety)
// as \uXXXX by default. serde_json writes NONE of them. The divergence was
// MEASURED and is exactly these five characters; field order, spacing and
// `retryable` were already identical.
//
// Decision: the SERIALIZER changed, not the goldens. Changing the goldens
// would change behavior for a consumer in the field; aligning the serializer
// changes nothing — it produces the same bytes.
use serde_json::ser::Formatter;
use std::io;

pub struct GoEscape;

impl Formatter for GoEscape {
    // serde_json passes the fragments that need NO escaping through here
    // (quote, backslash and control characters are handled separately). The
    // five characters Go additionally escapes are caught here.
    fn write_string_fragment<W>(&mut self, w: &mut W, frag: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut last = 0usize;
        for (i, c) in frag.char_indices() {
            let esc = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            w.write_all(&frag.as_bytes()[last..i])?;
            w.write_all(esc.as_bytes())?;
            last = i + c.len_utf8();
        }
        w.write_all(&frag.as_bytes()[last..])
    }
}

/// to_string, single-line JSON with Go-compatible escaping.
pub fn to_string<T: serde::Serialize>(v: &T) -> serde_json::Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscape);
    v.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json always produces valid UTF-8"))
}

/// GoEscapePretty, the SAME bytes as `json.MarshalIndent(v, "", "  ")`:
/// serde_json's indented layout + the five characters Go additionally escapes.
///
/// Why: the epoch pin file is SHARED with the Go binary. If the two binaries
/// wrote the same pin with different bytes, every measurement comparing the
/// file (the differential included) would see a false difference — and worse,
/// a user switching between the binaries would get the file rewritten every
/// time.
pub struct GoEscapePretty<'a> {
    inner: serde_json::ser::PrettyFormatter<'a>,
}

impl Default for GoEscapePretty<'_> {
    fn default() -> Self {
        GoEscapePretty {
            inner: serde_json::ser::PrettyFormatter::with_indent(b"  "),
        }
    }
}

impl Formatter for GoEscapePretty<'_> {
    fn write_string_fragment<W>(&mut self, w: &mut W, frag: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        GoEscape.write_string_fragment(w, frag)
    }

    fn begin_array<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_array(w)
    }
    fn end_array<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_array(w)
    }
    fn begin_array_value<W>(&mut self, w: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_array_value(w, first)
    }
    fn end_array_value<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_array_value(w)
    }
    fn begin_object<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_object(w)
    }
    fn end_object<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_object(w)
    }
    fn begin_object_key<W>(&mut self, w: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_object_key(w, first)
    }
    fn begin_object_value<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.begin_object_value(w)
    }
    fn end_object_value<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.inner.end_object_value(w)
    }
}

/// to_string_indent, 2-space indented JSON with Go-compatible escaping
/// (`json.MarshalIndent(v, "", "  ")`). NO trailing newline — Go adds none.
pub fn to_string_indent<T: serde::Serialize>(v: &T) -> serde_json::Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoEscapePretty::default());
    v.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json always produces valid UTF-8"))
}

/// quote, imitates Go's `%q`.
///
/// LIMIT: Rust's `{:?}` and Go's strconv.Quote diverge on non-printable
/// characters (`\u{7}` vs `\a`). The values on this path are project and key
/// NAMES, where the two forms agree. If a diverging name ever shows up, this
/// must be written by hand; the limit is accepted knowingly, not assumed away.
pub fn quote(s: &str) -> String {
    format!("{s:?}")
}

// --- decoding into a flat Go struct ------------------------------------------------
//
// `wapps login` decodes two Go structs (session.State and session.Claims) and
// the oracle's `json.Unmarshal` differs from a serde derive in ways a user
// can see: `null` is accepted anywhere and changes nothing, keys match
// case-insensitively with the LAST matching key winning, and a type error is
// a fixed English sentence that names the first offending field in DOCUMENT
// order. All of it was measured from a Go 1.26 program (tests/session.rs).
//
// Scope is exactly what those two structs need: string and int64 fields.
// Syntax errors are translated for the two shapes a non-JSON payload
// actually takes (empty input, a first byte that cannot start a value);
// every other syntax error keeps serde's sentence, which is a known and
// unmeasured divergence. Key folding is ASCII-only — Go also folds the
// Kelvin sign and the long s, which no claim name here contains.

/// GoField, the Go type of one struct field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GoField {
    Str,
    Int64,
}

/// GoValue, a decoded field value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GoValue {
    Str(String),
    Int64(i64),
}

/// GoStruct, the names a Go type error prints: `go_type` for a top-level
/// mismatch ("session.Claims"), `name` for a field one ("Claims.exp").
pub struct GoStruct<'a> {
    pub go_type: &'a str,
    pub name: &'a str,
    pub fields: &'a [(&'a str, GoField)],
}

/// decode_struct, `json.Unmarshal(raw, &v)` for a struct of string/int64
/// fields. Returns one slot per field, `None` where no key set it.
pub fn decode_struct(raw: &[u8], st: &GoStruct<'_>) -> Result<Vec<Option<GoValue>>, String> {
    // Go validates the WHOLE input before decoding anything, so a syntax error
    // wins over a type error that appears earlier in the document.
    if let Err(e) = serde_json::from_slice::<serde::de::IgnoredAny>(raw) {
        return Err(go_syntax_error(raw, &e));
    }
    let top: Box<serde_json::value::RawValue> =
        serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let mut slots = vec![None; st.fields.len()];
    let text = top.get();
    match kind_of(text) {
        "null" => return Ok(slots),
        "object" => {}
        other => {
            return Err(format!(
                "json: cannot unmarshal {other} into Go value of type {}",
                st.go_type
            ))
        }
    }
    let entries: Entries = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut first_err: Option<String> = None;
    for (key, value) in entries.0 {
        let Some(i) = st
            .fields
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(&key))
        else {
            continue;
        };
        let (name, ty) = st.fields[i];
        let v = value.get();
        let kind = kind_of(v);
        if kind == "null" {
            continue;
        }
        let decoded = match (ty, kind) {
            (GoField::Str, "string") => serde_json::from_str::<String>(v).ok().map(GoValue::Str),
            (GoField::Int64, "number") => v.parse::<i64>().ok().map(GoValue::Int64),
            _ => None,
        };
        match decoded {
            Some(d) => slots[i] = Some(d),
            None => {
                if first_err.is_none() {
                    let (what, go_ty) = match ty {
                        // Go names the literal only for numbers into ints.
                        GoField::Int64 if kind == "number" => (format!("number {v}"), "int64"),
                        GoField::Int64 => (kind.to_string(), "int64"),
                        GoField::Str => (kind.to_string(), "string"),
                    };
                    first_err = Some(format!(
                        "json: cannot unmarshal {what} into Go struct field {}.{name} of type {go_ty}",
                        st.name
                    ));
                }
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(slots),
    }
}

/// RawPairs, a JSON object as (key, raw value) pairs in document order.
pub type RawPairs = Vec<(String, Box<serde_json::value::RawValue>)>;

/// decode_raw_object, `json.Unmarshal(raw, &v)` where v is a type that takes a
/// JSON object as (key, raw value) pairs: a `map[string]json.RawMessage`, or
/// a struct whose fields are all `json.RawMessage`. `go_type` is the name Go
/// prints in a type error.
///
/// `Ok(None)` is a top-level `null` (Go leaves the target untouched). Pairs
/// come back in DOCUMENT order with duplicates kept; the caller decides which
/// one wins (for both target types, the last one).
pub fn decode_raw_object(raw: &[u8], go_type: &str) -> Result<Option<RawPairs>, String> {
    if let Err(e) = serde_json::from_slice::<serde::de::IgnoredAny>(raw) {
        return Err(go_syntax_error(raw, &e));
    }
    let top: Box<serde_json::value::RawValue> =
        serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    match kind_of(top.get()) {
        "null" => Ok(None),
        "object" => {
            let entries: Entries = serde_json::from_str(top.get()).map_err(|e| e.to_string())?;
            Ok(Some(entries.0))
        }
        other => Err(format!(
            "json: cannot unmarshal {other} into Go value of type {go_type}"
        )),
    }
}

/// compact, `json.Compact` on a VALID JSON text: insignificant whitespace is
/// dropped and nothing else changes — key order, number text and string
/// escapes stay byte-for-byte. Re-serializing through serde_json::Value would
/// reorder object keys and rewrite numbers (`2.50` -> `2.5`).
pub fn compact(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let (mut in_str, mut esc) = (false, false);
    for c in raw.chars() {
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            ' ' | '\t' | '\n' | '\r' => {}
            '"' => {
                in_str = true;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

// kind_of, the JSON kind of a raw value, named the way Go's type errors do.
fn kind_of(raw: &str) -> &'static str {
    match raw.trim_start().as_bytes().first() {
        Some(b'"') => "string",
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b't') | Some(b'f') => "bool",
        Some(b'n') => "null",
        _ => "number",
    }
}

// go_syntax_error, Go's sentence for the two syntax errors it is translated
// for; serde's own sentence otherwise (see the section comment).
fn go_syntax_error(raw: &[u8], e: &serde_json::Error) -> String {
    let first = raw
        .iter()
        .copied()
        .find(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r'));
    match first {
        None => "unexpected end of JSON input".to_string(),
        Some(c)
            if !matches!(
                c,
                b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
            ) =>
        {
            format!(
                "invalid character {} looking for beginning of value",
                go_quote_char(c)
            )
        }
        _ => trailing_data_error(raw).unwrap_or_else(|| e.to_string()),
    }
}

// trailing_data_error, Go's sentence for a valid value followed by more
// non-space bytes: "invalid character 'x' after top-level value". None when
// the input is not of that shape.
fn trailing_data_error(raw: &[u8]) -> Option<String> {
    let mut it = serde_json::Deserializer::from_slice(raw).into_iter::<serde::de::IgnoredAny>();
    it.next()?.ok()?;
    let rest = &raw[it.byte_offset()..];
    let c = rest
        .iter()
        .copied()
        .find(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r'))?;
    Some(format!(
        "invalid character {} after top-level value",
        go_quote_char(c)
    ))
}

// go_quote_char, encoding/json's quoteChar: `'\''`, `'"'`, else strconv.Quote
// of the byte with the double quotes swapped for single ones.
fn go_quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".to_string(),
        b'"' => "'\"'".to_string(),
        0x20..=0x7e => format!("'{}'", c as char),
        b'\x07' => "'\\a'".to_string(),
        b'\x08' => "'\\b'".to_string(),
        b'\x0c' => "'\\f'".to_string(),
        b'\x0b' => "'\\v'".to_string(),
        _ if c < 0x80 => format!("'\\x{c:02x}'"),
        // A non-ASCII first byte starts a multi-byte rune in Go's message;
        // the exact rune text is not measured.
        _ => format!("'\\x{c:02x}'"),
    }
}

// Entries, a JSON object as its (key, raw value) pairs in DOCUMENT order,
// duplicates kept — the order Go's decoder walks.
struct Entries(Vec<(String, Box<serde_json::value::RawValue>)>);

impl<'de> serde::Deserialize<'de> for Entries {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Entries;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Entries, A::Error> {
                let mut out = Vec::new();
                while let Some(e) = m.next_entry::<String, Box<serde_json::value::RawValue>>()? {
                    out.push(e);
                }
                Ok(Entries(out))
            }
        }
        d.deserialize_map(V)
    }
}
