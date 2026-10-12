//! Canonical identity bytes: compact JSON, keys in the order the typed struct
//! declares them (every canonical struct declares them sorted), and Python
//! `ensure_ascii=True` string escaping: every non-ASCII scalar and U+007F become
//! lowercase `\uXXXX` UTF-16 escapes. This is not gojson's GoEscape (which also
//! escapes `<>&`) and not serde_json's default UTF-8 output.
use ring::digest::{digest, SHA256};
use serde::Serialize;
use std::io::{self, Write};

struct Ascii;

impl serde_json::ser::Formatter for Ascii {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        for c in fragment.chars() {
            if c.is_ascii() && c != '\x7f' {
                writer.write_all(&[c as u8])?;
            } else {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

pub(super) fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value
        .serialize(&mut serde_json::Serializer::with_formatter(&mut out, Ascii))
        .expect("typed values serialize to memory");
    out
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
