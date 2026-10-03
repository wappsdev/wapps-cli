// gobase64, Go's `encoding/base64`, written by hand.
//
// Three functions, one per caller:
//   * `std_decode` — `base64.StdEncoding` as `dr restore` reads it (moved here
//     unchanged from drverb.rs, where it was private);
//   * `raw_url_decode` — `base64.RawURLEncoding`, the JWT segment decoder
//     behind `wapps login` (looksLikeJWT + session.ParseClaims);
//   * `std_encode` — `base64.StdEncoding.EncodeToString`, the `custom_labels`
//     body of `coolify set-labels`.
//
// No base64 crate: the tree has none, and three small functions do not justify
// opening the dependency policy (same reasoning as `ring` in Cargo.toml).

/// std_decode, standard padded base64 (RFC 4648) — Go's
/// `base64.StdEncoding.DecodeString` as `dr restore` uses it.
///
/// STRICT, and strictness is a parity requirement here:
///   * the length must be a multiple of 4 (else CorruptInputError),
///   * padding ('=') only at the end and at most two,
///   * every byte outside the alphabet (newline INCLUDED) is rejected.
///
/// A lax decoder would accept a manifest Go rejects, which is a divergence.
pub fn std_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    if b.is_empty() {
        return Some(Vec::new());
    }
    let mut pad = 0usize;
    while pad < 2 && b[b.len() - 1 - pad] == b'=' {
        pad += 1;
    }
    let body = &b[..b.len() - pad];
    // No padding may remain inside the body ("A=B=" is rejected).
    if body.contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in body.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        match chunk.len() {
            4 => {
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
                out.push(acc as u8);
            }
            3 => {
                let acc = acc << 6;
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
            }
            2 => {
                let acc = acc << 12;
                out.push((acc >> 16) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// raw_url_decode, Go's `base64.RawURLEncoding.DecodeString`.
///
/// Measured from Go (tests/gobase64.rs), and three points differ from the
/// strict std decoder above:
///   * '\r' and '\n' are skipped anywhere in the input (Go's decoder ignores
///     them for every encoding);
///   * '=' is not padding here but an illegal byte — the encoding has none;
///   * trailing bits are not checked (the encoding is not Strict), so "YR"
///     decodes like "YQ".
///
/// A length that leaves a single dangling character is an error.
pub fn raw_url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let body: Vec<u8> = s.bytes().filter(|&c| c != b'\r' && c != b'\n').collect();
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    for chunk in body.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => {
                let acc = acc << 6;
                out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]);
            }
            2 => out.push(((acc << 12) >> 16) as u8),
            _ => return None,
        }
    }
    Some(out)
}

/// std_encode, Go's `base64.StdEncoding.EncodeToString`: the standard
/// alphabet, padded with '='. `coolify set-labels` sends `custom_labels` in
/// this form.
pub fn std_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let acc = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((acc >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
