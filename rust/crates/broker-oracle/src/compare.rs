//! Byte comparison of two recordings, reported as the first line that differs.

/// `None` when the texts are byte-equal; otherwise the first differing line,
/// with both sides, so a failure names its own cause.
pub fn first_difference(expected: &str, actual: &str) -> Option<String> {
    if expected == actual {
        return None;
    }
    let mut want = expected.split_inclusive('\n');
    let mut have = actual.split_inclusive('\n');
    let mut line = 1;
    loop {
        match (want.next(), have.next()) {
            (Some(w), Some(h)) if w == h => line += 1,
            (w, h) => {
                let show = |side: Option<&str>| match side {
                    None => "<end of text>".to_string(),
                    Some(text) => match text.strip_suffix('\n') {
                        Some(body) => body.to_string(),
                        None => format!("{text}<no newline at end>"),
                    },
                };
                return Some(format!(
                    "first difference at line {line}\nexpected: {}\nactual:   {}",
                    show(w),
                    show(h)
                ));
            }
        }
    }
}
