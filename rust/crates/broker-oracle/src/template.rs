//! Placeholders in scripted frames, and subset patterns over received ones.
//!
//! A script cannot know the id the daemon gave its request, or the capability a
//! claim minted, so a frame names them: a JSON string that is exactly
//! `{{path}}` is replaced by the value at that dot path, with the value's own
//! type (a fencing token stays a number). Text that merely contains braces is
//! left as it is. An unresolved name is an error, never a literal: a frame sent
//! with `{{id}}` in it would be a fake answering something nobody asked.

use serde_json::Value;

/// Looks a dot path (`request.request_id`) up in `frame`.
pub fn pointer_lookup(frame: &Value) -> impl Fn(&str) -> Option<Value> + '_ {
    move |path| {
        let pointer: String = path.split('.').map(|part| format!("/{part}")).collect();
        frame.pointer(&pointer).cloned()
    }
}

fn placeholder(text: &str) -> Option<&str> {
    let inner = text.strip_prefix("{{")?.strip_suffix("}}")?;
    (!inner.is_empty() && !inner.contains(['{', '}', ' '])).then_some(inner)
}

pub fn fill(value: &Value, lookup: &dyn Fn(&str) -> Option<Value>) -> Result<Value, String> {
    Ok(match value {
        Value::String(text) => match placeholder(text) {
            Some(name) => {
                lookup(name).ok_or_else(|| format!("unresolved placeholder {{{{{name}}}}}"))?
            }
            None => value.clone(),
        },
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| fill(item, lookup))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| Ok((key.clone(), fill(item, lookup)?)))
                .collect::<Result<_, String>>()?,
        ),
        _ => value.clone(),
    })
}

/// `pattern` matches `actual` when every key of every object in the pattern is
/// present in `actual` with a matching value. Arrays match element for element
/// and must have the same length; scalars must be equal.
pub fn matches(pattern: &Value, actual: &Value) -> bool {
    match (pattern, actual) {
        (Value::Object(want), Value::Object(have)) => want
            .iter()
            .all(|(key, value)| have.get(key).is_some_and(|got| matches(value, got))),
        (Value::Array(want), Value::Array(have)) => {
            want.len() == have.len() && want.iter().zip(have).all(|(w, h)| matches(w, h))
        }
        _ => pattern == actual,
    }
}
