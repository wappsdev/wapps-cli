use broker_oracle::compare::first_difference;
use broker_oracle::template::{fill, matches, pointer_lookup};
use serde_json::json;

#[test]
fn a_placeholder_takes_the_type_of_what_it_names() {
    let frame = json!({"id": 7, "request_id": "r-1", "nested": {"token": 3}});
    let lookup = pointer_lookup(&frame);
    let filled = fill(
        &json!({"id": "{{id}}", "response": {"request_id": "{{request_id}}", "n": "{{nested.token}}"}}),
        &lookup,
    )
    .unwrap();
    assert_eq!(
        filled,
        json!({"id": 7, "response": {"request_id": "r-1", "n": 3}})
    );
}

#[test]
fn an_unresolved_placeholder_is_an_error_not_a_literal() {
    let frame = json!({"id": 1});
    let err = fill(&json!(["{{missing}}"]), &pointer_lookup(&frame)).unwrap_err();
    assert!(err.contains("missing"), "{err}");
}

#[test]
fn text_around_braces_is_not_a_placeholder() {
    let frame = json!({});
    let value = json!({"s": "a {{x}} b"});
    assert_eq!(fill(&value, &pointer_lookup(&frame)).unwrap(), value);
}

#[test]
fn a_pattern_matches_a_superset_object() {
    assert!(matches(
        &json!({"method": "initialize"}),
        &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    ));
    assert!(matches(
        &json!({"request": {"subtype": "initialize"}}),
        &json!({"type": "control_request", "request": {"subtype": "initialize", "hooks": {}}})
    ));
}

#[test]
fn a_pattern_does_not_match_a_different_value_or_a_missing_key() {
    assert!(!matches(
        &json!({"method": "initialize"}),
        &json!({"method": "tools/call"})
    ));
    assert!(!matches(&json!({"id": 1}), &json!({"method": "x"})));
    assert!(!matches(&json!([1, 2]), &json!([1, 2, 3])));
}

#[test]
fn equal_texts_have_no_difference() {
    assert_eq!(first_difference("a\nb\n", "a\nb\n"), None);
}

#[test]
fn the_first_differing_line_is_named_with_both_sides() {
    let d = first_difference("a\nb\nc\n", "a\nB\nc\n").unwrap();
    assert!(d.contains("line 2"), "{d}");
    assert!(d.contains("expected: b"), "{d}");
    assert!(d.contains("actual:   B"), "{d}");
}

#[test]
fn a_missing_tail_is_a_difference() {
    let d = first_difference("a\nb\n", "a\n").unwrap();
    assert!(d.contains("line 2"), "{d}");
    assert!(d.contains("<end of text>"), "{d}");
}
