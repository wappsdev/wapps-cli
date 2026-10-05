// The normalizer decides what "byte-equal" means for every seam, so each rule
// is pinned here by the case that would make it wrong.
use broker_oracle::normalize::Normalizer;

#[test]
fn literal_paths_are_replaced_longest_first() {
    let n = Normalizer::new()
        .literal("/tmp/bo-1", "<root>")
        .literal("/private/tmp/bo-1", "<root>");
    assert_eq!(
        n.apply("cwd /private/tmp/bo-1/proj and /tmp/bo-1/home"),
        "cwd <root>/proj and <root>/home"
    );
}

#[test]
fn uuids_are_numbered_by_first_occurrence_so_identity_survives() {
    let n = Normalizer::new().uuids();
    let a = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let b = "7C9E6679-7425-40DE-944B-E07FC1F90AE7";
    let text = format!("job {a} then {b} then {a} again");
    assert_eq!(
        n.apply(&text),
        "job <uuid-1> then <uuid-2> then <uuid-1> again"
    );
}

#[test]
fn a_uuid_inside_a_longer_hex_run_is_not_a_uuid() {
    let n = Normalizer::new().uuids();
    let text = "a0f8fad5b-d9cb-469f-a165-70867728950e0";
    assert_eq!(n.apply(text), text);
}

#[test]
fn key_strings_are_numbered_at_both_json_escaping_levels() {
    let n = Normalizer::new().key("capability");
    let raw = r#"{"capability":"AAA","x":1}"#;
    let nested = r#"{"text":"{\"capability\":\"BBB\",\"again\":\"AAA\"}"}"#;
    assert_eq!(n.apply(raw), r#"{"capability":"<capability-1>","x":1}"#);
    assert_eq!(
        n.apply(nested),
        r#"{"text":"{\"capability\":\"<capability-1>\",\"again\":\"AAA\"}"}"#
    );
}

#[test]
fn one_value_keeps_one_placeholder_across_a_whole_text() {
    let n = Normalizer::new().key("capability");
    let text = "{\"capability\":\"AAA\"}\n{\"capability\":\"BBB\"}\n{\"capability\":\"AAA\"}";
    assert_eq!(
        n.apply(text),
        "{\"capability\":\"<capability-1>\"}\n{\"capability\":\"<capability-2>\"}\n{\"capability\":\"<capability-1>\"}"
    );
}

#[test]
fn key_numbers_lose_their_value_but_not_their_type() {
    let n = Normalizer::new().key("waitedMs");
    assert_eq!(
        n.apply(r#"{"text":"{\"changed\":false,\"waitedMs\":2}"} {"waitedMs":1534.5,"y":0}"#),
        r#"{"text":"{\"changed\":false,\"waitedMs\":<waitedMs>}"} {"waitedMs":<waitedMs>,"y":0}"#
    );
}

#[test]
fn a_key_that_only_ends_with_the_name_is_left_alone() {
    let n = Normalizer::new().key("id");
    let text = r#"{"jobId":"abc","id":"x"}"#;
    assert_eq!(n.apply(text), r#"{"jobId":"abc","id":"<id-1>"}"#);
}

#[test]
fn null_and_boolean_values_are_not_rewritten() {
    let n = Normalizer::new().key("startedAt");
    let text = r#"{"startedAt":null}"#;
    assert_eq!(n.apply(text), text);
}

#[test]
fn rules_compose_in_the_order_given() {
    let n = Normalizer::new()
        .literal("/tmp/r", "<root>")
        .uuids()
        .key("digest");
    let text = r#"{"cwd":"/tmp/r/x","job":"0f8fad5b-d9cb-469f-a165-70867728950e","digest":"47f9460b65d5fb99"}"#;
    assert_eq!(
        n.apply(text),
        r#"{"cwd":"<root>/x","job":"<uuid-1>","digest":"<digest-1>"}"#
    );
}
