#[allow(dead_code)]
#[path = "../src/broker/execution/quota.rs"]
mod quota;
#[allow(dead_code)]
#[path = "../src/broker/execution/types.rs"]
mod types;

use serde_json::Value;

// Frozen Node/Bun JSON.parse expectations from the independent finite-ingress
// experiments. Disabling float_roundtrip loses reset bits and changes windows.
#[test]
fn raw_fractional_reset_preserves_frozen_bits_through_quota_ingress() {
    let raw = r#"{"type":"token_count","rate_limits":{"primary":{"resets_at":997473240364.3429}}}"#;
    let values: [Value; 3] = [
        serde_json::from_str(raw).unwrap(),
        serde_json::from_slice(raw.as_bytes()).unwrap(),
        serde_json::from_reader(raw.as_bytes()).unwrap(),
    ];
    for value in values {
        let reset = quota::read_quota(&value).unwrap().resets_at.unwrap();
        assert_eq!(reset.to_bits(), 0x426d07c138a58af9);
        assert_eq!(
            value["rate_limits"]["primary"]["resets_at"].to_string(),
            "997473240364.3429"
        );
    }
    assert_eq!(
        serde_json::from_str::<f64>("997473240364.3429")
            .unwrap()
            .to_bits(),
        0x426d07c138a58af9
    );
}

#[test]
fn raw_maximum_finite_reset_is_retained() {
    let raw =
        r#"{"type":"rate_limit_event","rate_limit_info":{"resetsAt":1.7976931348623157e308}}"#;
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        quota::read_quota(&value)
            .unwrap()
            .resets_at
            .unwrap()
            .to_bits(),
        0x7fefffffffffffff
    );
}

#[test]
fn raw_finite_rounding_boundary_is_accepted_as_maximum_reset() {
    let raw =
        r#"{"type":"rate_limit_event","rate_limit_info":{"resetsAt":1.7976931348623158e308}}"#;
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        quota::read_quota(&value)
            .unwrap()
            .resets_at
            .unwrap()
            .to_bits(),
        0x7fefffffffffffff
    );
}

#[test]
fn raw_subnormal_reset_rounds_to_smallest_positive_value() {
    let raw =
        r#"{"type":"token_count","rate_limits":{"primary":{"resets_at":2.4703282292062328e-324}}}"#;
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        quota::read_quota(&value)
            .unwrap()
            .resets_at
            .unwrap()
            .to_bits(),
        1
    );
}

#[test]
fn raw_extreme_window_preserves_frozen_finite_label() {
    let raw = r#"{"type":"token_count","rate_limits":{"primary":{"window_minutes":-9.671262202318759e26}}}"#;
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        quota::read_quota(&value).unwrap().window,
        "-1.6118770337197931e+25h"
    );
}

#[test]
fn raw_value_preserves_numeric_lexemes_and_internal_whitespace() {
    let raw = " [ 997473240364.3429, 1e309, 9007199254740993 ] ";
    let value: Box<serde_json::value::RawValue> = serde_json::from_str(raw).unwrap();
    assert_eq!(
        value.get(),
        "[ 997473240364.3429, 1e309, 9007199254740993 ]"
    );
}

#[test]
fn overflowing_quota_json_remains_rejected_not_js_infinity() {
    for raw in [
        "1e309",
        "-1e309",
        r#"{"type":"token_count","rate_limits":{"primary":{"window_minutes":1e309,"resets_at":1e309}}}"#,
    ] {
        assert!(serde_json::from_str::<Value>(raw).is_err());
    }
}

#[test]
fn integer_wire_text_stays_exact_while_quota_projection_uses_f64() {
    let raw = r#"{"type":"token_count","rate_limits":{"primary":{"resets_at":9007199254740993}}}"#;
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        value["rate_limits"]["primary"]["resets_at"].to_string(),
        "9007199254740993"
    );
    assert_eq!(
        quota::read_quota(&value)
            .unwrap()
            .resets_at
            .unwrap()
            .to_bits(),
        0x4340000000000000
    );
}

#[test]
fn negative_zero_reset_retains_its_sign_and_rust_serialization() {
    let raw = r#"{"type":"token_count","rate_limits":{"primary":{"resets_at":-0}}}"#;
    let value: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        quota::read_quota(&value)
            .unwrap()
            .resets_at
            .unwrap()
            .to_bits(),
        0x8000000000000000
    );
    assert_eq!(
        value["rate_limits"]["primary"]["resets_at"].to_string(),
        "-0.0"
    );
}
