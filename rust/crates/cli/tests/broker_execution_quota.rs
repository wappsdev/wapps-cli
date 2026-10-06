#[path = "../src/broker/execution/quota.rs"]
mod quota;
#[allow(dead_code)]
#[path = "../src/broker/execution/types.rs"]
mod types;

use quota::{classify_message, codex_event_payload, read_quota};
use serde_json::{json, Value};

// Literal expectations, independently checked against the frozen TypeScript source.
// These catch fraction/percentage confusion, coercion, rounding, field preference,
// reset-unit conversion, and accidental suppression of messages without quota.
const QUOTA_CASES: &str = r#"[
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":0.01,"rateLimitType":"five_hour","resetsAt":1787197490}},"want":{"provider":"claude","window":"five_hour","usedPercent":1,"resetsAt":1787197490.0,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":1}},"want":{"provider":"claude","window":"unspecified","usedPercent":100,"resetsAt":null,"status":"allowed_warning"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":0.005}},"want":{"provider":"claude","window":"unspecified","usedPercent":1,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":0.895,"status":"allowed"}},"want":{"provider":"claude","window":"unspecified","usedPercent":90,"resetsAt":null,"status":"allowed_warning"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":0.8949}},"want":{"provider":"claude","window":"unspecified","usedPercent":89,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":-2,"rateLimitType":"","resetsAt":-1.25}},"want":{"provider":"claude","window":"","usedPercent":0,"resetsAt":-1.25,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":1e308}},"want":{"provider":"claude","window":"unspecified","usedPercent":100,"resetsAt":null,"status":"allowed_warning"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":"0.95","status":"rejected","resetsAt":"1787197490"}},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"rejected"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":0.1,"status":"allowed_warning"}},"want":{"provider":"claude","window":"unspecified","usedPercent":10,"resetsAt":null,"status":"allowed_warning"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{"utilization":true,"status":"unknown","rateLimitType":22}},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":{}},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":[]},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":"synthetic-secret"},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":true},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":-1},"want":{"provider":"claude","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":1,"window_minutes":10080,"resets_at":1787197490}}},"want":{"provider":"codex","window":"7d","usedPercent":1,"resetsAt":1787197490.0,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":0.5,"window_minutes":30}}},"want":{"provider":"codex","window":"1h","usedPercent":1,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":0.49999999999999994,"window_minutes":29.99}}},"want":{"provider":"codex","window":"0h","usedPercent":0,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":89.5,"window_minutes":1440}}},"want":{"provider":"codex","window":"1d","usedPercent":90,"resetsAt":null,"status":"allowed_warning"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":101,"window_minutes":1439,"resets_at":0}}},"want":{"provider":"codex","window":"24h","usedPercent":100,"resetsAt":0.0,"status":"allowed_warning"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":-1,"window_minutes":2160,"resets_at":-0.5}}},"want":{"provider":"codex","window":"2d","usedPercent":0,"resetsAt":-0.5,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":99,"window_minutes":-30}}},"want":{"provider":"codex","window":"0h","usedPercent":99,"resetsAt":null,"status":"allowed_warning"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"window_minutes":-90}}},"want":{"provider":"codex","window":"-1h","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":"99","window_minutes":"60","resets_at":"1787197490","status":"rejected"}}},"want":{"provider":"codex","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"used_percent":1},"secondary":{"used_percent":100,"window_minutes":1440,"resets_at":123}}},"want":{"provider":"codex","window":"unspecified","usedPercent":1,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{}}},"want":{"provider":"codex","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":[]}},"want":{"provider":"codex","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":"synthetic-secret"}},"want":{"provider":"codex","window":"unspecified","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"window_minutes":1.44e24}}},"want":{"provider":"codex","window":"1e+21d","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"window_minutes":-6e22}}},"want":{"provider":"codex","window":"-1e+21h","usedPercent":null,"resetsAt":null,"status":"allowed"}},
 {"payload":{"type":"token_count","rate_limits":{"primary":{"window_minutes":60,"resets_at":100.125}}},"want":{"provider":"codex","window":"1h","usedPercent":null,"resetsAt":100.125,"status":"allowed"}},
 {"payload":{"type":"rate_limit_event","rate_limit_info":null},"want":null},
 {"payload":{"type":"rate_limit_event","rate_limit_info":false},"want":null},
 {"payload":{"type":"rate_limit_event","rate_limit_info":0},"want":null},
 {"payload":{"type":"rate_limit_event","rate_limit_info":""},"want":null},
 {"payload":{"type":"token_count","rate_limits":{"secondary":{"used_percent":100}}},"want":null},
 {"payload":{"type":"token_count","rate_limits":{"primary":false,"secondary":{"used_percent":100}}},"want":null},
 {"payload":{"type":"token_count","rate_limits":{"primary":null}},"want":null},
 {"payload":{"type":"token_count","rate_limits":{"primary":0}},"want":null},
 {"payload":{"type":"token_count","rate_limits":{"primary":""}},"want":null},
 {"payload":{"type":"token_count","rate_limits":true},"want":null},
 {"payload":{"type":"token_count","info":{"total_tokens":5}},"want":null},
 {"payload":{"type":"agent_message","message":"synthetic-secret"},"want":null},
 {"payload":{"type":"future_event","rate_limit_info":{"utilization":1}},"want":null},
 {"payload":{"type":99,"rate_limit_info":{}},"want":null},
 {"payload":null,"want":null}, {"payload":false,"want":null},
 {"payload":1,"want":null}, {"payload":"synthetic-secret","want":null},
 {"payload":[],"want":null}, {"payload":{},"want":null}
]"#;

const EVENT_CASES: &str = r#"[
 {"notification":{"method":"codex/event","params":{"msg":{"type":"token_count","rate_limits":{"primary":{}}}}},"admit":true,"suppress":true},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"token_count","info":{"total_tokens":5}}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"token_count","rate_limits":{"secondary":{"used_percent":100}}}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"token_count","rate_limits":{"primary":false}}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"agent_message","message":"synthetic-secret"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"session_configured","thread_id":"thread-synthetic"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"task_started"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"exec_command_begin","command":["echo","synthetic"]}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"patch_apply_begin"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"error","message":"synthetic-secret"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"item_started"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"item_completed"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"exec_command_end"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"patch_apply_end"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"turn_aborted"}}},"admit":true,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"agent_message_content_delta"}}},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"raw_response_item"}}},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"future_event","rate_limits":{"primary":{}}}}},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":"rate_limit_event","rate_limit_info":{}}}},"admit":false,"suppress":false},
 {"notification":{"method":"notifications/progress","params":{"msg":{"type":"agent_message"}}},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":{"type":true}}},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event","params":{"msg":null}},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event","params":[]},"admit":false,"suppress":false},
 {"notification":{"method":"codex/event"},"admit":false,"suppress":false},
 {"notification":null,"admit":false,"suppress":false},
 {"notification":[],"admit":false,"suppress":false},
 {"notification":"synthetic-secret","admit":false,"suppress":false}
]"#;

#[test]
fn reads_provider_specific_quota_without_coercion_or_reset_conversion() {
    let cases: Vec<Value> = serde_json::from_str(QUOTA_CASES).unwrap();
    for (index, case) in cases.iter().enumerate() {
        let actual = serde_json::to_value(read_quota(&case["payload"])).unwrap();
        assert_eq!(actual, case["want"], "quota fixture {index}");
    }
}

#[test]
fn quota_dependent_suppression_preserves_every_message_without_a_reading() {
    let cases: Vec<Value> = serde_json::from_str(QUOTA_CASES).unwrap();
    for (index, case) in cases.iter().enumerate() {
        let parsed = classify_message(&case["payload"]);
        assert_eq!(
            serde_json::to_value(parsed.quota).unwrap(),
            case["want"],
            "classified fixture {index}"
        );
        let suppress = case["payload"]["type"] == "token_count" && !case["want"].is_null();
        assert_eq!(parsed.suppress_progress, suppress, "noise fixture {index}");
    }
}

#[test]
fn codex_admits_only_source_watched_events_and_keeps_payload_identity() {
    let cases: Vec<Value> = serde_json::from_str(EVENT_CASES).unwrap();
    for (index, case) in cases.iter().enumerate() {
        let payload = codex_event_payload(&case["notification"]);
        assert_eq!(
            payload.is_some(),
            case["admit"].as_bool().unwrap(),
            "event fixture {index}"
        );
        if let Some(payload) = payload {
            assert!(std::ptr::eq(
                payload,
                &case["notification"]["params"]["msg"]
            ));
            assert_eq!(
                classify_message(payload).suppress_progress,
                case["suppress"].as_bool().unwrap(),
                "progress fixture {index}"
            );
        }
    }
}

#[test]
fn parser_diagnostics_do_not_echo_untrusted_windows_or_payload_fields() {
    let payload = json!({
        "type": "rate_limit_event",
        "capability": "synthetic-capability-do-not-log",
        "rate_limit_info": {"rateLimitType": "synthetic-window-do-not-log", "status": "rejected"}
    });
    let parsed = classify_message(&payload);
    assert!(parsed.quota.is_some());
    assert!(!parsed.suppress_progress);
    let diagnostic = format!("{parsed:?}");
    assert!(!diagnostic.contains("synthetic-window-do-not-log"));
    assert!(!diagnostic.contains("synthetic-capability-do-not-log"));
    // Raw provider reset data is retained even after its window has expired.
    // The parser does not decide storage selection or attention policy.
    let expired =
        json!({"type":"token_count", "rate_limits":{"primary":{"resets_at":1,"used_percent":99}}});
    assert_eq!(read_quota(&expired).unwrap().resets_at, Some(1.0));
}
