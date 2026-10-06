//! Pure path imports: execution remains unregistered and unavailable.
#[path = "../src/broker/execution/scrub.rs"]
mod scrub;

use scrub::{
    scrub_json, scrub_note_line_utf16_200, scrub_outbound, scrub_text,
    scrub_transcript_json_utf16_8192, OutboundText, ScrubError,
};
use serde_json::json;

#[test]
fn decodes_json_escapes_before_masking_values_and_secret_fields() {
    let result = scrub_json(
        r#"{"output":"fixture-known-secret\nTOKEN=small","apiKey":{"nested":"short"},"array":["Bearer abcdefgh",7,false],"plain":"Türkçe 😀"}"#,
        &["fixture-known-secret"],
    ).unwrap();
    assert_eq!(
        result,
        json!({"output":"[REDACTED]\nTOKEN=[REDACTED]","apiKey":"[REDACTED]","array":["Bearer [REDACTED]",7,false],"plain":"Türkçe 😀"})
    );
    assert_eq!(
        scrub_json(r#""fixture\"quoted\\secret""#, &["fixture\"quoted\\secret"]).unwrap(),
        json!("[REDACTED]")
    );
    let error = scrub_json("invalid fixture-secret", &[]).unwrap_err();
    assert_eq!(error, ScrubError::InvalidJson);
    assert_eq!(error.to_string(), "invalid scrub JSON");
    assert_eq!(format!("{error:?}"), "InvalidJson");
}

#[test]
fn note_line_scrubs_before_source_normalization_and_200_utf16_unit_bound() {
    assert_eq!(
        scrub_note_line_utf16_200("  first\nTOKEN=small\n  last \t", &[])
            .unwrap()
            .as_str(),
        "first TOKEN=[REDACTED] last"
    );
    assert_eq!(scrub_note_line_utf16_200(" \u{feff}\n", &[]), None);
    assert_eq!(
        scrub_note_line_utf16_200("\u{85}", &[]).unwrap().as_str(),
        "\u{85}"
    );
    let input = format!("{}😀trailing", "a".repeat(199));
    let result = scrub_note_line_utf16_200(&input, &[]).unwrap();
    assert_eq!(result.as_str(), format!("{}\u{fffd}", "a".repeat(199)));
    let input = format!("{}fixture-known-secret", "a".repeat(190));
    assert_eq!(
        scrub_note_line_utf16_200(&input, &["fixture-known-secret"])
            .unwrap()
            .as_str(),
        format!("{}[REDACTED]", "a".repeat(190))
    );
}

#[test]
fn transcript_json_bounds_each_scrubbed_string_in_utf16_not_bytes() {
    let ordinary = "é".repeat(8192);
    assert_eq!(
        scrub_transcript_json_utf16_8192(&serde_json::to_string(&ordinary).unwrap(), &[]).unwrap(),
        json!(ordinary)
    );
    let split = format!("{}😀z", "é".repeat(8191));
    let text = format!(
        "{}\u{fffd}\n[truncated, 8194 bytes total]",
        "é".repeat(8191)
    );
    assert_eq!(
        scrub_transcript_json_utf16_8192(&json!({"a":[split],"token":"private"}).to_string(), &[])
            .unwrap(),
        json!({"a":[text],"token":"[REDACTED]"})
    );
    let input = format!("{}fixture-known-secret", "x".repeat(8190));
    assert_eq!(
        scrub_transcript_json_utf16_8192(&json!(input).to_string(), &["fixture-known-secret"])
            .unwrap(),
        json!(format!(
            "{}[R\n[truncated, 8200 bytes total]",
            "x".repeat(8190)
        ))
    );
    assert_eq!(
        scrub_transcript_json_utf16_8192("invalid", &[]),
        Err(ScrubError::InvalidJson)
    );
}

#[test]
fn preserves_javascript_ascii_boundaries_and_multiline_terminators() {
    assert_eq!(
        scrub_text(
            "éBearer abcdefgh\rTOKEN=small\u{2028}PASSWORD=small\u{2029}KEY=small",
            &[]
        )
        .as_str(),
        "éBearer [REDACTED]\rTOKEN=[REDACTED]\u{2028}PASSWORD=[REDACTED]\u{2029}KEY=[REDACTED]"
    );
    assert_eq!(
        scrub_text("TOKEN=\u{feff}value\nTOKEN=\u{85}value", &[]).as_str(),
        "TOKEN=\u{feff}value\nTOKEN=[REDACTED]"
    );
    assert_eq!(
        scrub_text("sk-abcdefghijklmnop---", &[]).as_str(),
        "[REDACTED]---"
    );
    assert_eq!(
        scrub_text(&format!("--{}---", "aB3".repeat(14)), &[]).as_str(),
        "--[REDACTED]---"
    );
    assert_eq!(
        scrub_text("bash:\texport auth=value", &[]).as_str(),
        "bash:\texport auth=[REDACTED]"
    );
    assert_eq!(scrub_text("KEY=", &[]).as_str(), "KEY=");
    assert_eq!(scrub_text("-----BEGIN PRIVATE KEY-----first-----END OTHER PRIVATE KEY-----second-----END PRIVATE KEY-----", &[]).as_str(), "[REDACTED]second-----END PRIVATE KEY-----");
}

#[test]
fn outbound_gate_scrubs_escaped_json_on_each_surface() {
    let escaped = format!(
        r#"{{"value":"fixture{b}u002dsecret","apiKey":"short"}}"#,
        b = '\\'
    );
    let result = scrub_outbound(
        OutboundText {
            note: Some(&escaped),
            finish_output: Some(&escaped),
            finish_error: Some(&escaped),
        },
        &["fixture-secret"],
    )
    .unwrap();
    for text in [result.note, result.finish_output, result.finish_error] {
        let json: serde_json::Value = serde_json::from_str(text.unwrap().as_str()).unwrap();
        assert_eq!(json, json!({"value":"[REDACTED]","apiKey":"[REDACTED]"}));
    }
    let unchanged = " { \"value\" : \"ordinary prose\" } ";
    let result = scrub_outbound(
        OutboundText {
            note: None,
            finish_output: Some(unchanged),
            finish_error: None,
        },
        &[],
    )
    .unwrap();
    assert_eq!(result.finish_output.unwrap().as_str(), unchanged);
    let plain = "ordinary prose fixture-secret {invalid json";
    let result = scrub_outbound(
        OutboundText {
            note: None,
            finish_output: None,
            finish_error: Some(plain),
        },
        &["fixture-secret"],
    )
    .unwrap();
    assert_eq!(
        result.finish_error.unwrap().as_str(),
        "ordinary prose [REDACTED] {invalid json"
    );
}

#[test]
fn outbound_numeric_known_secrets_cannot_skip_the_final_text_gate() {
    let mut leaks = Vec::new();
    for trigger in ["", r#", "token":"unrelated""#] {
        let input = format!(r#"{{"count":12345678{trigger}}}"#);
        let result = scrub_outbound(
            OutboundText {
                note: Some(&input),
                finish_output: Some(&input),
                finish_error: Some(&input),
            },
            &["12345678"],
        )
        .unwrap();
        for (surface, text) in [
            ("note", result.note),
            ("finish_output", result.finish_output),
            ("finish_error", result.finish_error),
        ] {
            let text = text.unwrap();
            if text.as_str().contains("12345678") || !text.as_str().contains("[REDACTED]") {
                leaks.push(format!("{surface}, trigger={trigger:?}"));
            }
        }
    }
    assert!(leaks.is_empty(), "numeric secret leaked: {leaks:?}");
}

#[test]
fn outbound_pattern_keys_are_masked_with_or_without_structural_changes() {
    let mut leaks = Vec::new();
    let cases = [
        (r#""Bearer abcdefgh""#, "Bearer [REDACTED]"),
        (r#""Bearer\tabcdefgh""#, "Bearer [REDACTED]"),
        (r#""ghp_abcdefghijklmnopqrst""#, "[REDACTED]"),
        (
            concat!(r#""ghp_abcdefghij"#, "\\", r#"u006blmnopqrst""#),
            "[REDACTED]",
        ),
        (
            r#""-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----""#,
            "[REDACTED]",
        ),
        (r#""TOKEN=short""#, "TOKEN=[REDACTED]"),
        (
            r#""aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3aB3""#,
            "[REDACTED]",
        ),
    ];
    for (key, expected) in cases {
        for trigger in ["", r#", "token":"unrelated""#] {
            let input = format!(r#"{{"nested":[{{{key}:"ordinary"}}]{trigger}}}"#);
            let result = scrub_outbound(
                OutboundText {
                    note: Some(&input),
                    finish_output: Some(&input),
                    finish_error: Some(&input),
                },
                &[],
            )
            .unwrap();
            for (surface, text) in [
                ("note", result.note),
                ("finish_output", result.finish_output),
                ("finish_error", result.finish_error),
            ] {
                let text = text.unwrap();
                let decoded: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                if decoded["nested"][0].get(expected).is_none() {
                    leaks.push(format!("{surface}, key={key}, trigger={trigger:?}"));
                }
            }
        }
    }
    assert!(leaks.is_empty(), "pattern key leaked: {leaks:?}");
}

#[test]
fn outbound_rejects_unrelated_lone_surrogates_instead_of_literal_fallback() {
    for surrogate in ["d800", "dc00"] {
        for trigger in ["", r#", "token":"unrelated""#] {
            let input = format!(
                r#"{{"value":"fixture{b}u002dsecret","unrelated":"{b}u{surrogate}"{trigger}}}"#,
                b = char::from(92),
            );
            for surface in 0..3 {
                let result = scrub_outbound(
                    OutboundText {
                        note: Some(if surface == 0 {
                            &input
                        } else {
                            "ordinary note"
                        }),
                        finish_output: Some(if surface == 1 {
                            &input
                        } else {
                            "ordinary output"
                        }),
                        finish_error: Some(if surface == 2 {
                            &input
                        } else {
                            "ordinary error"
                        }),
                    },
                    &["fixture-secret"],
                );
                let error = result.unwrap_err();
                assert_eq!(error, ScrubError::InvalidJson, "surface={surface}");
                assert_eq!(error.to_string(), "invalid scrub JSON");
                assert_eq!(format!("{error:?}"), "InvalidJson");
            }
        }
    }
}

#[test]
fn outbound_rejects_129_json_nesting_instead_of_literal_fallback() {
    let input = format!(
        r#"{}"fixture{b}u002dsecret"{}"#,
        "[".repeat(129),
        "]".repeat(129),
        b = char::from(92),
    );
    for surface in 0..3 {
        let result = scrub_outbound(
            OutboundText {
                note: Some(if surface == 0 {
                    &input
                } else {
                    "ordinary note"
                }),
                finish_output: Some(if surface == 1 {
                    &input
                } else {
                    "ordinary output"
                }),
                finish_error: Some(if surface == 2 {
                    &input
                } else {
                    "ordinary error"
                }),
            },
            &["fixture-secret"],
        );
        assert_eq!(
            result.unwrap_err(),
            ScrubError::InvalidJson,
            "surface={surface}"
        );
    }
}

#[test]
fn outbound_rejects_malformed_json_shaped_text_without_echoing_input() {
    for input in [
        r#"{"value":"fixture-secret""#,
        r#"["fixture-secret",]"#,
        r#""fixture-secret" trailing"#,
        " \t\r\n{invalid fixture-secret}",
        "\u{85}[invalid fixture-secret]",
        "\u{feff}{invalid fixture-secret}",
    ] {
        let result = scrub_outbound(
            OutboundText {
                note: Some(input),
                finish_output: Some(input),
                finish_error: Some(input),
            },
            &["fixture-secret"],
        );
        assert_eq!(result.unwrap_err(), ScrubError::InvalidJson);
    }
}

#[test]
fn outbound_decoder_boundary_keeps_depth_127_and_rejects_depth_128() {
    let input = format!(
        r#"{}"fixture{b}u002dsecret"{}"#,
        "[".repeat(127),
        "]".repeat(127),
        b = char::from(92),
    );
    let result = scrub_outbound(
        OutboundText {
            note: Some(&input),
            finish_output: Some(&input),
            finish_error: Some(&input),
        },
        &["fixture-secret"],
    )
    .unwrap();
    let expected = format!(r#"{}"[REDACTED]"{}"#, "[".repeat(127), "]".repeat(127));
    for text in [result.note, result.finish_output, result.finish_error] {
        assert_eq!(text.unwrap().as_str(), expected);
    }
    let unsupported = format!("[{input}]");
    let error = scrub_outbound(
        OutboundText {
            note: Some(&unsupported),
            finish_output: Some(&unsupported),
            finish_error: Some(&unsupported),
        },
        &["fixture-secret"],
    )
    .unwrap_err();
    assert_eq!(error, ScrubError::InvalidJson);
}

#[test]
fn outbound_ordinary_text_keeps_a_deliberate_literal_path() {
    for (input, expected) in [
        (
            "ordinary fixture-secret {invalid json",
            "ordinary [REDACTED] {invalid json",
        ),
        ("true story fixture-secret", "true story [REDACTED]"),
        (
            "  ordinary prose [unfinished",
            "  ordinary prose [unfinished",
        ),
        ("  Bearer abcdefgh", "  Bearer [REDACTED]"),
    ] {
        let result = scrub_outbound(
            OutboundText {
                note: Some(input),
                finish_output: Some(input),
                finish_error: Some(input),
            },
            &["fixture-secret"],
        )
        .unwrap();
        for text in [result.note, result.finish_output, result.finish_error] {
            assert_eq!(text.unwrap().as_str(), expected);
        }
    }
}

#[test]
fn json_value_apis_preserve_numeric_scalars_and_pattern_keys() {
    let input = r#"{"count":12345678,"Bearer abcdefgh":"ordinary","ghp_abcdefghijklmnopqrst":false,"token":"unrelated"}"#;
    let expected = json!({"count":12345678,"Bearer abcdefgh":"ordinary","ghp_abcdefghijklmnopqrst":false,"token":"[REDACTED]"});
    assert_eq!(scrub_json(input, &["12345678"]).unwrap(), expected);
    assert_eq!(
        scrub_transcript_json_utf16_8192(input, &["12345678"]).unwrap(),
        expected
    );
}

#[test]
fn masks_known_secrets_in_json_keys_as_existing_cli_does() {
    assert_eq!(
        scrub_json(r#"{"fixture-key":"value"}"#, &["fixture-key"]).unwrap(),
        json!({"[REDACTED]":"value"})
    );
}

#[test]
fn absent_outbound_values_stay_absent() {
    let result = scrub_outbound(
        OutboundText {
            note: None,
            finish_output: None,
            finish_error: None,
        },
        &[],
    )
    .unwrap();
    assert!(
        result.note.is_none() && result.finish_output.is_none() && result.finish_error.is_none()
    );
}

#[test]
fn masks_all_three_outbound_surfaces_without_clipping_finish_text() {
    let note = "Bash: export API_TOKEN=fixture-short ./run";
    let output = format!(
        "{}\nBearer fixtureBearer123\nEND",
        "ordinary output\n".repeat(1000)
    );
    let error = format!(
        "{}failed with fixture-known-secret\nEND",
        "ordinary error\n".repeat(1000)
    );
    let result = scrub_outbound(
        OutboundText {
            note: Some(note),
            finish_output: Some(&output),
            finish_error: Some(&error),
        },
        &["fixture-known-secret"],
    )
    .unwrap();
    assert_eq!(
        result.note.unwrap().as_str(),
        "Bash: export API_TOKEN=[REDACTED]"
    );
    let output = result.finish_output.unwrap();
    assert_eq!(
        output.as_str(),
        format!(
            "{}\nBearer [REDACTED]\nEND",
            "ordinary output\n".repeat(1000)
        )
    );
    assert_eq!(
        result.finish_error.unwrap().as_str(),
        format!(
            "{}failed with [REDACTED]\nEND",
            "ordinary error\n".repeat(1000)
        )
    );
}

#[test]
fn ports_five_patterns_and_keeps_ordinary_prose() {
    let cases = [
        ("\tpassword: tiny", "\tpassword: [REDACTED]"),
        ("Bash: AWS_SECRET_ACCESS_KEY=fixture/value ./deploy", "Bash: AWS_SECRET_ACCESS_KEY=[REDACTED]"),
        ("We discussed TOKEN=short in prose", "We discussed TOKEN=short in prose"),
        ("Bash: echo TOKEN=short", "Bash: echo TOKEN=short"),
        ("Bearer abcdefgh", "Bearer [REDACTED]"),
        ("Basic\tYWJjZGVmZ2g=", "Basic [REDACTED]"),
        ("Bearer abcdefg", "Bearer abcdefg"),
        ("notBearer abcdefgh", "notBearer abcdefgh"),
        ("sk-abcdefghijklmnop ghp_abcdefghijklmnopqrst github_pat_abcdefghijklmnopqrst xoxb-abcdefghij AKIAABCDEFGHIJKLMNOP", "[REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED]"),
        ("before -----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY----- after", "before [REDACTED] after"),
        ("-----BEGIN RSA PRIVATE KEY-----\nunfinished", "-----BEGIN RSA PRIVATE KEY-----\nunfinished"),
        ("path /ordinary/directory/12345 abcdefabcdefabcdefabcdefabcdefabcdefabcdef 123e4567-e89b-12d3-a456-426614174000", "path /ordinary/directory/12345 abcdefabcdefabcdefabcdefabcdefabcdefabcdef 123e4567-e89b-12d3-a456-426614174000"),
    ];
    for (input, expected) in cases {
        assert_eq!(scrub_text(input, &[]).as_str(), expected);
    }
    let opaque = format!("prefix {} suffix", "aB3".repeat(14));
    assert_eq!(
        scrub_text(&opaque, &[]).as_str(),
        "prefix [REDACTED] suffix"
    );
}

#[test]
fn long_hyphenated_nonsecrets_are_not_rescanned_at_each_word_boundary() {
    let input = "a-".repeat(100_000);
    assert_eq!(scrub_text(&input, &[]).as_str(), input);
    let input = format!("--{}---", "a-B-3-".repeat(40_000));
    assert_eq!(scrub_text(&input, &[]).as_str(), "--[REDACTED]----");
    let input = format!("{} A1", "a-".repeat(100_000));
    assert_eq!(scrub_text(&input, &[]).as_str(), input);
}

#[test]
fn known_secrets_are_literal_ordered_and_empty_entries_are_ignored() {
    assert_eq!(
        scrub_text("Türkçe 😀 fixture.a+b\nfixture.a+b", &["", "fixture.a+b"]).as_str(),
        "Türkçe 😀 [REDACTED]\n[REDACTED]"
    );
    assert_eq!(scrub_text("abc", &["ab", "abc"]).as_str(), "[REDACTED]c");
}
