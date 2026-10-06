// This path-imported test uses only the contract needed by the codec.
#[path = "../src/broker/execution/cloud_wire.rs"]
mod cloud_wire;
#[allow(dead_code)]
#[path = "../src/broker/execution/types.rs"]
mod types;

use cloud_wire::*;
use serde_json::{json, Value};
use types::{CloudError, JobAuthority, LeaseAuthority, Provider, ReportStatus, SecretMaterial};

fn lease() -> LeaseAuthority {
    LeaseAuthority::new(SecretMaterial::new("lease-secret".into()).unwrap(), 7).unwrap()
}
fn job() -> JobAuthority {
    JobAuthority::new(
        "job-1".into(),
        SecretMaterial::new("job-secret".into()).unwrap(),
    )
    .unwrap()
}
fn dispatch(authority: &LeaseAuthority) -> Dispatch<'_> {
    Dispatch {
        authority,
        lane_id: "lane",
        role: "scout",
        dispatch_key: "key",
        base: "main",
        head: "abc",
        task: "read it",
        worker_provider: Provider::Codex,
        work_item_id: None,
        reviews_job_id: None,
        resumes_job_id: None,
        answers_question_id: None,
    }
}

#[test]
fn dispatch_has_only_cloud_fields_and_keeps_all_four_optional_links() {
    let authority = lease();
    let mut request = dispatch(&authority);
    assert_eq!(
        request.encode().unwrap(),
        json!({
            "authority":{"capability":"lease-secret","fencingToken":7},
            "laneId":"lane","role":"scout","dispatchKey":"key","base":"main","head":"abc",
            "task":"read it","workerProvider":"codex"
        })
    );
    request.work_item_id = Some(" w ");
    request.reviews_job_id = Some("r");
    request.resumes_job_id = Some("old");
    request.answers_question_id = Some("q");
    assert_eq!(
        request.encode().unwrap(),
        json!({
            "authority":{"capability":"lease-secret","fencingToken":7},
            "laneId":"lane","role":"scout","dispatchKey":"key","base":"main","head":"abc",
            "task":"read it","workerProvider":"codex", "workItemId":"w", "reviewsJobId":"r",
            "resumesJobId":"old","answersQuestionId":"q"
        })
    );
}

#[test]
fn dispatch_uses_javascript_trim_and_utf16_lengths() {
    let authority = lease();
    let mut request = dispatch(&authority);
    request.lane_id = "\u{feff} lane \u{feff}";
    assert_eq!(request.encode().unwrap()["laneId"], "lane");
    request.lane_id = "\u{85}";
    assert_eq!(request.encode().unwrap()["laneId"], "\u{85}");
    let at_limit = "😀".repeat(64);
    request.lane_id = &at_limit;
    assert!(request.encode().is_ok());
    let too_long = format!("{at_limit}a");
    request.lane_id = &too_long;
    assert_eq!(request.encode(), Err(CloudError::Protocol));
    request.lane_id = " \u{feff}";
    assert_eq!(request.encode(), Err(CloudError::Protocol));
}

#[test]
fn attach_progress_finish_cancel_and_register_have_exact_optional_shapes() {
    let worker = job();
    let holder = lease();
    let mut attach = Attach {
        authority: &worker,
        provider_run_id: "job-1",
        worktree: None,
    };
    assert_eq!(
        attach.encode().unwrap(),
        json!({"authority":{"jobId":"job-1","capability":"job-secret"},"providerRunId":"job-1"})
    );
    attach.worktree = Some(Worktree {
        path: " /synthetic/tree ",
        branch: " lane/test ",
    });
    assert_eq!(
        attach.encode().unwrap(),
        json!({"authority":{"jobId":"job-1","capability":"job-secret"},"providerRunId":"job-1","worktree":{"path":"/synthetic/tree","branch":"lane/test"}})
    );
    assert_eq!(
        Progress {
            authority: &worker,
            note: None
        }
        .encode()
        .unwrap(),
        json!({"authority":{"jobId":"job-1","capability":"job-secret"}})
    );
    assert_eq!(
        Progress {
            authority: &worker,
            note: Some(" note ")
        }
        .encode()
        .unwrap(),
        json!({"authority":{"jobId":"job-1","capability":"job-secret"},"note":"note"})
    );
    assert_eq!(
        Finish {
            authority: &worker,
            status: ReportStatus::Completed,
            output: Some(""),
            error: None
        }
        .encode()
        .unwrap(),
        json!({"authority":{"jobId":"job-1","capability":"job-secret"},"status":"completed","output":""})
    );
    assert_eq!(
        Finish {
            authority: &worker,
            status: ReportStatus::TimedOut,
            output: None,
            error: Some("  stopped  ")
        }
        .encode()
        .unwrap(),
        json!({"authority":{"jobId":"job-1","capability":"job-secret"},"status":"timed_out","error":"  stopped  "})
    );
    assert_eq!(
        Cancel {
            authority: &holder,
            job_id: " job-1 "
        }
        .encode()
        .unwrap(),
        json!({"authority":{"capability":"lease-secret","fencingToken":7},"jobId":"job-1"})
    );
    assert_eq!(
        Register {
            mission_id: "mission.1",
            repo: " owner/repo "
        }
        .encode()
        .unwrap(),
        json!({"missionId":"mission.1","repo":"owner/repo"})
    );
}

#[test]
fn outbound_limits_reject_instead_of_truncating_or_filling_empty_fields() {
    let worker = job();
    let note = "😀".repeat(250);
    assert!(Progress {
        authority: &worker,
        note: Some(&note)
    }
    .encode()
    .is_ok());
    let long_note = format!("{note}a");
    assert_eq!(
        Progress {
            authority: &worker,
            note: Some(&long_note)
        }
        .encode(),
        Err(CloudError::Protocol)
    );
    assert_eq!(
        Progress {
            authority: &worker,
            note: Some(" ")
        }
        .encode(),
        Err(CloudError::Protocol)
    );
    let output = "😀".repeat(100_000);
    assert!(Finish {
        authority: &worker,
        status: ReportStatus::Failed,
        output: Some(&output),
        error: None
    }
    .encode()
    .is_ok());
    let error = "😀".repeat(10_001);
    assert_eq!(
        Finish {
            authority: &worker,
            status: ReportStatus::Failed,
            output: None,
            error: Some(&error)
        }
        .encode(),
        Err(CloudError::Protocol)
    );
    for id in ["Mission", " mission", "a/b", "", "_mission", "a:"] {
        assert_eq!(
            Register {
                mission_id: id,
                repo: "repo"
            }
            .encode(),
            Err(CloudError::Protocol)
        );
    }
}

fn brief() -> Value {
    json!({"ok":true,"jobId":"job-1","task":"the cloud's authoritative task",
        "role":"scout","laneId":"lane","base":"main","head":"abc",
        "workItemId":null,"reviewsJobId":null,"answersQuestionId":null,
        "deadline":300001,"resumeFrom":null})
}

#[test]
fn dispatch_creation_yields_job_authority_but_existing_job_never_yields_a_secret() {
    let created =
        json!({"jobId":"job-1","created":true,"state":"reserved","capability":" job-secret "});
    let answer = decode_dispatch(&created).unwrap();
    let Dispatched::Created(authority) = answer.value else {
        panic!("must be created")
    };
    assert_eq!(authority.job_id(), "job-1");
    assert_eq!(
        serde_json::to_value(authority.wire()).unwrap()["capability"],
        " job-secret "
    );
    for capability in [None, Some(Value::Null)] {
        let mut existing = json!({"jobId":"job-1","created":false,"state":"running"});
        if let Some(capability) = capability {
            existing["capability"] = capability;
        }
        let answer = decode_dispatch(&existing).unwrap();
        assert!(
            matches!(answer.value, Dispatched::Existing {job_id, state:JobState::Running} if job_id == "job-1")
        );
    }
    for (key, bad) in [
        ("ok", json!(false)),
        ("created", json!("true")),
        ("jobId", json!(" job-1 ")),
        ("jobId", json!("")),
        ("state", json!("running")),
        ("capability", json!(null)),
        ("capability", json!("")),
    ] {
        let mut corrupt = created.clone();
        corrupt[key] = bad;
        assert!(
            matches!(decode_dispatch(&corrupt), Err(CloudError::Protocol)),
            "{key}"
        );
    }
    let secret_on_replay =
        json!({"jobId":"job-1","created":false,"state":"running","capability":"secret"});
    assert!(matches!(
        decode_dispatch(&secret_on_replay),
        Err(CloudError::Protocol)
    ));
    for key in ["jobId", "created", "state", "capability"] {
        let mut corrupt = created.clone();
        corrupt.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(decode_dispatch(&corrupt), Err(CloudError::Protocol)),
            "{key}"
        );
    }
}

#[test]
fn attach_validates_the_original_job_brief_and_resume_before_spawn() {
    let authority = job();
    let original = brief();
    let answer = decode_attach(&original, &authority, None).unwrap();
    assert_eq!(answer.value.task, "the cloud's authoritative task");
    assert_eq!(answer.value.deadline, 300001);
    assert_eq!(answer.value.job_id, "job-1");
    assert_eq!(answer.value.role, "scout");
    assert_eq!(answer.value.lane_id, "lane");
    assert_eq!(answer.value.base, "main");
    assert_eq!(answer.value.head, "abc");
    assert!(answer.value.work_item_id.is_none());
    assert!(answer.value.reviews_job_id.is_none());
    assert!(answer.value.answers_question_id.is_none());
    assert!(answer.value.resume_from.is_none());
    let mut resumed = original.clone();
    resumed["resumeFrom"] = json!({"jobId":"prior","providerRunId":"session","worktree":{"path":"/synthetic/tree","branch":"lane/prior"}});
    let answer = decode_attach(&resumed, &authority, Some("prior")).unwrap();
    let resume = answer.value.resume_from.unwrap();
    assert_eq!(resume.job_id, "prior");
    assert_eq!(resume.provider_run_id, "session");
    let worktree = resume.worktree.unwrap();
    assert_eq!(worktree.path, "/synthetic/tree");
    assert_eq!(worktree.branch, "lane/prior");
    assert!(matches!(
        decode_attach(&resumed, &authority, None),
        Err(CloudError::Protocol)
    ));
    assert!(matches!(
        decode_attach(&resumed, &authority, Some("other")),
        Err(CloudError::Protocol)
    ));
    assert!(matches!(
        decode_attach(&original, &authority, Some("prior")),
        Err(CloudError::Protocol)
    ));
    for (key, bad) in [
        ("ok", json!(false)),
        ("jobId", json!("other")),
        ("jobId", json!(" job-1 ")),
        ("task", json!(null)),
        ("task", json!("")),
        ("deadline", json!(1.5)),
        ("deadline", json!(0)),
        ("deadline", json!("300001")),
        ("workItemId", json!(7)),
        ("resumeFrom", json!({"jobId":"prior","providerRunId":""})),
    ] {
        let mut corrupt = original.clone();
        corrupt[key] = bad;
        assert!(
            matches!(
                decode_attach(&corrupt, &authority, None),
                Err(CloudError::Protocol)
            ),
            "{key}"
        );
    }
    for key in [
        "ok",
        "jobId",
        "task",
        "role",
        "laneId",
        "base",
        "head",
        "workItemId",
        "reviewsJobId",
        "answersQuestionId",
        "deadline",
        "resumeFrom",
    ] {
        let mut corrupt = original.clone();
        corrupt.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(
                decode_attach(&corrupt, &authority, None),
                Err(CloudError::Protocol)
            ),
            "missing {key}"
        );
    }
}

#[test]
fn progress_finish_cancel_and_registration_require_application_acknowledgement() {
    let authority = job();
    let progress = json!({"jobId":"job-1","deadline":300001.0});
    assert_eq!(
        decode_progress(&progress, &authority)
            .unwrap()
            .value
            .deadline,
        300001
    );
    for state in [
        "review_pending",
        "failed",
        "completed",
        "timed_out",
        "cancelled",
    ] {
        let finish = json!({"jobId":"job-1","state":state,"subject":null});
        assert!(decode_finish(&finish, &authority).is_ok());
    }
    let finish = json!({"jobId":"job-1","state":"completed","subject":{"jobId":"subject","state":"rejected"}});
    let finished = decode_finish(&finish, &authority).unwrap().value;
    assert_eq!(finished.state, JobState::Completed);
    let subject = finished.subject.unwrap();
    assert_eq!(subject.job_id, "subject");
    assert_eq!(subject.state, JobState::Rejected);
    let cancel = json!({"jobId":"job-1","state":"cancelled"});
    assert!(decode_cancel(&cancel, "job-1").is_ok());
    assert!(matches!(
        decode_cancel(&cancel, "other"),
        Err(CloudError::Protocol)
    ));
    let registered = json!({"created":false,"mission":{"missionId":"mission","repo":"owner/repo","registeredAt":1.0,"registeredBy":"svc:synthetic"}});
    let registration = decode_register(
        &registered,
        &Register {
            mission_id: "mission",
            repo: "owner/repo",
        },
    )
    .unwrap()
    .value;
    assert!(!registration.created);
    assert_eq!(registration.registered_at, 1);
    assert_eq!(registration.registered_by, "svc:synthetic");
    assert!(matches!(
        decode_register(
            &registered,
            &Register {
                mission_id: "mission",
                repo: "other"
            }
        ),
        Err(CloudError::Protocol)
    ));
    let mut broken = progress.clone();
    broken["ok"] = json!(false);
    assert!(matches!(
        decode_progress(&broken, &authority),
        Err(CloudError::Protocol)
    ));
    let mut broken = finish.clone();
    broken["state"] = json!("running");
    assert!(matches!(
        decode_finish(&broken, &authority),
        Err(CloudError::Protocol)
    ));
}

// Exact public HTTP bodies from platform services/broker/test/frozen/
// surface-transcript.json at 4f701f6b (not the private DO success envelopes).
// Full fixture SHA-256: 26eb925fe33e2dc495c1a2ebfca5c6b6bb186c96cc937187d122dfe6b2f833fa.
// The capability below is the frozen test's synthetic creation-only authority.
fn public_reply(operation: &str) -> Value {
    let replies: Value = serde_json::from_str(r#"{
        "jobs-dispatch":{"jobId":"00000000-0000-4000-8000-000000000005","created":true,"state":"reserved","capability":"hwqNEJMWmRyfIqUoqy6xNLc6vUDDRslMz1LVWNte4WQ"},
        "jobs-dispatch-replay":{"jobId":"00000000-0000-4000-8000-000000000005","created":false,"state":"reserved","capability":null},
        "jobs-attach":{"ok":true,"jobId":"00000000-0000-4000-8000-000000000005","task":"do it","role":"builder","laneId":"lane-a","base":"main","head":"abc123","workItemId":"00000000-0000-4000-8000-000000000002","reviewsJobId":null,"answersQuestionId":null,"deadline":1900000960000,"resumeFrom":null},
        "jobs-progress":{"jobId":"00000000-0000-4000-8000-000000000005","deadline":1900000960000},
        "jobs-finish":{"jobId":"00000000-0000-4000-8000-000000000005","state":"review_pending","subject":null},
        "jobs-finish-review":{"jobId":"00000000-0000-4000-8000-000000000006","state":"completed","subject":{"jobId":"00000000-0000-4000-8000-000000000005","state":"completed"}},
        "jobs-cancel":{"jobId":"00000000-0000-4000-8000-000000000009","state":"cancelled"},
        "missions-register":{"created":true,"mission":{"missionId":"tx-lease","repo":"wapps/broker","registeredAt":1900000000000,"registeredBy":"human:adnan@wapps.co"}}
    }"#).unwrap();
    replies.get(operation).unwrap().clone()
}

fn public_worker() -> JobAuthority {
    JobAuthority::new(
        "00000000-0000-4000-8000-000000000005".into(),
        SecretMaterial::new("synthetic-job".into()).unwrap(),
    )
    .unwrap()
}

fn rpc_application(value: Value) -> Value {
    // broker_mcp::result and mcp_lane::tool_result wrap the same public body,
    // without inventing ok. This exercises the envelope, not a live MCP call.
    let text = value.to_string();
    // mcp_lane::tool_result omits isError on successful replies.
    let rpc = json!({"jsonrpc":"2.0","id":7,"result":{
        "content":[{"type":"text","text":text}],"structuredContent":value
    }});
    decode_rpc(&rpc, &json!(7)).unwrap().clone()
}

fn assert_public_dispatch(source: &Value, created: bool) {
    let answer = decode_dispatch(source).unwrap();
    match answer.value {
        Dispatched::Created(authority) => {
            assert!(created);
            assert_eq!(authority.job_id(), "00000000-0000-4000-8000-000000000005");
            assert_eq!(
                serde_json::to_value(authority.wire()).unwrap()["capability"],
                "hwqNEJMWmRyfIqUoqy6xNLc6vUDDRslMz1LVWNte4WQ"
            );
        }
        Dispatched::Existing { job_id, state } => {
            assert!(!created);
            assert_eq!(job_id, "00000000-0000-4000-8000-000000000005");
            assert_eq!(state, JobState::Reserved);
        }
    }
}

#[test]
fn public_http_dispatch_accepts_creation_and_null_capability_replay() {
    for (operation, created) in [("jobs-dispatch", true), ("jobs-dispatch-replay", false)] {
        assert_public_dispatch(&public_reply(operation), created);
    }
}

#[test]
fn public_mcp_dispatch_accepts_creation_and_null_capability_replay() {
    for (operation, created) in [("jobs-dispatch", true), ("jobs-dispatch-replay", false)] {
        assert_public_dispatch(&rpc_application(public_reply(operation)), created);
    }
}

#[test]
fn public_http_progress_preserves_the_deadline() {
    assert_eq!(
        decode_progress(&public_reply("jobs-progress"), &public_worker())
            .unwrap()
            .value
            .deadline,
        1_900_000_960_000
    );
}

#[test]
fn public_mcp_envelope_progress_preserves_the_deadline() {
    // The public catalog has no progress tool. Only its generic result envelope
    // is exercised here; this does not add or claim a supported tool route.
    assert_eq!(
        decode_progress(
            &rpc_application(public_reply("jobs-progress")),
            &public_worker()
        )
        .unwrap()
        .value
        .deadline,
        1_900_000_960_000
    );
}

fn assert_public_finish(source: &Value) {
    let answer = decode_finish(source, &public_worker()).unwrap();
    assert_eq!(answer.value.state, JobState::ReviewPending);
    assert!(answer.value.subject.is_none());
}

#[test]
fn public_http_finish_preserves_cloud_settlement() {
    assert_public_finish(&public_reply("jobs-finish"));
}

#[test]
fn public_mcp_finish_preserves_cloud_settlement() {
    assert_public_finish(&rpc_application(public_reply("jobs-finish")));
}

#[test]
fn public_http_cancel_accepts_the_original_id() {
    assert_eq!(
        decode_cancel(
            &public_reply("jobs-cancel"),
            "00000000-0000-4000-8000-000000000009"
        )
        .unwrap()
        .value,
        JobState::Cancelled
    );
}

#[test]
fn public_mcp_cancel_accepts_the_original_id() {
    assert_eq!(
        decode_cancel(
            &rpc_application(public_reply("jobs-cancel")),
            "00000000-0000-4000-8000-000000000009"
        )
        .unwrap()
        .value,
        JobState::Cancelled
    );
}

#[test]
fn public_attach_requires_ok_but_public_registration_does_not_supply_it() {
    let source = public_reply("jobs-attach");
    let answer = decode_attach(&source, &public_worker(), None).unwrap();
    assert_eq!(answer.value.task, "do it");
    let mcp = rpc_application(source.clone());
    assert_eq!(
        decode_attach(&mcp, &public_worker(), None)
            .unwrap()
            .value
            .task,
        "do it"
    );
    for bad in [
        None,
        Some(json!(false)),
        Some(Value::Null),
        Some(json!("true")),
    ] {
        let mut broken = source.clone();
        if let Some(bad) = bad {
            broken["ok"] = bad;
        } else {
            broken.as_object_mut().unwrap().remove("ok");
        }
        assert!(matches!(
            decode_attach(&broken, &public_worker(), None),
            Err(CloudError::Protocol)
        ));
    }
    // register_mission projects created/mission and omits private catalog ok.
    let source = public_reply("missions-register");
    let request = Register {
        mission_id: "tx-lease",
        repo: "wapps/broker",
    };
    let registered = decode_register(&source, &request).unwrap().value;
    assert!(registered.created);
    assert_eq!(registered.registered_at, 1_900_000_000_000);
    assert_eq!(registered.registered_by, "human:adnan@wapps.co");
    for bad in [json!(false), Value::Null, json!("true")] {
        let mut broken = source.clone();
        broken["ok"] = bad;
        assert!(matches!(
            decode_register(&broken, &request),
            Err(CloudError::Protocol)
        ));
    }
}

fn public_mutation(operation: &str, source: &Value) -> Result<(), CloudError> {
    match operation {
        "jobs-dispatch" => decode_dispatch(source).map(|_| ()),
        "jobs-progress" => decode_progress(source, &public_worker()).map(|_| ()),
        "jobs-finish" => decode_finish(source, &public_worker()).map(|_| ()),
        "jobs-cancel" => decode_cancel(source, "00000000-0000-4000-8000-000000000009").map(|_| ()),
        _ => panic!("unknown test operation"),
    }
}

#[test]
fn public_acknowledgements_require_operation_fields_not_arbitrary_objects() {
    for (operation, required) in [
        (
            "jobs-dispatch",
            &["jobId", "created", "state", "capability"][..],
        ),
        ("jobs-progress", &["jobId", "deadline"][..]),
        ("jobs-finish", &["jobId", "state", "subject"][..]),
        ("jobs-cancel", &["jobId", "state"][..]),
    ] {
        let source = public_reply(operation);
        for key in required {
            let mut broken = source.clone();
            broken.as_object_mut().unwrap().remove(*key);
            assert_eq!(
                public_mutation(operation, &broken),
                Err(CloudError::Protocol),
                "{operation} missing {key}"
            );
        }
        for bad in [
            json!({}),
            json!({"ok":true}),
            Value::Null,
            json!([]),
            json!(true),
        ] {
            assert_eq!(
                public_mutation(operation, &bad),
                Err(CloudError::Protocol),
                "{operation}"
            );
        }
        for bad in [json!(false), Value::Null, json!("true"), json!(1)] {
            let mut broken = source.clone();
            broken["ok"] = bad;
            assert_eq!(
                public_mutation(operation, &broken),
                Err(CloudError::Protocol),
                "{operation} contradictory ok"
            );
        }
        let mut mixed = source.clone();
        for (key, value) in envelope("FORBIDDEN", false).as_object().unwrap() {
            mixed[key] = value.clone();
        }
        assert_eq!(
            public_mutation(operation, &mixed),
            Err(CloudError::Protocol)
        );
        assert_eq!(
            public_mutation(operation, &envelope("FORBIDDEN", false)),
            Err(CloudError::Refused)
        );
        let mixed_rpc = json!({"jsonrpc":"2.0","id":7,"result":tool(mixed,true)});
        assert_eq!(decode_rpc(&mixed_rpc, &json!(7)), Err(CloudError::Protocol));
    }
}

#[test]
fn public_reply_extensions_do_not_override_mutation_success_or_failure() {
    for operation in [
        "jobs-dispatch",
        "jobs-progress",
        "jobs-finish",
        "jobs-cancel",
    ] {
        let mut source = public_reply(operation);
        source["extension"] = json!({"future":true});
        source["attentionError"] = envelope("INTERNAL", false);
        let application = rpc_application(source.clone());
        assert_eq!(application, source);
        assert_eq!(public_mutation(operation, &application), Ok(()));
        if operation == "jobs-dispatch" {
            let answer = decode_dispatch(&application).unwrap();
            assert_eq!(answer.attention_error, Some(&source["attentionError"]));
        }
        source.as_object_mut().unwrap().remove("attentionError");
        source["attention"] = json!({"future":{"preserved":true}});
        assert_eq!(public_mutation(operation, &source), Ok(()));
        source["attentionError"] = envelope("INTERNAL", false);
        assert_eq!(
            public_mutation(operation, &source),
            Err(CloudError::Protocol)
        );
    }
}

#[test]
fn finish_preserves_a_subject_cancelled_while_its_reviewer_was_running() {
    // core job_transition_allowed permits review_pending -> cancelled, but not
    // cancelled -> completed. mission_lane::settle_subject returns that observed
    // state; a successful reviewer's finish does not mean its verdict changed it.
    let mut source = public_reply("jobs-finish-review");
    source["subject"]["state"] = json!("cancelled");
    let reviewer = JobAuthority::new(
        "00000000-0000-4000-8000-000000000006".into(),
        SecretMaterial::new("synthetic-reviewer".into()).unwrap(),
    )
    .unwrap();
    for application in [source.clone(), rpc_application(source)] {
        let answer = decode_finish(&application, &reviewer).unwrap();
        assert_eq!(answer.value.state, JobState::Completed);
        let subject = answer.value.subject.unwrap();
        assert_eq!(subject.job_id, "00000000-0000-4000-8000-000000000005");
        assert_eq!(subject.state, JobState::Cancelled);
    }
}

#[test]
fn finish_subject_validates_observed_state_vocabulary_without_transition_policy() {
    let authority = job();
    for (state, expected) in [
        ("reserved", JobState::Reserved),
        ("running", JobState::Running),
        ("review_pending", JobState::ReviewPending),
        ("completed", JobState::Completed),
        ("rejected", JobState::Rejected),
        ("failed", JobState::Failed),
        ("timed_out", JobState::TimedOut),
        ("cancelled", JobState::Cancelled),
        ("orphaned", JobState::Orphaned),
    ] {
        let source = json!({"jobId":"job-1","state":"completed","subject":{"jobId":"subject","state":state}});
        assert_eq!(
            decode_finish(&source, &authority)
                .unwrap()
                .value
                .subject
                .unwrap()
                .state,
            expected
        );
    }
    for bad in [json!("unknown"), Value::Null, json!(true), json!(1)] {
        let source =
            json!({"jobId":"job-1","state":"completed","subject":{"jobId":"subject","state":bad}});
        assert!(matches!(
            decode_finish(&source, &authority),
            Err(CloudError::Protocol)
        ));
    }
}

fn envelope(code: &str, retryable: bool) -> Value {
    json!({"error":code,"message":"synthetic refusal","recovery":"correct the request","retryable":retryable,"details":{"refusal":"synthetic"}})
}
fn tool(value: Value, is_error: bool) -> Value {
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":is_error})
}
#[test]
fn rpc_errors_refusals_and_post_mutation_attention_errors_stay_distinct() {
    let refusal = json!({"jsonrpc":"2.0","id":7,"result":tool(envelope("FORBIDDEN",false),true)});
    assert_eq!(decode_rpc(&refusal, &json!(7)), Err(CloudError::Refused));
    let rpc = json!({"jsonrpc":"2.0","id":7,"error":{"code":-32000.0,"message":"synthetic"}});
    assert_eq!(decode_rpc(&rpc, &json!(7)), Err(CloudError::Rpc));
    let huge_code = json!({"jsonrpc":"2.0","id":7,"error":{"code":1e30,"message":"synthetic"}});
    assert_eq!(decode_rpc(&huge_code, &json!(7)), Err(CloudError::Rpc));
    let mut attached = brief();
    attached["attentionError"] = envelope("FORBIDDEN", false);
    let rpc = json!({"jsonrpc":"2.0","id":7,"result":tool(attached.clone(),false)});
    let application = decode_rpc(&rpc, &json!(7)).unwrap();
    let authority = job();
    let answer = decode_attach(application, &authority, None).unwrap();
    assert_eq!(answer.attention_error, Some(&attached["attentionError"]));
    assert!(answer.attention.is_none());
    assert_eq!(answer.value.task, "the cloud's authoritative task");
    for bad in [
        json!({"jsonrpc":"2.0","id":7,"result":tool(envelope("INTERNAL",false),true)}),
        json!({"jsonrpc":"2.0","id":7,"result":tool(json!({}),true)}),
        json!({"jsonrpc":"2.0","id":7,"error":{"code":1.5,"message":"synthetic"}}),
        json!({"jsonrpc":"2.0","id":7,"error":{"code":1,"message":null}}),
        json!({"jsonrpc":"2.0","id":8,"result":tool(brief(),false)}),
        json!({"jsonrpc":"1.0","id":7,"result":tool(brief(),false)}),
        json!({"jsonrpc":"2.0","id":7,"result":{"structuredContent":brief()}}),
        json!({"jsonrpc":"2.0","id":7,"result":tool(brief(),false),"error":{"code":1,"message":"synthetic"}}),
    ] {
        assert_eq!(decode_rpc(&bad, &json!(7)), Err(CloudError::Protocol));
    }
    assert_eq!(
        CloudError::Transport.outcome(),
        types::MutationOutcome::Unknown
    );
    assert_eq!(CloudError::Rpc.outcome(), types::MutationOutcome::Unknown);
    assert_eq!(
        CloudError::Protocol.outcome(),
        types::MutationOutcome::Unknown
    );
    assert_eq!(
        CloudError::Refused.outcome(),
        types::MutationOutcome::Refused
    );
}

#[test]
fn contradictory_success_and_refusal_never_establish_safe_replay() {
    let mut mixed = envelope("FORBIDDEN", false);
    mixed["ok"] = json!(true);
    mixed["jobId"] = json!("job-1");
    assert!(matches!(decode_dispatch(&mixed), Err(CloudError::Protocol)));
    let successful_error =
        json!({"jsonrpc":"2.0","id":7,"result":tool(envelope("FORBIDDEN",false),false)});
    assert_eq!(
        decode_rpc(&successful_error, &json!(7)),
        Err(CloudError::Protocol)
    );
}

#[test]
fn only_complete_nonmutating_envelopes_count_as_refusals() {
    for (code, retryable) in [
        ("INVALID_ARGUMENT", false),
        ("UNAUTHENTICATED", false),
        ("FORBIDDEN", false),
        ("NOT_FOUND", false),
        ("CONFLICT", true),
        ("OPERATION_KEY_CONFLICT", false),
    ] {
        let value = envelope(code, retryable);
        assert!(matches!(decode_dispatch(&value), Err(CloudError::Refused)));
        let rpc = json!({"jsonrpc":"2.0","id":"request","result":tool(value,true)});
        assert_eq!(
            decode_rpc(&rpc, &json!("request")),
            Err(CloudError::Refused)
        );
    }
    for (code, retryable) in [
        ("INTERNAL", false),
        ("RATE_LIMITED", true),
        ("NOT_AVAILABLE", true),
        ("SERVICE_MISCONFIGURED", false),
        ("UNKNOWN", false),
    ] {
        let value = envelope(code, retryable);
        assert!(matches!(decode_dispatch(&value), Err(CloudError::Protocol)));
    }
    for key in ["error", "message", "recovery", "retryable"] {
        let mut invalid = envelope("FORBIDDEN", false);
        invalid.as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_dispatch(&invalid),
            Err(CloudError::Protocol)
        ));
        let rpc = json!({"jsonrpc":"2.0","id":7,"result":tool(invalid,true)});
        assert_eq!(decode_rpc(&rpc, &json!(7)), Err(CloudError::Protocol));
    }
    for (key, bad) in [
        ("error", json!(true)),
        ("message", json!(null)),
        ("recovery", json!(7)),
        ("retryable", json!(true)),
    ] {
        let mut invalid = envelope("FORBIDDEN", false);
        invalid[key] = bad;
        assert!(matches!(
            decode_dispatch(&invalid),
            Err(CloudError::Protocol)
        ));
    }
}

#[test]
fn original_ids_nullable_links_and_attention_are_preserved_without_defaults() {
    let authority = job();
    let mut value = brief();
    value["workItemId"] = json!("work");
    value["reviewsJobId"] = json!("review");
    value["answersQuestionId"] = json!("question");
    value["attention"] = json!({"extension":{"unmodified":true}});
    let result = decode_attach(&value, &authority, None).unwrap();
    assert_eq!(result.value.work_item_id.as_deref(), Some("work"));
    assert_eq!(result.value.reviews_job_id.as_deref(), Some("review"));
    assert_eq!(
        result.value.answers_question_id.as_deref(),
        Some("question")
    );
    assert_eq!(result.attention, Some(&value["attention"]));
    assert!(result.attention_error.is_none());
    for key in ["workItemId", "reviewsJobId", "answersQuestionId"] {
        let mut invalid = value.clone();
        invalid[key] = json!(" id ");
        assert!(matches!(
            decode_attach(&invalid, &authority, None),
            Err(CloudError::Protocol)
        ));
    }
    value["attentionError"] = envelope("INTERNAL", false);
    assert!(matches!(
        decode_attach(&value, &authority, None),
        Err(CloudError::Protocol)
    ));
    value.as_object_mut().unwrap().remove("attention");
    assert!(decode_attach(&value, &authority, None).is_ok());
    value["attentionError"] = Value::Null;
    assert!(matches!(
        decode_attach(&value, &authority, None),
        Err(CloudError::Protocol)
    ));
    let mut value = brief();
    value["resumeFrom"] = json!({"jobId":"prior","providerRunId":"run","worktree":null});
    assert!(decode_attach(&value, &authority, Some("prior"))
        .unwrap()
        .value
        .resume_from
        .unwrap()
        .worktree
        .is_none());
    for key in ["jobId", "providerRunId", "worktree"] {
        let mut invalid = value.clone();
        invalid["resumeFrom"].as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_attach(&invalid, &authority, Some("prior")),
            Err(CloudError::Protocol)
        ));
    }
}

#[test]
fn deadlines_are_safe_integral_numbers_not_coerced_or_filled() {
    let authority = job();
    for valid in [json!(1), json!(1.0), json!(9_007_199_254_740_991_u64)] {
        let value = json!({"jobId":"job-1","deadline":valid});
        assert!(decode_progress(&value, &authority).is_ok());
    }
    for invalid in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!("1"),
        json!(true),
        Value::Null,
        json!(9_007_199_254_740_992_u64),
    ] {
        let value = json!({"jobId":"job-1","deadline":invalid});
        assert!(matches!(
            decode_progress(&value, &authority),
            Err(CloudError::Protocol)
        ));
    }
    let source = json!({"jobId":"job-1","deadline":1});
    for key in ["jobId", "deadline"] {
        let mut broken = source.clone();
        broken.as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_progress(&broken, &authority),
            Err(CloudError::Protocol)
        ));
    }
}

#[test]
fn settlements_and_registration_do_not_turn_missing_or_wrong_fields_into_success() {
    let authority = job();
    let source = json!({"jobId":"job-1","state":"review_pending","subject":null});
    for key in ["jobId", "state", "subject"] {
        let mut broken = source.clone();
        broken.as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_finish(&broken, &authority),
            Err(CloudError::Protocol)
        ));
    }
    for bad in [
        json!({"jobId":"subject","state":"unknown"}),
        json!({"state":"rejected"}),
        json!({"jobId":"subject"}),
        json!(true),
    ] {
        let mut broken = source.clone();
        broken["subject"] = bad;
        assert!(matches!(
            decode_finish(&broken, &authority),
            Err(CloudError::Protocol)
        ));
    }
    let source = json!({"jobId":"job-1","state":"cancelled"});
    for key in ["jobId", "state"] {
        let mut broken = source.clone();
        broken.as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_cancel(&broken, "job-1"),
            Err(CloudError::Protocol)
        ));
    }
    let request = Register {
        mission_id: "mission",
        repo: "repo",
    };
    let source = json!({"created":true,"mission":{"missionId":"mission","repo":"repo","registeredAt":0,"registeredBy":"svc:synthetic"}});
    assert!(decode_register(&source, &request).unwrap().value.created);
    for key in ["missionId", "repo", "registeredAt", "registeredBy"] {
        let mut broken = source.clone();
        broken["mission"].as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_register(&broken, &request),
            Err(CloudError::Protocol)
        ));
    }
    for key in ["created", "mission"] {
        let mut broken = source.clone();
        broken.as_object_mut().unwrap().remove(key);
        assert!(matches!(
            decode_register(&broken, &request),
            Err(CloudError::Protocol)
        ));
    }
    for (key, bad) in [
        ("missionId", json!("other")),
        ("repo", json!("other")),
        ("registeredAt", json!(1.5)),
        ("registeredBy", json!("")),
    ] {
        let mut broken = source.clone();
        broken["mission"][key] = bad;
        assert!(matches!(
            decode_register(&broken, &request),
            Err(CloudError::Protocol)
        ));
    }
}

#[test]
fn rpc_content_and_metadata_are_validated_without_text_fallback() {
    let application = brief();
    let source = json!({"jsonrpc":"2.0","id":7,"result":tool(application.clone(),false)});
    for content in [
        json!(null),
        json!({}),
        json!([{"type":"text"}]),
        json!([{"type":"unknown"}]),
        json!([{"type":"text","text":"text","annotations":{"priority":2}}]),
    ] {
        let mut invalid = source.clone();
        invalid["result"]["content"] = content;
        assert_eq!(decode_rpc(&invalid, &json!(7)), Err(CloudError::Protocol));
    }
    for (key, bad) in [
        ("structuredContent", Value::Null),
        ("structuredContent", json!([])),
        ("isError", Value::Null),
        ("isError", json!("false")),
        ("_meta", json!(false)),
    ] {
        let mut invalid = source.clone();
        invalid["result"][key] = bad;
        assert_eq!(decode_rpc(&invalid, &json!(7)), Err(CloudError::Protocol));
    }
    let mut absent = source.clone();
    absent["result"]
        .as_object_mut()
        .unwrap()
        .remove("structuredContent");
    assert_eq!(decode_rpc(&absent, &json!(7)), Err(CloudError::Protocol));
    let mut absent = source.clone();
    absent["result"].as_object_mut().unwrap().remove("isError");
    assert_eq!(decode_rpc(&absent, &json!(7)).unwrap(), &application);
    for content in [
        json!([]),
        json!([{"type":"image","data":"synthetic","mimeType":"image/png"}]),
        json!([{"type":"audio","data":"synthetic","mimeType":"audio/wav"}]),
        json!([{"type":"resource","resource":{"uri":"synthetic:text","text":"synthetic"}}]),
        json!([{"type":"resource_link","name":"synthetic","uri":"synthetic:link"}]),
    ] {
        let mut accepted = source.clone();
        accepted["result"]["content"] = content;
        assert_eq!(decode_rpc(&accepted, &json!(7)).unwrap(), &application);
    }
}
