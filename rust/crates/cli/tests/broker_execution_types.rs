#[path = "../src/broker/execution/types.rs"]
mod types;

use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
use types::{
    CloudError, ContractError, JobAuthority, LeaseAuthority, MutationOutcome, Provider,
    ReportStatus, SecretMaterial,
};

// Reuse the oracle's exclusive 0700 root; no installed CLI, provider, or cloud.
struct DiagnosticRoot(PathBuf);

impl Drop for DiagnosticRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compile_contract(body: &str) -> Output {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = DiagnosticRoot(broker_oracle::hermetic::temp_root(&format!(
        "execution-types-{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let mut serde_libraries: Vec<_> = fs::read_dir(&deps)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .is_some_and(|name| name.starts_with("libserde-") && name.ends_with(".rlib"))
        })
        .collect();
    serde_libraries.sort();
    let serde = serde_libraries
        .first()
        .expect("serde is already built by cargo");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/broker/execution/types.rs");
    let fixture = root.0.join("fixture.rs");
    fs::write(
        &fixture,
        format!("#[path = {source:?}] mod types;\n{body}\n"),
    )
    .unwrap();
    let output = Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-type=lib",
            "--emit=metadata",
            "--crate-name=contract_fixture",
        ])
        .arg(&fixture)
        .arg("--extern")
        .arg(format!("serde={}", serde.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("--out-dir")
        .arg(&root.0)
        .current_dir(&root.0)
        .output()
        .expect("local Rust compiler");
    println!("contract_diagnostic_exit={:?}", output.status.code());
    output
}

fn secret(value: &str) -> SecretMaterial {
    SecretMaterial::new(value.to_owned()).expect("synthetic nonempty capability")
}

#[test]
fn compiler_allows_only_explicit_wire_serialization_and_distinct_authority_positions() {
    // Compile the positive fixture first, so a broken compiler setup cannot make
    // the negative cases pass merely because every invocation fails.
    let positive = compile_contract(
        r#"
        fn serialize<T: serde::Serialize>(_: T) {}
        fn lease(_: types::LeaseAuthority) {}
        fn job(_: types::JobAuthority) {}
        fn allowed(l: types::LeaseAuthority, j: types::JobAuthority) {
            serialize(l.wire()); serialize(j.wire());
            lease(l); job(j);
        }
    "#,
    );
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );

    for (body, diagnostic, type_name) in [
        ("fn lease(_: types::LeaseAuthority) {} fn bad(j: types::JobAuthority) { lease(j); }", "E0308", "JobAuthority"),
        ("fn job(_: types::JobAuthority) {} fn bad(l: types::LeaseAuthority) { job(l); }", "E0308", "LeaseAuthority"),
        ("fn serialize<T: serde::Serialize>(_: T) {} fn bad(l: types::LeaseAuthority) { serialize(l); }", "E0277", "LeaseAuthority"),
        ("fn serialize<T: serde::Serialize>(_: T) {} fn bad(j: types::JobAuthority) { serialize(j); }", "E0277", "JobAuthority"),
        ("fn serialize<T: serde::Serialize>(_: T) {} fn bad(s: types::SecretMaterial) { serialize(s); }", "E0277", "SecretMaterial"),
        ("fn bad(l: types::LeaseAuthority) { let _ = format!(\"{l}\"); }", "E0277", "LeaseAuthority"),
        ("fn bad(j: types::JobAuthority) { let _ = format!(\"{j}\"); }", "E0277", "JobAuthority"),
        ("fn bad(s: types::SecretMaterial) { let _ = format!(\"{s}\"); }", "E0277", "SecretMaterial"),
        ("fn bad(l: types::LeaseAuthority) { let _ = l.capability; }", "E0616", "capability"),
        ("fn bad(j: types::JobAuthority) { let _ = j.capability; }", "E0616", "capability"),
        ("fn bad(s: types::SecretMaterial) { let _ = s.0; }", "E0616", "private"),
        ("fn bad(w: types::LeaseAuthorityWire<'_>) { let _ = w.capability; }", "E0616", "capability"),
        ("fn bad(w: types::JobAuthorityWire<'_>) { let _ = w.capability; }", "E0616", "capability"),
    ] {
        let negative = compile_contract(body);
        assert!(!negative.status.success(), "unsafe contract compiled: {body}");
        let stderr = String::from_utf8_lossy(&negative.stderr);
        assert!(stderr.contains(diagnostic) && stderr.contains(type_name), "wrong compiler failure: {stderr}");
    }
}

#[test]
fn providers_are_exact_source_names_without_model_selection() {
    for (name, provider) in [("claude", Provider::Claude), ("codex", Provider::Codex)] {
        assert_eq!(name.parse::<Provider>(), Ok(provider));
        assert_eq!(provider.as_str(), name);
        assert_eq!(serde_json::to_value(provider).unwrap(), json!(name));
    }
    for name in ["", "Claude", " codex", "gpt-6.1-sol", "synthetic-secret"] {
        let error = name.parse::<Provider>().unwrap_err();
        assert_eq!(error, ContractError::UnknownProvider);
        assert!(!format!("{error:?} {error}").contains(name) || name.is_empty());
    }
}

#[test]
fn report_status_is_not_job_state_or_the_plugins_smaller_result_set() {
    for (name, status) in [
        ("completed", ReportStatus::Completed),
        ("failed", ReportStatus::Failed),
        ("timed_out", ReportStatus::TimedOut),
        ("cancelled", ReportStatus::Cancelled),
    ] {
        assert_eq!(name.parse::<ReportStatus>(), Ok(status));
        assert_eq!(status.as_str(), name);
        assert_eq!(serde_json::to_value(status).unwrap(), json!(name));
    }
    for name in [
        "reserved",
        "running",
        "review_pending",
        "rejected",
        "orphaned",
        "synthetic-secret",
    ] {
        let error = name.parse::<ReportStatus>().unwrap_err();
        assert_eq!(error, ContractError::InvalidReportStatus);
        assert!(!format!("{error:?} {error}").contains(name));
    }
}

#[test]
fn lease_wire_carries_epoch_but_job_wire_carries_job_identity() {
    let lease = LeaseAuthority::new(secret("synthetic-lease-capability"), 42).unwrap();
    let job = JobAuthority::new("job-1".to_owned(), secret("synthetic-job-capability")).unwrap();
    assert_eq!(lease.fencing_token(), 42);
    assert_eq!(job.job_id(), "job-1");
    assert_eq!(
        serde_json::to_value(lease.wire()).unwrap(),
        json!({"capability":"synthetic-lease-capability","fencingToken":42})
    );
    assert_eq!(
        serde_json::to_value(job.wire()).unwrap(),
        json!({"jobId":"job-1","capability":"synthetic-job-capability"})
    );
}

#[test]
fn all_authority_debug_paths_redact_capabilities_and_untrusted_job_ids() {
    let material = secret("synthetic-secret-material");
    let lease = LeaseAuthority::new(secret("synthetic-lease-secret"), 17).unwrap();
    let job = JobAuthority::new(
        "synthetic-secret-id".to_owned(),
        secret("synthetic-job-secret"),
    )
    .unwrap();
    for diagnostic in [
        format!("{material:?} {material:#?}"),
        format!(
            "{lease:?} {lease:#?} {:?} {:#?}",
            lease.wire(),
            lease.wire()
        ),
        format!("{job:?} {job:#?} {:?} {:#?}", job.wire(), job.wire()),
        format!("{:?}", (Some(&lease), vec![&job], job.wire())),
    ] {
        assert!(
            !diagnostic.contains("synthetic-"),
            "authority diagnostic leaked material"
        );
        assert!(diagnostic.contains("[REDACTED]"));
    }
}

#[test]
fn fencing_token_matches_positive_javascript_safe_integer_bounds() {
    for token in [1, 9_007_199_254_740_991] {
        let lease = LeaseAuthority::new(secret("synthetic"), token).unwrap();
        assert_eq!(
            serde_json::to_value(lease.wire()).unwrap()["fencingToken"],
            json!(token)
        );
    }
    for token in [0, 9_007_199_254_740_992, u64::MAX] {
        assert_eq!(
            LeaseAuthority::new(secret("synthetic"), token).unwrap_err(),
            ContractError::InvalidFencingToken
        );
    }
}

#[test]
fn capability_is_nonempty_but_never_trimmed_or_reformatted() {
    assert_eq!(
        SecretMaterial::new(String::new()).unwrap_err(),
        ContractError::EmptyCapability
    );
    let lease = LeaseAuthority::new(secret(" \t synthetic \n"), 1).unwrap();
    assert_eq!(
        serde_json::to_value(lease.wire()).unwrap()["capability"],
        json!(" \t synthetic \n")
    );
    let whitespace = JobAuthority::new("job".to_owned(), secret(" ")).unwrap();
    assert_eq!(
        serde_json::to_value(whitespace.wire()).unwrap()["capability"],
        json!(" ")
    );
}

#[test]
fn job_identity_uses_core_javascript_trim_and_utf16_limits() {
    let job = JobAuthority::new(
        "\u{feff}\u{a0}job-1\u{2029}".to_owned(),
        secret("synthetic"),
    )
    .unwrap();
    assert_eq!(job.job_id(), "job-1");
    assert!(JobAuthority::new("x".repeat(128), secret("synthetic")).is_ok());
    assert!(JobAuthority::new("😀".repeat(64), secret("synthetic")).is_ok());
    for id in [
        String::new(),
        "\u{feff} \t".to_owned(),
        "x".repeat(129),
        "😀".repeat(65),
    ] {
        assert_eq!(
            JobAuthority::new(id, secret("synthetic")).unwrap_err(),
            ContractError::InvalidJobId
        );
    }
    // Rust's trim includes NEL; JavaScript's trim does not.
    let nel = JobAuthority::new("\u{85}job\u{85}".to_owned(), secret("synthetic")).unwrap();
    assert_eq!(nel.job_id(), "\u{85}job\u{85}");
}

#[test]
fn validation_errors_are_safe_in_display_debug_and_serialization() {
    for error in [
        ContractError::EmptyCapability,
        ContractError::InvalidFencingToken,
        ContractError::InvalidJobId,
        ContractError::UnknownProvider,
        ContractError::InvalidReportStatus,
    ] {
        let diagnostic = format!(
            "{error} {error:?} {}",
            serde_json::to_string(&error).unwrap()
        );
        assert!(!diagnostic.contains("synthetic-secret"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn only_an_explicit_cloud_refusal_establishes_refused_mutation_outcome() {
    for error in [
        CloudError::Transport,
        CloudError::Http { status: 500 },
        CloudError::Http { status: 403 },
        CloudError::Protocol,
        CloudError::Rpc,
    ] {
        assert_eq!(error.outcome(), MutationOutcome::Unknown);
        let diagnostic = format!(
            "{error} {error:?} {}",
            serde_json::to_string(&error).unwrap()
        );
        assert!(!diagnostic.contains("synthetic-secret"));
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(CloudError::Refused.outcome(), MutationOutcome::Refused);
    assert_eq!(
        serde_json::to_value(CloudError::Transport).unwrap(),
        json!({"kind":"transport"})
    );
    assert_eq!(
        serde_json::to_value(CloudError::Http { status: 503 }).unwrap(),
        json!({"kind":"http","status":503})
    );
    assert_eq!(
        serde_json::to_value(CloudError::Rpc).unwrap(),
        json!({"kind":"rpc"})
    );
    assert_eq!(
        serde_json::to_value(CloudError::Protocol).unwrap(),
        json!({"kind":"protocol"})
    );
    assert_eq!(
        serde_json::to_value(CloudError::Refused).unwrap(),
        json!({"kind":"refused"})
    );
}
