// The fake cloud is seam 3's oracle stand-in: it must hand back the real
// Worker's bytes and remember exactly what it was asked, never a secret.
use broker_oracle::cloud::{Envelope, Exchange, FakeCloud, Fixture, Request};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

struct Answer {
    status: u16,
    head: String,
    body: String,
}

fn http(url: &str, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Answer {
    let addr = url.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Answer {
        status,
        head: head.to_string(),
        body: body.to_string(),
    }
}

fn exchange(id: &str, method: &str, path: &str, body: Option<&str>, answer: &str) -> Exchange {
    Exchange {
        id: id.to_string(),
        route: format!("{method} {path}"),
        principal: None,
        request: Request {
            method: method.to_string(),
            path: path.to_string(),
            body: body.map(str::to_string),
        },
        status: 200,
        envelope: Envelope {
            content_type: "application/json; charset=utf-8".to_string(),
            retry_after: None,
        },
        body: answer.to_string(),
    }
}

#[test]
fn a_recorded_answer_is_served_byte_for_byte() {
    let mut retry = exchange(
        "busy",
        "POST",
        "/v1/missions",
        Some(r#"{"missionId":"m"}"#),
        "{\"error\":\"x\"}\n",
    );
    retry.status = 429;
    retry.envelope.retry_after = Some("2".to_string());
    let cloud = FakeCloud::start(vec![retry], None).unwrap();
    let a = http(
        cloud.url(),
        "POST",
        "/v1/missions",
        &[],
        r#"{"missionId":"m"}"#,
    );
    assert_eq!(a.status, 429);
    assert!(
        a.head
            .contains("\r\ncontent-type: application/json; charset=utf-8"),
        "{}",
        a.head
    );
    assert!(a.head.contains("\r\nretry-after: 2"), "{}", a.head);
    assert_eq!(a.body, "{\"error\":\"x\"}\n");
}

#[test]
fn the_same_request_twice_gets_the_storyline_in_order() {
    let cloud = FakeCloud::start(
        vec![
            exchange("first", "GET", "/v1/missions/m/lease", None, "1"),
            exchange("second", "GET", "/v1/missions/m/lease", None, "2"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        http(cloud.url(), "GET", "/v1/missions/m/lease", &[], "").body,
        "1"
    );
    assert_eq!(
        http(cloud.url(), "GET", "/v1/missions/m/lease", &[], "").body,
        "2"
    );
    let answered: Vec<_> = cloud.requests().into_iter().map(|r| r.answered).collect();
    assert_eq!(
        answered,
        [Some("first".to_string()), Some("second".to_string())]
    );
}

#[test]
fn bodies_are_matched_as_json_and_a_different_body_is_not_answered() {
    let cloud = FakeCloud::start(
        vec![exchange(
            "w",
            "POST",
            "/v1/x",
            Some(r#"{"a":1,"b":[1,2]}"#),
            "ok",
        )],
        None,
    )
    .unwrap();
    let other = http(cloud.url(), "POST", "/v1/x", &[], r#"{"a":2,"b":[1,2]}"#);
    assert_eq!(other.status, 501);
    assert!(other.body.contains("ORACLE_UNMATCHED"), "{}", other.body);
    let same = http(
        cloud.url(),
        "POST",
        "/v1/x",
        &[],
        r#"{ "b": [1, 2], "a": 1 }"#,
    );
    assert_eq!(same.status, 200);
    assert_eq!(same.body, "ok");
    let recorded = cloud.requests();
    assert_eq!(recorded[0].answered, None);
    assert_eq!(recorded[1].answered.as_deref(), Some("w"));
    assert_eq!(recorded[1].body, r#"{ "b": [1, 2], "a": 1 }"#);
}

#[test]
fn access_headers_are_seen_by_name_and_their_values_are_never_kept() {
    let secret = "s3cr3t-value-of-the-service-token";
    let cloud = FakeCloud::start(
        vec![
            exchange("a", "GET", "/v1/health", None, "{}"),
            exchange(
                "b",
                "POST",
                "/v1/x",
                Some(r#"{"note":"leaks s3cr3t-value-of-the-service-token"}"#),
                "{}",
            ),
        ],
        Some(secret.to_string()),
    )
    .unwrap();
    http(
        cloud.url(),
        "GET",
        "/v1/health",
        &[
            ("CF-Access-Client-Id", "id.access"),
            ("CF-Access-Client-Secret", secret),
        ],
        "",
    );
    http(
        cloud.url(),
        "POST",
        "/v1/x",
        &[("CF-Access-Client-Id", "id.access")],
        r#"{"note":"leaks s3cr3t-value-of-the-service-token"}"#,
    );
    let recorded = cloud.requests();
    assert!(recorded[0].access);
    assert!(!recorded[0].leaked);
    assert!(
        !recorded[1].access,
        "a request with only the client id is not authenticated"
    );
    assert!(recorded[1].leaked, "the secret in a body is a leak");
    assert!(recorded[0]
        .headers
        .contains(&"cf-access-client-secret".to_string()));
    let everything = format!("{recorded:?}");
    assert_eq!(
        everything.matches(secret).count(),
        1,
        "kept only inside the leaking body: {everything}"
    );
}

#[test]
fn the_committed_fixture_is_the_real_workers_surface() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/cloud/surface-transcript.json");
    let fixture = Fixture::load(&path).unwrap();
    assert_eq!(fixture.exchanges.len(), 127);
    let mut routes: Vec<&str> = fixture.exchanges.iter().map(|e| e.route.as_str()).collect();
    routes.sort();
    routes.dedup();
    assert_eq!(routes.len(), 37, "the 37 route! rows of broker_routes.rs");
}

#[test]
fn replaying_the_fixture_storyline_returns_every_recorded_answer() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/cloud/surface-transcript.json");
    let fixture = Fixture::load(&path).unwrap();
    let cases = fixture.exchanges.clone();
    let cloud = FakeCloud::start(fixture.exchanges, None).unwrap();
    for case in &cases {
        let body = case.request.body.as_deref().unwrap_or("");
        let a = http(
            cloud.url(),
            &case.request.method,
            &case.request.path,
            &[],
            body,
        );
        assert_eq!(a.status, case.status, "{}", case.id);
        assert_eq!(a.body, case.body, "{}", case.id);
    }
    assert!(cloud.requests().iter().all(|r| r.answered.is_some()));
    assert!(cloud.unanswered().is_empty());
}
