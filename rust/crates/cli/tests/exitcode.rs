// The process exit code a failing verb leaves behind.
//
// Every error used to exit 1 (Go's root: `os.Exit(1)` after reportError). Two
// verbs own their code instead, and both write their own output first:
// `wapps deploy` (its 0..8 contract, cmd/deploy/deploy.go) and the exec family
// (the child's code, mirrored). `CmdError::Exit` carries that code to main's
// single exit point; the root's reporter must print nothing for it.
use wapps::cli::{report_error, CmdError};
use wapps::clierr::{Code, Error};

fn reported(e: &CmdError, agent: bool) -> String {
    let mut out = Vec::new();
    report_error(&mut out, e, agent);
    String::from_utf8(out).expect("utf-8")
}

#[test]
fn reported_errors_exit_1() {
    assert_eq!(CmdError::Plain("x".into()).exit_code(), 1);
    assert_eq!(
        CmdError::Cli(Error::new(Code::Internal, "x")).exit_code(),
        1
    );
}

#[test]
fn a_verb_owned_code_is_carried_as_is() {
    for code in [2u8, 3, 7, 8, 255] {
        assert_eq!(CmdError::Exit(code).exit_code(), code);
    }
}

#[test]
fn a_verb_owned_code_prints_nothing_in_either_mode() {
    assert_eq!(reported(&CmdError::Exit(4), false), "");
    assert_eq!(reported(&CmdError::Exit(4), true), "");
}
