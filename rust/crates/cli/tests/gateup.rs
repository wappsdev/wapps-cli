// The fake gates come up on a machine whose reverse DNS hangs, as the hosted
// macOS runner's does (tests/pty/gateup.py says how that was measured). Without
// this, the differential and every other pty probe fail there with "fake gate
// did not come up" before measuring anything.
use std::path::Path;
use std::process::Command;

#[test]
fn every_fake_gate_comes_up_while_reverse_dns_hangs() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/gateup.py");
    let out = Command::new("python3")
        .arg(&script)
        .output()
        .expect("cannot run python3");
    assert!(
        out.status.success(),
        "gateup.py failed (exit {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
