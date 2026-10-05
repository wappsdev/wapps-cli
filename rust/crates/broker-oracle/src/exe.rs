//! Writing a program that is about to be run.
//!
//! On Linux, exec(2) refuses a file that any process holds open for writing
//! (ETXTBSY). A test binary runs its tests on threads, and a child that another
//! thread forks inherits every descriptor this process has open at that moment,
//! keeping it until the child itself execs. So a program written here with
//! `fs::write` or `fs::copy` can be refused AFTER this process closed it, while
//! a sibling test's fork still holds the copy: CI run 37291344603 failed this
//! way (`Text file busy`). Closing or fsyncing first does not help; the
//! descriptor that blocks is the inherited one.
//!
//! So the bytes are written by a short-lived `/bin/sh` child instead, and the
//! write descriptor exists only in that child, which forks nothing. No process
//! forked from the test binary ever holds the file open for writing, so there
//! is no window to retry through. Every place in the workspace that writes a
//! program and then runs it writes it through here.

use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Writes `bytes` to `path` as an executable (mode 0755), replacing any file
/// there. The parent directory must exist.
pub fn write_executable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"cat > "$1" && chmod 755 "$1""#)
        .arg("sh")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let written = stdin.write_all(bytes);
    drop(stdin);
    let status = child.wait()?;
    written?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "cannot write the program {}: /bin/sh exited with {status}",
            path.display()
        )))
    }
}
