// A program the harness writes is run at once, from a test binary whose other
// threads are spawning processes of their own. On Linux, exec(2) refuses a file
// that any process still holds open for writing (ETXTBSY), and a child forked
// by another thread holds a copy of every descriptor this process had open
// until that child execs. So a file written in this process can be refused
// even after it was closed here: CI run 37291344603 failed this way in mcp.rs.
use broker_oracle::exe::write_executable;
use broker_oracle::hermetic::temp_root;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

#[test]
fn a_program_written_while_other_threads_spawn_runs_at_once() {
    let root = temp_root("exe-race");
    let stop = Arc::new(AtomicBool::new(false));
    let spawners: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    Command::new("/bin/sh").arg("-c").arg(":").status().unwrap();
                }
            })
        })
        .collect();
    let writers: Vec<_> = (0..4)
        .map(|w| {
            let root = root.clone();
            thread::spawn(move || {
                for i in 0..60 {
                    let exe = root.join(format!("prog-{w}-{i}"));
                    write_executable(&exe, b"#!/bin/sh\nexit 7\n").unwrap();
                    let status = Command::new(&exe)
                        .status()
                        .unwrap_or_else(|e| panic!("cannot start {}: {e}", exe.display()));
                    assert_eq!(status.code(), Some(7));
                }
            })
        })
        .collect();
    let results: Vec<_> = writers.into_iter().map(|t| t.join()).collect();
    stop.store(true, Ordering::Relaxed);
    for t in spawners {
        t.join().unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
    for r in results {
        r.unwrap();
    }
}

#[test]
fn the_written_program_has_the_bytes_and_mode_given() {
    use std::os::unix::fs::PermissionsExt;
    let root = temp_root("exe-bytes");
    let exe = root.join("prog");
    write_executable(&exe, b"#!/bin/sh\necho hi\n").unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), b"#!/bin/sh\necho hi\n");
    assert_eq!(
        std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
        0o755
    );
    let _ = std::fs::remove_dir_all(&root);
}
