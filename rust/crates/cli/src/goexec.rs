// goexec, Go `os/exec` behavior a port can observe: how a bare program name
// is found on PATH, and the text of a child's failed exit. Both were private
// to loginverb; `secrets sync` runs `tofu` the same way, so they live here
// now, unchanged.
use std::path::{Path, PathBuf};

// exit_text, Go's *exec.ExitError text: "exit status N" or "signal: <name>".
pub fn exit_text(st: std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    if st.success() {
        return None;
    }
    if let Some(code) = st.code() {
        return Some(format!("exit status {code}"));
    }
    let sig = st.signal().unwrap_or(0);
    // Go's syscall signal table; only the names a dying cloudflared plausibly
    // reports are carried, the rest print Go's numeric fallback.
    let name = match sig {
        1 => "hangup".to_string(),
        2 => "interrupt".to_string(),
        9 => "killed".to_string(),
        15 => "terminated".to_string(),
        n => format!("signal {n}"),
    };
    let core = if st.core_dumped() {
        " (core dumped)"
    } else {
        ""
    };
    Some(format!("signal: {name}{core}"))
}

// look_path, Go's exec.LookPath for a bare name: the first PATH entry holding
// an executable regular file. A match in a RELATIVE entry is an error in Go
// (exec.ErrDot), so it ends the search as "not found".
pub fn look_path(name: &str, path_env: &str) -> Option<PathBuf> {
    for dir in path_env.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = Path::new(dir).join(name);
        if crate::doctorverb::is_executable_file(&p) {
            return if p.is_absolute() { Some(p) } else { None };
        }
    }
    None
}
