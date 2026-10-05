//! The fake `claude`/`codex` worker; see `broker_oracle::peer`.
fn main() {
    std::process::exit(broker_oracle::peer::run_from_exe());
}
