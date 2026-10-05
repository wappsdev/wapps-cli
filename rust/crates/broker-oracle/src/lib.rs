//! The broker daemon's oracle harness (docs/broker-daemon-port.md §6, slice 13.0).
//!
//! Every daemon slice is held to the seams built here:
//!
//! - [`peer`]: the fake `claude` and `codex` workers. They record exactly what the
//!   daemon launches (argv, environment names, cwd, every stdin frame) and answer
//!   from a script (seam 1).
//! - [`cloud`]: the fake cloud broker, answering from recorded exchanges of the
//!   real Worker routes and recording every request (seam 3).
//! - [`mcp`]: drives a stdio MCP server one request at a time and writes a
//!   transcript that is compared byte for byte after [`normalize`] (seam 2).
//! - [`hermetic`]: skill and rulebook roots inside the fixture, so no run reads
//!   the owner's real `~/.claude` (Finding 0.1).
//! - [`plugin`]: the bun/TypeScript plugin run as the oracle under all of the above.
//!
//! Recordings are text, one line per frame: `in <bytes>` for what the recorded
//! process read, `out <bytes>` for what it wrote. Frames are kept as the bytes
//! that crossed the pipe, never re-serialised, so the comparison is of what was
//! sent and not of a parse of it.

pub mod cloud;
pub mod compare;
pub mod exe;
pub mod hermetic;
pub mod mcp;
pub mod normalize;
pub mod peer;
pub mod plugin;
pub mod template;
