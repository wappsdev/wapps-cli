// completion, `wapps completion <shell>`: the scripts clap_complete generates
// out of cli::completion_tree().
//
// The owner's decision (docs/PORT-kalan-yuzey.md §4.2): generated from the
// command definitions, so a verb added to the tree is in the next script
// without anyone touching this file. The scripts are not cobra's bytes (cobra's
// call the binary back through `__complete`; these carry the tree);
// tests/completion.rs compares what Tab offers with them instead.
use crate::cli;
use clap::Command;
use clap_complete::Shell;
use std::io::Write;

/// write, the script for `shell` (one of the four cobra offers), with or
/// without the commands' and flags' descriptions (`--no-descriptions`).
pub fn write<W: Write>(out: &mut W, shell: &str, descriptions: bool) -> std::io::Result<()> {
    let shell = match shell {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" => Shell::PowerShell,
        other => unreachable!("not a completion shell: {other}"),
    };
    let mut cmd = cli::completion_tree();
    if !descriptions {
        cmd = without_descriptions(cmd);
    }
    // Into a buffer first: clap_complete panics on a failed write, and a
    // closed stdout (`wapps completion zsh | head`) is an error to report.
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut cmd, "wapps", &mut script);
    out.write_all(&script)
}

/// descriptions, a shell's `--no-descriptions` as pflag parses it (a bool
/// flag: `--no-descriptions=false` is accepted, a bad value is pflag's
/// sentence, at parse time): whether the script carries descriptions.
pub fn descriptions(m: &clap::ArgMatches) -> Result<bool, String> {
    use crate::coolifyverb::{bool_errors, bool_value, first_error};
    first_error(bool_errors(m, "no-descriptions"))?;
    Ok(!bool_value(m, "no-descriptions", false)?)
}

/// no_args, cobra's NoArgs on a shell: an extra word is an "unknown command".
pub fn no_args(shell: &str, m: &clap::ArgMatches) -> Result<(), String> {
    match m.get_many::<String>("extra").and_then(|mut v| v.next()) {
        Some(extra) => Err(format!(
            "unknown command {} for \"wapps completion {shell}\"",
            crate::gojson::quote(extra)
        )),
        None => Ok(()),
    }
}

fn without_descriptions(cmd: Command) -> Command {
    let mut cmd = cmd
        .about(None::<&str>)
        .long_about(None::<&str>)
        .mut_args(|a| a.help(None::<&str>).long_help(None::<&str>));
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(name, without_descriptions);
    }
    cmd
}
