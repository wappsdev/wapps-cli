// cobrahelp renders cobra's help layout out of the clap command tree.
//
// The Go binary is the oracle and its help is cobra's default template
// (cobra v1.10.2 `defaultHelpFunc` / `defaultUsageFunc`, pflag v1.0.10
// `FlagUsagesWrapped(0)`), so the Rust binary prints that layout, not clap's.
// clap still parses; it is only no longer the one that writes the page.
//
// Where cobra's data lives on the clap tree:
//
//   cobra Short    -> `about`
//   cobra Long     -> `long_about`
//   cobra Use      -> `override_usage` (the name when absent)
//   pflag type     -> the arg's `value_name` ("string", "int", "strings",
//                     "stringArray"); a flag without one is a bool
//   pflag usage    -> the arg's `help`, written as pflag prints it, so a
//                     non-zero default carries its " (default ...)" suffix in
//                     the text itself: several defaults are applied by the
//                     verb's own flag parsing (pflag semantics), not by clap
//
// Only the root's flags are persistent (cobra's "Global Flags"), as in Go. The
// help flag is cobra's on every node and `--version` is the root's alone; both
// are drawn here, whatever the tree carries for parsing.
//
// Runnable: a node without subcommands. In this tree every cobra command that
// has a Run has no children and no family has a Run, so the two coincide;
// tests/helpaxis.rs compares every page with the oracle.
use crate::gojson::quote as go_quote;
use clap::{Arg, Command};

// cobra's minNamePadding.
const MIN_NAME_PADDING: usize = 11;

/// chain resolves a path of subcommand names to the commands along it, root
/// first. None when a name is not a subcommand.
pub fn chain<'a>(root: &'a Command, path: &[String]) -> Option<Vec<&'a Command>> {
    let mut out = vec![root];
    for name in path {
        let next = out.last()?.find_subcommand(name)?;
        out.push(next);
    }
    Some(out)
}

/// help_page, cobra's `defaultHelpFunc` for the last command of the chain.
pub fn help_page(chain: &[&Command]) -> String {
    let c = chain[chain.len() - 1];
    let text = c
        .get_long_about()
        .or(c.get_about())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let text = text.trim_end();
    let mut out = String::new();
    if !text.is_empty() {
        out.push_str(text);
        out.push_str("\n\n");
    }
    // Runnable || HasSubCommands holds for every node of this tree.
    out.push_str(&usage_string(chain, true));
    out
}

/// usage_string, cobra's `defaultUsageFunc`. `flags_ready`: whether cobra
/// has initialized the command's help (and on the root version) flag, which
/// it does only for a command it executes or shows a page for. The help
/// command's "Unknown help topic" prints the root's usage without them.
pub fn usage_string(chain: &[&Command], flags_ready: bool) -> String {
    let c = chain[chain.len() - 1];
    let path = command_path(chain);
    let mut out = String::from("Usage:");
    let subs: Vec<&Command> = {
        let mut v: Vec<&Command> = c.get_subcommands().filter(|s| !s.is_hide_set()).collect();
        v.sort_by(|a, b| a.get_name().cmp(b.get_name()));
        v
    };
    if subs.is_empty() {
        out.push_str("\n  ");
        out.push_str(&use_line(chain));
    } else {
        out.push_str(&format!("\n  {path} [command]"));
        let pad = c
            .get_subcommands()
            .map(|s| s.get_name().len())
            .max()
            .unwrap_or(0)
            .max(MIN_NAME_PADDING);
        out.push_str("\n\nAvailable Commands:");
        for s in &subs {
            let short = s.get_about().map(|a| a.to_string()).unwrap_or_default();
            out.push_str(&format!("\n  {:<pad$} {short}", s.get_name()));
        }
    }
    let local = local_flags(chain, flags_ready);
    if !local.is_empty() {
        out.push_str("\n\nFlags:\n");
        out.push_str(flag_usages(&local).trim_end());
    }
    let inherited = inherited_flags(chain);
    if !inherited.is_empty() {
        out.push_str("\n\nGlobal Flags:\n");
        out.push_str(flag_usages(&inherited).trim_end());
    }
    if !subs.is_empty() {
        out.push_str(&format!(
            "\n\nUse \"{path} [command] --help\" for more information about a command."
        ));
    }
    out.push('\n');
    out
}

/// Found, what cobra's `Find` resolves an argv to.
pub struct Found {
    /// The command's path (empty: the root).
    pub path: Vec<String>,
    /// legacyArgs on the root: the first word that names no command.
    pub unknown: Option<String>,
}

/// find, cobra's `Command.Find` over the argv (without the program name).
///
/// It is not clap's matching, and the difference is observable: Find runs
/// BEFORE cobra initializes the help and version flags (that happens in
/// `execute`, for the found command only), so `-h`, `--help` and `--version`
/// are unknown to it and, like any flag it does not know as a bool, take the
/// next word as their value. `wapps -h secrets get` is therefore "unknown
/// command "get" for "wapps"", and `wapps secrets -h get` is `secrets`'s page.
pub fn find(root: &Command, args: &[String]) -> Found {
    let mut chain = vec![root];
    let mut path = Vec::new();
    let mut rest = args.to_vec();
    loop {
        let words = strip_flags(&rest, &chain);
        let Some(next) = words.first() else { break };
        let Some(sub) = chain[chain.len() - 1].find_subcommand(next) else {
            break;
        };
        rest = args_minus_first_x(&rest, next, &chain);
        path.push(next.clone());
        chain.push(sub);
    }
    let unknown = if path.is_empty() {
        strip_flags(&rest, &chain).first().cloned()
    } else {
        None
    };
    Found { path, unknown }
}

// consumes_next: a `--name` or `-x` token without "=" that takes_value.
fn consumes_next(s: &str, chain: &[&Command]) -> bool {
    (s.starts_with("--") || (s.starts_with('-') && s.len() == 2))
        && !s.contains('=')
        && takes_value(s, chain)
}

// takes_value: does the flag token consume the next word, by Find's rule —
// anything that is not a bool flag known to the command at Find time.
fn takes_value(token: &str, chain: &[&Command]) -> bool {
    let bools = find_time_flags(chain)
        .into_iter()
        .filter(|f| f.kind.is_empty())
        .collect::<Vec<_>>();
    if let Some(long) = token.strip_prefix("--") {
        return !bools.iter().any(|f| f.long == long);
    }
    let short = token.chars().nth(1);
    !bools.iter().any(|f| f.short.is_some() && f.short == short)
}

// The flags `Find` sees on the last command of the chain: its own and the
// root's persistent ones it does not shadow; never help or version.
fn find_time_flags(chain: &[&Command]) -> Vec<Flag> {
    let c = chain[chain.len() - 1];
    let mut flags: Vec<Flag> = c
        .get_arguments()
        .filter(|a| is_flag(a))
        .map(flag_of)
        .collect();
    flags.extend(inherited_flags(chain));
    flags
}

// cobra's stripFlags: the words of `args` that are not flags or flag values.
fn strip_flags(args: &[String], chain: &[&Command]) -> Vec<String> {
    let mut words = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let s = &args[i];
        i += 1;
        if s == "--" {
            break;
        }
        if consumes_next(s, chain) {
            if args.len() - i <= 1 {
                break;
            }
            i += 1;
        } else if !s.is_empty() && !s.starts_with('-') {
            words.push(s.clone());
        }
    }
    words
}

// cobra's argsMinusFirstX: `args` without the first `x` that is not a flag value.
fn args_minus_first_x(args: &[String], x: &str, chain: &[&Command]) -> Vec<String> {
    let mut pos = 0;
    while pos < args.len() {
        let s = &args[pos];
        if s == "--" {
            break;
        }
        if consumes_next(s, chain) {
            pos += 2;
            continue;
        }
        if !s.starts_with('-') && s == x {
            let mut out = args.to_vec();
            out.remove(pos);
            return out;
        }
        pos += 1;
    }
    args.to_vec()
}

/// version_line, cobra's `defaultVersionFunc` for the root.
pub fn version_line(root: &Command) -> String {
    format!(
        "{} version {}\n",
        root.get_name(),
        env!("CARGO_PKG_VERSION")
    )
}

/// unknown_command, the root's `legacyArgs` error with cobra's suggestions.
pub fn unknown_command(root: &Command, arg: &str) -> String {
    let mut msg = format!(
        "unknown command {} for {}",
        go_quote(arg),
        go_quote(root.get_name())
    );
    let suggestions = suggestions_for(root, arg);
    if !suggestions.is_empty() {
        msg.push_str("\n\nDid you mean this?\n");
        for s in suggestions {
            msg.push_str(&format!("\t{s}\n"));
        }
    }
    msg
}

/// unknown_help_topic, the first line cobra's help command prints for a path
/// the root cannot resolve: `%#q` of the argument slice.
pub fn unknown_help_topic(args: &[String]) -> String {
    let quoted: Vec<String> = args
        .iter()
        .map(|a| {
            if can_backquote(a) {
                format!("`{a}`")
            } else {
                go_quote(a)
            }
        })
        .collect();
    format!("Unknown help topic [{}]\n", quoted.join(" "))
}

// strconv.CanBackquote for a valid UTF-8 string.
fn can_backquote(s: &str) -> bool {
    s.chars()
        .all(|c| c != '`' && c != '\u{FEFF}' && (c == '\t' || !c.is_control()))
}

// SuggestionsFor: Levenshtein distance <= 2 or a case-insensitive prefix, over
// the available commands (cobra's help command is not one).
fn suggestions_for(root: &Command, typed: &str) -> Vec<String> {
    let mut subs: Vec<&Command> = root
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
        .collect();
    subs.sort_by(|a, b| a.get_name().cmp(b.get_name()));
    subs.into_iter()
        .filter(|s| {
            let name = s.get_name();
            levenshtein(&typed.to_lowercase(), &name.to_lowercase()) <= 2
                || name.to_lowercase().starts_with(&typed.to_lowercase())
        })
        .map(|s| s.get_name().to_string())
        .collect()
}

// cobra's `ld`, over bytes.
fn levenshtein(s: &str, t: &str) -> usize {
    let (s, t) = (s.as_bytes(), t.as_bytes());
    let mut d = vec![vec![0usize; t.len() + 1]; s.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for j in 1..=t.len() {
        for i in 1..=s.len() {
            d[i][j] = if s[i - 1] == t[j - 1] {
                d[i - 1][j - 1]
            } else {
                d[i - 1][j].min(d[i][j - 1]).min(d[i - 1][j - 1]) + 1
            };
        }
    }
    d[s.len()][t.len()]
}

fn command_path(chain: &[&Command]) -> String {
    chain
        .iter()
        .map(|c| c.get_name())
        .collect::<Vec<_>>()
        .join(" ")
}

// UseLine: the parent's path, the Use string, then " [flags]" (every command
// has at least the help flag).
fn use_line(chain: &[&Command]) -> String {
    let c = chain[chain.len() - 1];
    let use_ = c
        .get_overridden_usage()
        .map(|u| u.to_string())
        .unwrap_or_else(|| c.get_name().to_string());
    let mut line = if chain.len() > 1 {
        format!("{} {use_}", command_path(&chain[..chain.len() - 1]))
    } else {
        use_
    };
    if !line.contains("[flags]") {
        line.push_str(" [flags]");
    }
    line
}

struct Flag {
    long: String,
    short: Option<char>,
    // pflag's type word; empty for a bool.
    kind: String,
    usage: String,
}

fn is_flag(a: &Arg) -> bool {
    a.get_long().is_some() && !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version"
}

fn flag_of(a: &Arg) -> Flag {
    Flag {
        long: a.get_long().unwrap_or_default().to_string(),
        short: a.get_short(),
        kind: a
            .get_value_names()
            .and_then(|v| v.first())
            .map(|v| v.to_string())
            .unwrap_or_default(),
        usage: a.get_help().map(|h| h.to_string()).unwrap_or_default(),
    }
}

// LocalFlags: the command's own flags (on the root, the persistent ones), and
// once initialized its help flag and on the root `--version`.
fn local_flags(chain: &[&Command], flags_ready: bool) -> Vec<Flag> {
    let c = chain[chain.len() - 1];
    let mut flags: Vec<Flag> = c
        .get_arguments()
        .filter(|a| is_flag(a))
        .map(flag_of)
        .collect();
    if !flags_ready {
        return flags;
    }
    flags.push(Flag {
        long: "help".into(),
        short: Some('h'),
        kind: String::new(),
        usage: format!("help for {}", c.get_name()),
    });
    if chain.len() == 1 {
        flags.push(Flag {
            long: "version".into(),
            short: None,
            kind: String::new(),
            usage: format!("version for {}", c.get_name()),
        });
    }
    flags
}

// InheritedFlags: the root's persistent flags a local flag of the same name
// does not shadow.
fn inherited_flags(chain: &[&Command]) -> Vec<Flag> {
    if chain.len() == 1 {
        return Vec::new();
    }
    let c = chain[chain.len() - 1];
    let local: Vec<&str> = c.get_arguments().filter_map(|a| a.get_long()).collect();
    chain[0]
        .get_arguments()
        .filter(|a| is_flag(a) && !local.contains(&a.get_long().unwrap_or_default()))
        .map(flag_of)
        .collect()
}

// pflag's FlagUsagesWrapped(0): sorted by name, the usage column aligned on
// the longest "  -x, --name type" prefix, a back-quoted word in the usage
// replacing the type word.
fn flag_usages(flags: &[Flag]) -> String {
    let mut sorted: Vec<&Flag> = flags.iter().collect();
    sorted.sort_by(|a, b| a.long.cmp(&b.long));
    let mut lines = Vec::new();
    let mut maxlen = 0;
    for f in sorted {
        let mut head = match f.short {
            Some(s) => format!("  -{s}, --{}", f.long),
            None => format!("      --{}", f.long),
        };
        let (varname, usage) = unquote_usage(&f.usage, &f.kind);
        if !varname.is_empty() {
            head.push(' ');
            head.push_str(&varname);
        }
        // pflag counts the "\x00" marker into maxlen.
        maxlen = maxlen.max(head.len() + 1);
        lines.push((head, usage));
    }
    let mut out = String::new();
    for (head, usage) in lines {
        let spacing = " ".repeat(maxlen - head.len());
        let usage = usage.replace('\n', &format!("\n{}", " ".repeat(maxlen + 2)));
        out.push_str(&format!("{head} {spacing} {usage}\n"));
    }
    out
}

// pflag's UnquoteUsage: the first back-quoted word names the value.
fn unquote_usage(usage: &str, kind: &str) -> (String, String) {
    if let Some(i) = usage.find('`') {
        if let Some(len) = usage[i + 1..].find('`') {
            let name = &usage[i + 1..i + 1 + len];
            let rest = format!("{}{name}{}", &usage[..i], &usage[i + 2 + len..]);
            return (name.to_string(), rest);
        }
    }
    (kind.to_string(), usage.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_matches_cobra() {
        assert_eq!(levenshtein("secre", "secrets"), 2);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn a_back_quoted_word_names_the_value() {
        assert_eq!(
            unquote_usage("from `wapps dr verify`; else", "string"),
            (
                "wapps dr verify".to_string(),
                "from wapps dr verify; else".to_string()
            )
        );
        // One back quote only: the type word stays.
        assert_eq!(
            unquote_usage("a ` b", "string"),
            ("string".to_string(), "a ` b".to_string())
        );
    }

    #[test]
    fn help_topics_are_back_quoted_unless_they_cannot_be() {
        assert_eq!(
            unknown_help_topic(&["a".into(), "b`c".into()]),
            "Unknown help topic [`a` \"b`c\"]\n"
        );
    }
}
