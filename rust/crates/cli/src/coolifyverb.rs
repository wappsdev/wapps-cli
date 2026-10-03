// coolifyverb, the `wapps coolify` leaves — the port of cmd/coolify/*.go:
// update-env, set-labels, deploy-app, deploy-app-git, import-app.
//
// Order, measured from the Go oracle (tests/pty/cases.py, COOLIFY_CASES and
// COOLIFY_DEPLOY_CASES):
//
//   1. flag VALUES (pflag): every StringSlice value (`--env`, `--label`,
//      `--env-from-shell`, `--watch-path`, `--build-arg`) is read as CSV and
//      every bool (`--strip-cert-resolver`, `--instant-deploy`) by
//      strconv.ParseBool; the first bad value from the left is the error.
//      This is PARSE time in Go, so it beats the root's `--config`/`--project`
//      check — main.rs calls `parse_flags` before it;
//   2. the required flags (cobra, after the root hook): every missing one
//      named, in sorted order;
//   3. COOLIFY_API_TOKEN;
//   4. the verb's own checks, then the client (uuid check, then HTTP).
//
// No agent gate, no binding, no `Ctx`: the root `-c`/`-p` are inert. The
// files deploy-app[-git] and import-app write are relative to the cwd.
use crate::coolify::{Client, GitHubApp};
use crate::gocsv;
use crate::goerr;
use crate::gostrconv::{parse_bool, quote};
use crate::wappsyaml::go_clean;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};

// DEFAULT_ENDPOINT, Go's getEndpoint fallback when COOLIFY_URL is unset/empty.
const DEFAULT_ENDPOINT: &str = "https://coolify.meapps.dev/api/v1";

/// Leaf, one parsed `coolify` subcommand. `missing` holds the required
/// flags that were not given (cobra reports them after the root hook).
pub enum Leaf {
    UpdateEnv {
        app_uuid: Option<String>,
        envs: Vec<String>,
    },
    SetLabels {
        app_uuid: Option<String>,
        labels: Vec<String>,
        strip: bool,
    },
    DeployApp {
        missing: Vec<&'static str>,
        project_uuid: String,
        server_uuid: String,
        name: String,
        compose_file: String,
        env_from_shell: Vec<String>,
    },
    DeployAppGit {
        missing: Vec<&'static str>,
        project_uuid: String,
        server_uuid: String,
        github_app_uuid: String,
        name: String,
        git_repo: String,
        git_branch: String,
        dockerfile: String,
        base_dir: String,
        ports: String,
        watch_paths: Vec<String>,
        build_pack: String,
        instant_deploy: bool,
        build_args: Vec<String>,
    },
    ImportApp {
        server_uuid: String,
        output_dir: String,
    },
}

/// string_slice, the values of a pflag `StringSliceVar` given as `flag`:
/// each value read as CSV (gocsv), the results concatenated; a bad value is
/// refused with pflag's sentence.
pub fn string_slice(flag: &str, values: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for v in values {
        out.extend(gocsv::read_as_csv(v).map_err(|e| invalid_argument(v, flag, &e))?);
    }
    Ok(out)
}

// invalid_argument, pflag's `*InvalidValueError` text.
fn invalid_argument(value: &str, flag: &str, cause: &str) -> String {
    format!(
        "invalid argument {} for {} flag: {cause}",
        quote(value),
        quote(flag)
    )
}

/// parse_env_kvs, Go's `parseEnvKVs`: "KEY=VAL" entries into a map (last
/// value of a key wins); an entry without '=' or with an empty key is refused.
pub fn parse_env_kvs(pairs: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for kv in pairs {
        let Some((k, v)) = kv.split_once('=') else {
            return Err(format!("invalid env (need KEY=VAL): {}", quote(kv)));
        };
        if k.is_empty() {
            return Err(format!("invalid env (empty KEY): {}", quote(kv)));
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

/// strip_cert_resolver, set-labels' filter: with `strip` on, every label
/// containing "certresolver=letsencrypt" is dropped.
pub fn strip_cert_resolver(labels: &[String], strip: bool) -> Vec<String> {
    labels
        .iter()
        .filter(|l| !strip || !l.contains("certresolver=letsencrypt"))
        .cloned()
        .collect()
}

// valued, every value of a repeatable arg with its command-line index.
fn valued(m: &clap::ArgMatches, id: &str) -> Vec<(usize, String)> {
    match (m.get_many::<String>(id), m.indices_of(id)) {
        (Some(vals), Some(idx)) => idx.zip(vals.cloned()).collect(),
        _ => Vec::new(),
    }
}

// first_error, the error of the value pflag would hit first (leftmost).
fn first_error(errs: impl IntoIterator<Item = (usize, String)>) -> Result<(), String> {
    match errs.into_iter().min_by_key(|(i, _)| *i) {
        Some((_, e)) => Err(e),
        None => Ok(()),
    }
}

// slice_errors, the CSV error of each occurrence of a StringSlice flag,
// with its command-line index.
fn slice_errors(m: &clap::ArgMatches, id: &str) -> Vec<(usize, String)> {
    valued(m, id)
        .into_iter()
        .filter_map(|(i, v)| string_slice(&format!("--{id}"), &[v]).err().map(|e| (i, e)))
        .collect()
}

// bool_errors, the ParseBool error of each occurrence of a bool flag.
fn bool_errors(m: &clap::ArgMatches, id: &str) -> Vec<(usize, String)> {
    valued(m, id)
        .into_iter()
        .filter_map(|(i, v)| {
            parse_bool(&v)
                .err()
                .map(|e| (i, invalid_argument(&v, &format!("--{id}"), &e)))
        })
        .collect()
}

// bool_value, a pflag BoolVar: its default, or the last occurrence.
fn bool_value(m: &clap::ArgMatches, id: &str, default: bool) -> Result<bool, String> {
    match valued(m, id).pop() {
        Some((_, v)) => parse_bool(&v),
        None => Ok(default),
    }
}

// last, a pflag StringVar: the last occurrence, None when not given.
fn last(m: &clap::ArgMatches, id: &str) -> Option<String> {
    valued(m, id).pop().map(|(_, v)| v)
}

// missing, cobra's required-flag check: the flags never given, sorted (pflag
// visits flags in lexical order). An empty value counts as given.
fn missing(m: &clap::ArgMatches, required: &[&'static str]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = required
        .iter()
        .copied()
        .filter(|id| m.get_many::<String>(id).is_none())
        .collect();
    out.sort_unstable();
    out
}

/// parse_flags, a `coolify` leaf's flags as pflag would have parsed them;
/// None for a leaf this binary does not have.
pub fn parse_flags(leaf: &str, m: &clap::ArgMatches) -> Option<Result<Leaf, String>> {
    let or = |id: &str, default: &str| last(m, id).unwrap_or_else(|| default.to_string());
    Some(match leaf {
        // One slice flag: string_slice already stops at the leftmost bad value.
        "update-env" => string_slice("--env", &values(m, "env")).map(|envs| Leaf::UpdateEnv {
            app_uuid: last(m, "app-uuid"),
            envs,
        }),
        "set-labels" => {
            // Two flags: the error is the leftmost bad value across both.
            let mut errs = slice_errors(m, "label");
            errs.extend(bool_errors(m, "strip-cert-resolver"));
            first_error(errs).and_then(|()| {
                Ok(Leaf::SetLabels {
                    app_uuid: last(m, "app-uuid"),
                    labels: string_slice("--label", &values(m, "label"))?,
                    strip: bool_value(m, "strip-cert-resolver", true)?,
                })
            })
        }
        "deploy-app" => {
            string_slice("--env-from-shell", &values(m, "env-from-shell")).map(|env_from_shell| {
                Leaf::DeployApp {
                    missing: missing(m, &["project-uuid", "server-uuid", "name", "compose-file"]),
                    project_uuid: or("project-uuid", ""),
                    server_uuid: or("server-uuid", ""),
                    name: or("name", ""),
                    compose_file: or("compose-file", ""),
                    env_from_shell,
                }
            })
        }
        "deploy-app-git" => {
            let mut errs = slice_errors(m, "watch-path");
            errs.extend(slice_errors(m, "build-arg"));
            errs.extend(bool_errors(m, "instant-deploy"));
            first_error(errs).and_then(|()| {
                Ok(Leaf::DeployAppGit {
                    missing: missing(
                        m,
                        &[
                            "project-uuid",
                            "server-uuid",
                            "github-app-uuid",
                            "name",
                            "git-repo",
                        ],
                    ),
                    project_uuid: or("project-uuid", ""),
                    server_uuid: or("server-uuid", ""),
                    github_app_uuid: or("github-app-uuid", ""),
                    name: or("name", ""),
                    git_repo: or("git-repo", ""),
                    git_branch: or("git-branch", "main"),
                    dockerfile: or("dockerfile", "Dockerfile"),
                    base_dir: or("base-dir", "/"),
                    ports: or("ports", ""),
                    watch_paths: string_slice("--watch-path", &values(m, "watch-path"))?,
                    build_pack: or("build-pack", "dockerfile"),
                    instant_deploy: bool_value(m, "instant-deploy", true)?,
                    build_args: string_slice("--build-arg", &values(m, "build-arg"))?,
                })
            })
        }
        "import-app" => Ok(Leaf::ImportApp {
            server_uuid: or("server-uuid", ""),
            output_dir: or("output-dir", "./.outputs/import"),
        }),
        _ => return None,
    })
}

fn values(m: &clap::ArgMatches, id: &str) -> Vec<String> {
    m.get_many::<String>(id)
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}

/// collect_env_from_shell, Go's `collectEnvFromShell`: each named variable's
/// value from `lookup`; an unset or EMPTY one is refused before any request.
pub fn collect_env_from_shell(
    keys: &[String],
    lookup: impl Fn(&str) -> String,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for key in keys {
        let val = lookup(key);
        if val.is_empty() {
            return Err(format!(
                "env {key} not set in current shell (expected by --env-from-shell)"
            ));
        }
        out.insert(key.clone(), val);
    }
    Ok(out)
}

// getenv, Go's os.Getenv: an EXACT name match over the environment. libc's
// getenv (behind std::env::var) stops a name at '=' on macOS, so "A=x" would
// read A's value; Go reads nothing.
fn getenv(key: &str) -> String {
    std::env::vars_os()
        .find(|(k, _)| k.as_encoded_bytes() == key.as_bytes())
        .map(|(_, v)| v.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// tofu_identifier, import-app's resource name: the app name lowercased rune
/// by rune, every run outside [a-zA-Z0-9_] replaced by one '_'.
///
/// Go lowercases with unicode.ToLower, one rune to one rune. Rust's full
/// lowercase can be longer: 'İ' gives "i\u{307}", which would add a '_'.
/// Taking only its FIRST char is Go's simple mapping ('İ' is the only rune
/// whose full lowercase has more than one char).
pub fn tofu_identifier(name: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in name.chars() {
        let lower = c.to_lowercase().next().unwrap_or(c);
        if lower.is_ascii_alphanumeric() || lower == '_' {
            out.push(lower);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// go_join, Go's filepath.Join of two elements: empty ones dropped, the
/// result cleaned.
pub fn go_join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        return go_clean(name);
    }
    go_clean(&format!("{dir}/{name}"))
}

/// import_files, the two files import-app writes, as (imports.sh, apps.tf),
/// and how many apps went in: the objects whose `destination.server.uuid`
/// matches `server_uuid` (when given) and that carry a uuid and a name.
pub fn import_files(apps: &[Map<String, Value>], server_uuid: &str) -> (String, String, usize) {
    let mut imports = String::from(
        "#!/usr/bin/env bash\n# Generated by wapps coolify import-app — review before running.\nset -e\n\n",
    );
    let mut hcl = String::from(
        "# Generated stubs by wapps coolify import-app — fill in args from `tofu show <addr>` after import.\n\n",
    );
    let mut count = 0;
    for a in apps {
        let srv = a
            .get("destination")
            .and_then(Value::as_object)
            .and_then(|d| d.get("server"))
            .and_then(Value::as_object)
            .and_then(|s| s.get("uuid"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !server_uuid.is_empty() && srv != server_uuid {
            continue;
        }
        let uuid = a.get("uuid").and_then(Value::as_str).unwrap_or("");
        let name = a.get("name").and_then(Value::as_str).unwrap_or("");
        if uuid.is_empty() || name.is_empty() {
            continue;
        }
        // Go falls back to "app_<uuid[:8]>" for an empty identifier; a
        // non-empty name never yields one, so that branch is unreachable.
        let id = tofu_identifier(name);
        imports.push_str(&format!(
            "tofu import 'coolify_application.{id}' '{uuid}'\n"
        ));
        hcl.push_str(&format!(
            "# Imported from Coolify: {name} (uuid={uuid})\n\
             resource \"coolify_application\" \"{id}\" {{\n\
             \x20 # Run: tofu import, then fill in args from `tofu show coolify_application.{id}`\n\
             }}\n\n"
        ));
        count += 1;
    }
    (imports, hcl, count)
}

// read_file, Go's os.ReadFile: the open and the read fail with their own
// *PathError texts ("read <path>: is a directory" for a directory).
fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let mut f = std::fs::File::open(path).map_err(|e| goerr::open_error(path, &e))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .map_err(|e| goerr::path_error("read", path, &e))?;
    Ok(data)
}

// mkdir_all, Go's os.MkdirAll(path, 0755) with its error ignored (every
// caller ignores it).
fn mkdir_all(path: &str) {
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(path);
}

// write_uuid_file, deploy-app[-git]'s `.outputs/<name>-uuid` (Go's
// os.WriteFile(…, 0644)); every error ignored, as in Go.
fn write_uuid_file(name: &str, uuid: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    mkdir_all(".outputs");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(format!(".outputs/{name}-uuid"))
    {
        let _ = f.write_all(uuid.as_bytes());
    }
}

// create, Go's os.Create: truncate or create with 0666 (before the umask).
fn create(path: &str) -> Result<std::fs::File, String> {
    std::fs::File::create(path).map_err(|e| goerr::open_error(path, &e))
}

fn required(missing: &[&str]) -> Result<(), String> {
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "required flag(s) {} not set",
        missing
            .iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// run, the leaf's RunE after the root hook. Errors are Go's plain texts.
pub fn run<W: Write>(leaf: Leaf, out: &mut W) -> Result<(), String> {
    match &leaf {
        Leaf::UpdateEnv { app_uuid, .. } | Leaf::SetLabels { app_uuid, .. } => {
            if app_uuid.is_none() {
                required(&["app-uuid"])?;
            }
        }
        Leaf::DeployApp { missing, .. } | Leaf::DeployAppGit { missing, .. } => required(missing)?,
        Leaf::ImportApp { .. } => {}
    }
    let token = std::env::var("COOLIFY_API_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err("COOLIFY_API_TOKEN not set".to_string());
    }
    let endpoint = match std::env::var("COOLIFY_URL") {
        Ok(e) if !e.is_empty() => e,
        _ => DEFAULT_ENDPOINT.to_string(),
    };
    let client = Client::new(&endpoint, &token);
    match leaf {
        Leaf::UpdateEnv { app_uuid, envs } => {
            let app_uuid = app_uuid.unwrap_or_default();
            let envs = parse_env_kvs(&envs)?;
            client.update_app_envs(&app_uuid, &envs)?;
            let _ = writeln!(out, "✓ Updated {} env vars on {app_uuid}", envs.len());
        }
        Leaf::SetLabels {
            app_uuid,
            labels,
            strip,
        } => {
            let app_uuid = app_uuid.unwrap_or_default();
            let filtered = strip_cert_resolver(&labels, strip);
            // Coolify treats an empty custom_labels as "clear all labels".
            if filtered.is_empty() {
                return Err("set-labels: no labels to set (pass --label at least once); refusing to wipe existing labels".to_string());
            }
            client.set_custom_labels(&app_uuid, &filtered)?;
            let _ = writeln!(out, "✓ Set {} labels on {app_uuid}", filtered.len());
        }
        Leaf::DeployApp {
            project_uuid,
            server_uuid,
            name,
            compose_file,
            env_from_shell,
            ..
        } => {
            let compose =
                read_file(&compose_file).map_err(|e| format!("read compose file: {e}"))?;
            let envs = collect_env_from_shell(&env_from_shell, getenv)?;
            let uuid = client
                .create_docker_compose_app(&project_uuid, &server_uuid, &name, &compose)
                .map_err(|e| format!("create app: {e}"))?;
            if !envs.is_empty() {
                client
                    .update_app_envs(&uuid, &envs)
                    .map_err(|e| format!("update envs: {e}"))?;
            }
            client
                .start_app(&uuid)
                .map_err(|e| format!("start app: {e}"))?;
            write_uuid_file(&name, &uuid);
            let _ = writeln!(out, "✓ Deployed {name} (uuid={uuid})");
        }
        Leaf::DeployAppGit {
            project_uuid,
            server_uuid,
            github_app_uuid,
            name,
            git_repo,
            git_branch,
            dockerfile,
            base_dir,
            ports,
            watch_paths,
            build_pack,
            instant_deploy,
            build_args,
            ..
        } => {
            // Build args must be set before Coolify starts the build, so a
            // create with build args never deploys; the deploy is triggered
            // after them.
            let uuid = client
                .create_private_github_app_app(&GitHubApp {
                    project_uuid: &project_uuid,
                    server_uuid: &server_uuid,
                    github_app_uuid: &github_app_uuid,
                    git_repository: &git_repo,
                    git_branch: &git_branch,
                    build_pack: &build_pack,
                    name: &name,
                    base_directory: &base_dir,
                    dockerfile_location: &dockerfile,
                    ports: &ports,
                    watch_paths: &watch_paths.join("\n"),
                    instant_deploy: instant_deploy && build_args.is_empty(),
                })
                .map_err(|e| format!("create app: {e}"))?;
            write_uuid_file(&name, &uuid);
            let _ = writeln!(
                out,
                "✓ Created Coolify Application '{name}' (uuid={uuid}, source=github:{git_repo}@{git_branch})"
            );
            if !build_args.is_empty() {
                client
                    .set_build_args(&uuid, &build_args)
                    .map_err(|e| format!("set build args: {e}"))?;
                let _ = writeln!(out, "✓ Set {} build arg(s) on '{name}'", build_args.len());
                if instant_deploy {
                    client
                        .trigger_deploy(&uuid)
                        .map_err(|e| format!("trigger deploy: {e}"))?;
                    let _ = writeln!(out, "✓ Triggered deploy for '{name}'");
                }
            }
        }
        Leaf::ImportApp {
            server_uuid,
            output_dir,
        } => {
            let apps = client.list_applications()?;
            mkdir_all(&output_dir);
            let imports_path = go_join(&output_dir, "imports.sh");
            let hcl_path = go_join(&output_dir, "apps.tf");
            let mut imports_file = create(&imports_path)?;
            let mut hcl_file = create(&hcl_path)?;
            let (imports, hcl, count) = import_files(&apps, &server_uuid);
            // Go writes line by line and ignores every write error.
            let _ = imports_file.write_all(imports.as_bytes());
            let _ = hcl_file.write_all(hcl.as_bytes());
            let _ = writeln!(
                out,
                "✓ Wrote {count} imports to {imports_path} + HCL stubs to {hcl_path}"
            );
        }
    }
    Ok(())
}
