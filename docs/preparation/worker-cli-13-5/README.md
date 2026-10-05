# Worker CLI preparation

Read `research.txt` for the original English synthesis, historical version-pinned
measurements, documentation references and unverified OD5 experiment plan. **Help,
version and source inspection did not prove real main-thread skills/effort, hook
authorization or cancellation.** Command-hook failure-open limits remain explicit.
Correct hook field: `effort.level`; future actual provider `output_config.effort`
remains stronger evidence. No main-thread/model-backed experiment is authorized here.

## Safe reproducible probe

`probe.py` is a rewritten help/version-only utility, not a copy of native source
inspection. It requires an explicit absolute binary path and a new output filename
in an existing private UID-owned directory. It never searches installed configuration,
reads stores, extracts credentials, inherits credential/config environment variables,
starts a conversation, runs hooks or signals processes. It constructs seven fixed
cases ending in `--help` or `--version`, supplies disposable HOME/config/tmp/project
directories and bounds each subprocess to 20 seconds.

It records binary SHA-256, case argv without the binary path, individual child exits,
recognized version/flag presence and boolean diagnostics. No raw stdout/stderr, native
excerpts or private machine paths are stored. Missing executable/unsafe output or
I/O error returns `2`; timeout is recorded with `exit_code: null`. Its exit `0` means
**recorded**, not all CLI cases passed. Inspect individual exits; none verifies runtime.
A failed write may leave a partial private evidence file: retain it, use a new filename,
and never rerun the original preserved evidence-overwriting probe.

Run only on an explicitly chosen, trusted CLI binary or a synthetic executable:

```sh
base=/absolute/path/to/your/wapps-cli-worktree
private=$(mktemp -d)
chmod 700 "$private"
python3 -B "$base/docs/preparation/worker-cli-13-5/probe.py" \
  --binary /absolute/path/to/the/chosen/claude \
  --output "$private/probe.json"
result=$?
printf 'OFFLINE_PROBE_EXIT=%s\n' "$result"
```

Do not replace the binary argument with a shell fragment. No `-p`/prompt, credential,
URL, arbitrary CLI argument or live mode exists. Help is deliberately a short-circuit
negative control: undocumented flags and malformed role definitions may appear to
pass while runtime startup would refuse them. Environment isolation is not an OS-level
network/filesystem sandbox; trust the selected binary and keep output private.

`test_probe.py` has six tests using newly created **synthetic** executables only:
all seven cases/direct statuses; exclusive output; private permissions; explicit child
environment; rejection of non-help arguments; and exclusion of raw output/paths.
Use `../verify.py` from a staged/clean indexed checkout to run them under a private
synthetic home together with the original 98 replay tests. No installed CLI binary
was invoked by this curation's verification. The historical 14 successful help/version
exits are a separate earlier measurement, not results of these six tests.
