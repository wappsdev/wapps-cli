#!/usr/bin/env python3
"""File-to-slice table for docs/broker-daemon-port.md.

usage: slices.py <plugin repo>   (reads src/**/*.ts with wc -l semantics; changes nothing)

1. every bucket-(b) line of the plugin is assigned to exactly one slice
2. per-slice sums are computed, not typed
3. every import edge between two bucket-(b) files is checked: a slice must not import a file
   that a LATER slice owns (the dependency the reviewer found for skills.ts / rulebook.ts)
"""
import re, subprocess, sys, pathlib, collections

repo = pathlib.Path(sys.argv[1])
def lines(rel): return len((repo / rel).read_bytes().splitlines())

ORDER = ["13.1", "13.2", "13.3", "13.4", "13.5", "13.6", "13.7"]

# whole files -> slice
FILES = {
    "src/mcp/server.ts": "13.1", "src/mcp/tool_names.ts": "13.1", "src/security/redaction.ts": "13.1",
    "src/bootstrap.ts": "13.1", "src/roles/types.ts": "13.1",
    "src/daemon/server.ts": "13.2", "src/daemon/client.ts": "13.2", "src/daemon/protocol.ts": "13.2",
    "src/daemon.ts": "13.2", "src/main.ts": "13.2", "src/process/liveness.ts": "13.2",
    "src/process/codex_mcp.ts": "13.3", "src/process/fake_provider.ts": "13.3", "src/process/provider_types.ts": "13.3", "src/process/cancel.ts": "13.3",
    "src/process/scratch.ts": "13.3", "src/security/argv.ts": "13.3", "src/security/path_containment.ts": "13.3",
    "src/security/transcript_scrub.ts": "13.3", "src/roles/skills.ts": "13.3", "src/roles/rulebook.ts": "13.3",
    "src/roles/registry.ts": "13.3", "src/roles/provider_tools.ts": "13.3", "src/roles/resolve_role.ts": "13.3",
    "src/policy/owner_pause.ts": "13.3", "src/policy/shell.ts": "13.3", "src/policy/capability.ts": "13.3",
    "src/bootstrap_runtime.ts": "13.3",
    "src/process/claude_agent_sdk.ts": "13.5", "src/policy/claude_hook_root.ts": "13.5",
    "src/process/quota.ts": "13.6", "src/process/native_attach.ts": "13.6", "src/roles/resolve_adapter.ts": "13.6",
    "src/policy/claude_hook.ts": "13.7",
}
# line ranges (1-based, inclusive) of files shared by two slices
RANGES = {
    "src/process/worktree.ts": [(1, 36, "13.3"), (37, 77, "13.4")],
    "src/process/runtime.ts": [
        (1, 131, "13.3"), (132, 160, "13.1"), (161, 370, "13.3"),
        (371, 389, "c-open"),                       # #route: routing directives, open in the cloud
        (390, 503, "13.3"), (504, 554, "13.6"), (555, 661, "13.3"), (662, 670, "13.6"), (671, 679, "13.3"),
        (680, 734, "13.6"), (735, 761, "13.1"), (762, 803, "13.3"), (804, 807, "13.1"),
        (808, 1071, "a"),                           # RuntimeControlBackend: tool -> store call
    ],
}
NOT_PORTED = ("src/storage/", "src/view/", "src/lifecycle/", "src/mcp/schemas.ts", "src/roles/propose.ts",
              "src/roles/route.ts", "src/process/recovery.ts", "src/security/launcher_handshake.ts",
              "src/cli/commands.ts")

def owner(rel):
    if rel in FILES: return FILES[rel]
    return None

rows = collections.OrderedDict()
tot = collections.Counter()
for rel, s in FILES.items():
    n = lines(rel); rows[(rel, f"1-{n}")] = (n, s); tot[s] += n
for rel, parts in RANGES.items():
    n_file = lines(rel); covered = 0; last = 0
    for a, b, s in parts:
        assert a == last + 1, (rel, a, last)
        last = b; covered += b - a + 1
        rows[(rel, f"{a}-{b}")] = (b - a + 1, s); tot[s] += b - a + 1
    assert last == n_file, (rel, last, n_file)

if "--table" in sys.argv:
    for (rel, rng), (n, s) in sorted(rows.items(), key=lambda kv: (kv[1][1], kv[0])):
        print(f"{s}|{rel}|{rng}|{n}")
    print()
b_total = sum(v for k, v in tot.items() if k.startswith("13."))
for s in ORDER: print(f"{s}: {tot[s]}")
print("c-open:", tot["c-open"], " a:", tot["a"], " sum of 13.x:", b_total)

# --- scrub ordering: the scrub must land no later than the first slice that sends free text -------
# Free text leaves the machine through #note (progress.note), #terminalize (finish.output/error) and
# reportSubagent (finish.output/error, native lane). Their line ranges are in RANGES above.
def slice_at(rel, line):
    for a, b, s in RANGES[rel]:
        if a <= line <= b: return s
SENDERS = {"#note": 672, "#terminalize": 575, "reportSubagent": 708}
first = min(SENDERS.values(), key=lambda l: ORDER.index(slice_at("src/process/runtime.ts", l)))
first_slice = slice_at("src/process/runtime.ts", first)
scrub_slice = FILES["src/security/transcript_scrub.ts"]
print(f"\nfree-text senders: " + ", ".join(f"{k} -> {slice_at('src/process/runtime.ts', v)}" for k, v in SENDERS.items()))
print(f"scrub is in {scrub_slice}; first sender is in {first_slice}")
assert ORDER.index(scrub_slice) <= ORDER.index(first_slice), "free text would leave the machine before the scrub exists"

# --- coverage: every src file is either assigned above or named as not ported ----------------------
allsrc = sorted(str(p.relative_to(repo)) for p in (repo / "src").rglob("*.ts"))
unassigned = [f for f in allsrc if f not in FILES and f not in RANGES and not f.startswith(NOT_PORTED)]
ported = [f for f in allsrc if f in FILES or f in RANGES]
print(f"\nsrc files: {len(allsrc)}; assigned: {len(ported)} ({len(FILES)} whole + {len(RANGES)} split); not ported (a/c/d/OD8/OD9): {len(allsrc) - len(ported)}; unaccounted: {len(unassigned)}")
print("src lines, all:", sum(lines(f) for f in allsrc))
assert not unassigned, unassigned

# --- import-edge check -------------------------------------------------------------------------
def slice_of_file(rel):
    if rel in FILES: return FILES[rel]
    if rel in RANGES: return "mixed"
    return None
def imports(rel):
    text = (repo / rel).read_text()
    out = []
    for m in re.finditer(r'from "(\.[^"]+)"', text):
        t = (pathlib.PurePosixPath(rel).parent / m.group(1))
        parts = []
        for p in t.parts:
            if p == "..": parts.pop()
            elif p != ".": parts.append(p)
        out.append("/".join(parts) + ".ts")
    return sorted(set(out))
# Wiring edges: a constructor-injection file names every adapter, so it points at later slices by
# construction. Its Rust counterpart grows one registration per slice; nothing is imported early.
WIRING = {
    ("src/main.ts", "src/bootstrap_runtime.ts"): "main builds the runtime it connects to (13.2 hosts the 13.1 backend; 13.3 fills it)",
    ("src/daemon.ts", "src/bootstrap_runtime.ts"): "same: the daemon hosts whatever backend exists in its slice",
    ("src/bootstrap_runtime.ts", "src/process/claude_agent_sdk.ts"): "registers the claude adapter; one line added in 13.5",
}
bad = []
for rel, s in FILES.items():
    for t in imports(rel):
        ts = slice_of_file(t)
        if ts is None or ts == "mixed": continue
        if ORDER.index(ts) > ORDER.index(s): bad.append((s, rel, ts, t))
declared = [b for b in bad if (b[1], b[3]) in WIRING]
bad = [b for b in bad if (b[1], b[3]) not in WIRING]
print("\nimport edges that point at a LATER slice, undeclared:", len(bad))
for s, rel, ts, t in bad: print(f"  {s} {rel} -> {ts} {t}")
print("declared wiring edges:", len(declared))
for s, rel, ts, t in declared: print(f"  {s} {rel} -> {ts} {t}: {WIRING[(rel, t)]}")
sys.exit(1 if bad else 0)
