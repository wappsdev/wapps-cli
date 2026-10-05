#!/usr/bin/env python3
"""File-to-slice table for docs/broker-daemon-port.md.

usage: slices.py <plugin repo> [--table] [--edges]   (reads the plugin; changes nothing)

1. every bucket-(b) line of the plugin is assigned to exactly one slice (partition check)
2. per-slice sums are computed, not typed
3. every dependency between ported code is checked at SYMBOL level, from every importer, whole
   files AND line ranges: an import used on a line, a `this.method(` call, and a `this.store.x(`
   call into a ported storage range. A use in one slice of a symbol a LATER slice owns is a
   violation unless it is declared below as a wiring edge or as a stub (with the seam cases the
   stub excludes). A use of code that is never ported must name what replaces it.
4. the scrub lands no later than the first slice that sends free text off the machine
5. --owner: the size of each owner command in scripts/work.ts (OD9, the explorer driver)

Exit status 1 on any violation.
"""
import re, sys, pathlib, collections

repo = pathlib.Path(sys.argv[1])
def text(rel): return (repo / rel).read_text()
def lines(rel): return len((repo / rel).read_bytes().splitlines())

ORDER = ["13.1", "13.2", "13.3", "13.4", "13.5", "13.6", "13.7", "13.8", "13.9", "13.10"]
PORTED = set(ORDER)

# whole files -> slice
FILES = {
    "src/mcp/server.ts": "13.1", "src/mcp/tool_names.ts": "13.1", "src/security/redaction.ts": "13.1",
    "src/bootstrap.ts": "13.1", "src/roles/types.ts": "13.1",
    "src/daemon/server.ts": "13.2", "src/daemon/client.ts": "13.2", "src/daemon/protocol.ts": "13.2",
    "src/daemon.ts": "13.2", "src/main.ts": "13.2", "src/process/liveness.ts": "13.2",
    "src/process/codex_mcp.ts": "13.3", "src/process/fake_provider.ts": "13.3", "src/process/provider_types.ts": "13.3",
    "src/process/cancel.ts": "13.3", "src/process/scratch.ts": "13.3", "src/security/argv.ts": "13.3",
    "src/security/path_containment.ts": "13.3", "src/security/transcript_scrub.ts": "13.3",
    "src/roles/skills.ts": "13.3", "src/roles/rulebook.ts": "13.3", "src/roles/registry.ts": "13.3",
    "src/roles/provider_tools.ts": "13.3", "src/roles/resolve_role.ts": "13.3", "src/policy/owner_pause.ts": "13.3",
    "src/policy/shell.ts": "13.3", "src/policy/capability.ts": "13.3", "src/bootstrap_runtime.ts": "13.3",
    # readQuota decides whether a codex token_count event is a progress note (runtime.ts:459)
    "src/process/quota.ts": "13.3",
    # the daemon must name workerProvider, and review independence is decided only here (the cloud
    # does not check it); only the owner's routing DIRECTIVE (storage/routing.ts) stays open
    "src/roles/route.ts": "13.3",
    "src/process/claude_agent_sdk.ts": "13.5", "src/policy/claude_hook_root.ts": "13.5",
    "src/process/native_attach.ts": "13.6", "src/roles/resolve_adapter.ts": "13.6",
    "src/policy/claude_hook.ts": "13.7",
    # OD8 (decided 2026-10-05): the explorer is ported as `wapps broker explore`
    "src/view/explorer.ts": "13.10", "src/view/markdown.ts": "13.10", "src/view/width.ts": "13.10",
    "src/view/transcript.ts": "13.10",
}
# line ranges (1-based, inclusive). A label that is not a slice is code that is not ported.
RANGES = {
    "src/process/worktree.ts": [(1, 36, "13.3"), (37, 77, "13.4")],
    "src/process/runtime.ts": [
        (1, 131, "13.3"),      # types, SubmitRequest, RuntimeOptions
        (132, 160, "13.1"),    # agent_await constants, attentionBlock
        (161, 370, "13.3"),    # class head, constructor, submit
        (371, 389, "13.3"),    # #route
        (390, 503, "13.3"),    # #runRemote
        (504, 554, "13.6"),    # resumeAbandoned
        (555, 638, "13.3"),    # #release, #worktreeRoot, #terminalize, #pausedClassStarting, roles, #skillRoots
        (639, 651, "13.9"),    # #record: the local transcript (OD8)
        (652, 679, "13.3"),    # #session, #quota (daemon memory, OD8), #note
        (680, 734, "13.6"),    # attachSubagent, reportSubagent
        (735, 761, "13.1"),    # awaitChange
        (762, 803, "13.3"),    # waitForJob, activeWorkerCount, cancel
        (804, 807, "13.1"),    # leaseFrom
        (808, 1071, "a"),      # RuntimeControlBackend: replaced by the forwarding of section 3.7
    ],
    # OD8 moves two pieces of the store out of bucket (c): the transcript stays LOCAL, quota stays
    # in daemon memory. The rest of the file is the cloud's.
    "src/storage/jobs.ts": [
        (1, 786, "c"),
        (787, 882, "13.9"),    # recordTranscript, recordObservedModel, TranscriptEntry, jobTranscript, latestJobTranscript
        (883, 906, "13.3"),    # QUOTA_KEPT_PER_PROVIDER, StoredQuota, recordQuota (written by #quota)
        (907, 933, "13.6"),    # latestQuota (read by the attention merge)
        (934, 1026, "c"),
    ],
    "src/storage/attention.ts": [
        (1, 223, "c"),
        (224, 246, "13.6"),    # the quota list: warning threshold, reset filter, relative times
        (247, 321, "c"),
        (322, 328, "13.6"),    # the digest's quota status, so a status change wakes agent_await
        (329, 332, "c"),
    ],
}
NOT_PORTED = ("src/storage/", "src/lifecycle/", "src/mcp/schemas.ts", "src/roles/propose.ts",
              "src/process/recovery.ts", "src/security/launcher_handshake.ts", "src/cli/commands.ts")

# ---- declared exceptions ------------------------------------------------------------------------
# Wiring: a constructor-injection file names every adapter, so it points forward by construction.
WIRING = {
    ("src/main.ts", "src/bootstrap_runtime.ts"): "main builds the runtime it connects to (13.2 hosts the 13.1 backend; 13.3 fills it)",
    ("src/daemon.ts", "src/bootstrap_runtime.ts"): "the daemon hosts whatever backend exists in its slice",
    ("src/bootstrap_runtime.ts", "src/process/claude_agent_sdk.ts"): "registers the claude adapter; one line added in 13.5",
}
# Stubs: (importer, symbol) -> what the earlier slice does instead, and the seam cases it excludes.
STUBS = {
    ("src/process/runtime.ts", "resolveAdapter"):
        "13.3 answers broker_managed and refuses handBack. Excludes: seam-2 agent_submit with handBack:true. "
        "Without handBack a fresh oracle store has no native evidence, so it answers broker_managed too",
    ("src/process/runtime.ts", "createWorktree"):
        "13.3 refuses a role that holds write before reserving. Excludes: every dispatch of a writing role "
        "(seams 1-3), the `working in`/`carrying on in` notes, a resume into an inherited tree",
    ("src/process/runtime.ts", "removeWorktreeIfClean"):
        "unreachable in 13.3: no job has a worktree. Excludes: the `left <branch> checked out` note",
    ("src/process/runtime.ts", "#record"):
        "a no-op until 13.9. Excludes: transcript rows, which no seam compares before 13.9",
    ("src/process/runtime.ts", "recordObservedModel"):
        "a no-op until 13.9 (the cloud has no column for it). Excludes: seam 1's `model observed` reaction until 13.9",
}
# Code that is never ported, and what replaces it where ported code used it.
REPLACED = {
    "src/mcp/schemas.ts": "the Worker's tools/list and its bodies (OD3); the daemon publishes its own schema for 3 tools",
    "src/storage/attention.ts": "the cloud's GET .../attention (missionAttention), merged with 13.6's quota list",
    "src/storage/db.ts": "the cloud broker's routes (BrokerStore, LeaseAuthority, MissionAttention, isQuiet)",
    "src/storage/jobs.ts": "the cloud: the attach answer's `task` carries reviewVerdictInstruction and the delegated brief "
                           "(methods.rs brief_task); MissionJob becomes the cloud's JobView + 13.9's local job header",
    "src/storage/work.ts": "the cloud's WorkItemView, OpenQuestion and horizon (payload.rs)",
    "src/security/launcher_handshake.ts": "(d): the Access principal, and the orchestrator provider declared by the install (OD1)",
    "src/roles/propose.ts": "the Worker's roles_propose (P12)",
    # a ranged file is keyed by the label of the range the used symbol is defined in
    ("src/process/runtime.ts", "a"): "section 3.7's forwarding (RuntimeControlBackend)",
}

# ---- partition -----------------------------------------------------------------------------------
rows = collections.OrderedDict()
tot = collections.Counter()
for rel, s in FILES.items():
    n = lines(rel); rows[(rel, f"1-{n}")] = (n, s); tot[s] += n
for rel, parts in RANGES.items():
    last = 0
    for a, b, s in parts:
        assert a == last + 1, ("gap or overlap", rel, a, last)
        last = b
        rows[(rel, f"{a}-{b}")] = (b - a + 1, s); tot[s] += b - a + 1
    assert last == lines(rel), ("range does not end at the file's end", rel, last, lines(rel))

if "--table" in sys.argv:
    for (rel, rng), (n, s) in sorted(rows.items(), key=lambda kv: (kv[1][1], kv[0])):
        print(f"{s}|{rel}|{rng}|{n}")
    print()
b_total = sum(v for k, v in tot.items() if k in PORTED)
for s in ORDER: print(f"{s}: {tot[s]}")
print("in ranged files, not ported: a:", tot["a"], " c:", tot["c"], "   sum of 13.x:", b_total)

# ---- coverage ------------------------------------------------------------------------------------
allsrc = sorted(str(p.relative_to(repo)) for p in (repo / "src").rglob("*.ts"))
unassigned = [f for f in allsrc if f not in FILES and f not in RANGES and not f.startswith(NOT_PORTED)]
touched = [f for f in allsrc if f in FILES or f in RANGES]
whole_np = [f for f in allsrc if f not in FILES and f not in RANGES]
print(f"\nsrc files: {len(allsrc)}; with ported lines: {len(touched)} ({len(FILES)} whole + {len(RANGES)} by range); "
      f"wholly not ported: {len(whole_np)}; unaccounted: {len(unassigned)}")
print("src lines, all:", sum(lines(f) for f in allsrc), "  wholly-not-ported lines:", sum(lines(f) for f in whole_np))
assert not unassigned, unassigned

# ---- symbol-level dependency check ---------------------------------------------------------------
def slice_at(rel, line):
    if rel in FILES: return FILES[rel]
    for a, b, s in RANGES.get(rel, []):
        if a <= line <= b: return s
    return "c" if rel.startswith(NOT_PORTED) else None

def resolve(rel, spec):
    parts = list(pathlib.PurePosixPath(rel).parent.parts)
    for p in spec.split("/"):
        if p == "..": parts.pop()
        elif p != ".": parts.append(p)
    return "/".join(parts) + ".ts"

def code_lines(rel):
    """(line number, text with comments removed) for every line that is code."""
    out, in_block = [], False
    for n, raw in enumerate(text(rel).splitlines(), 1):
        s = raw
        if in_block:
            if "*/" in s: s, in_block = s.split("*/", 1)[1], False
            else: continue
        if "/*" in s:
            head, rest = s.split("/*", 1)
            if "*/" in rest: s = head + rest.split("*/", 1)[1]
            else: s, in_block = head, True
        s = s.split("//", 1)[0] if not re.search(r'"[^"]*//', s) else s
        out.append((n, s))
    return out

IMPORT = re.compile(r'import\s+(type\s+)?\{([^}]*)\}\s*from\s*"(\.[^"]+)"', re.S)
def imports(rel):
    """[(local name, imported name, target file, import line span)]"""
    t = text(rel); out = []
    for m in IMPORT.finditer(t):
        first = t.count("\n", 0, m.start()) + 1; last = t.count("\n", 0, m.end()) + 1
        for part in m.group(2).split(","):
            part = re.sub(r"^\s*type\s+", "", part.strip())
            if not part: continue
            name, _, local = part.partition(" as ")
            out.append(((local or name).strip(), name.strip(), resolve(rel, m.group(3)), (first, last)))
    return out

def definition_line(rel, name):
    pat = re.compile(rf'^\s*(export\s+)?(async\s+)?(function\*?|interface|type|class|const|let|enum)\s+{re.escape(name)}\b', re.M)
    m = pat.search(text(rel))
    return None if m is None else text(rel).count("\n", 0, m.start()) + 1

def methods(rel):
    """method name -> definition line, for the class bodies of a file (two-space indent)."""
    out = {}
    for n, s in code_lines(rel):
        m = re.match(r"^  (?:async\s+|get\s+|static\s+)*(#?[A-Za-z_]\w*)\s*[(<]", s)
        if m and m.group(1) not in ("constructor", "if", "for", "while", "switch", "return"):
            out.setdefault(m.group(1), n)
    return out

STORAGE_FNS = {}
for rel, parts in RANGES.items():
    if rel.startswith("src/storage/"):
        for m in re.finditer(r"^export function (\w+)", text(rel), re.M):
            STORAGE_FNS[m.group(1)] = (rel, text(rel).count("\n", 0, m.start()) + 1)

edges = []   # (use slice, importer, use line, symbol, def slice, target)
for rel in list(FILES) + list(RANGES):
    body = code_lines(rel)
    for local, name, target, (i0, i1) in imports(rel):
        if not (repo / target).exists(): continue
        d = definition_line(target, name)
        if target in RANGES or target in FILES:
            assert d is not None or target in FILES, ("definition not found", target, name)
        tslice = slice_at(target, d or 1)
        used = [n for n, s in body if not (i0 <= n <= i1) and re.search(rf"(?<![\w$#.]){re.escape(local)}\b", s)]
        for n in used or [i0]:
            us = slice_at(rel, n)
            if us in PORTED: edges.append((us, rel, n, name, tslice, target))
    if rel in RANGES:
        defs = methods(rel)
        for n, s in body:
            for m in re.finditer(r"this\.(#?\w+)\s*\(", s):
                if m.group(1) in defs:
                    us = slice_at(rel, n)
                    if us in PORTED: edges.append((us, rel, n, m.group(1), slice_at(rel, defs[m.group(1)]), rel))
    for n, s in body:
        for m in re.finditer(r"this\.store\.(\w+)\s*\(", s):
            if m.group(1) in STORAGE_FNS:
                trel, tline = STORAGE_FNS[m.group(1)]
                us = slice_at(rel, n)
                if us in PORTED: edges.append((us, rel, n, m.group(1), slice_at(trel, tline), trel))

edges = sorted(set(edges), key=lambda e: (e[1], e[2], e[3]))
later = [e for e in edges if e[4] in PORTED and ORDER.index(e[4]) > ORDER.index(e[0])]
wired = [e for e in later if (e[1], e[5]) in WIRING]
stubbed = [e for e in later if (e[1], e[3]) in STUBS and e not in wired]
bad = [e for e in later if e not in wired and e not in stubbed]
unported = [e for e in edges if e[4] not in PORTED]
def reason(e): return REPLACED.get((e[5], e[4])) if e[5] in RANGES and e[5] not in REPLACED else REPLACED.get(e[5])
unexplained = [e for e in unported if reason(e) is None]

print(f"\nsymbol uses between ported code: {len(edges)} "
      f"(from {len({(e[1]) for e in edges})} files; ranged importers included)")
print("uses that point at a LATER slice, undeclared:", len(bad))
for e in bad: print(f"  {e[0]} {e[1]}:{e[2]} uses {e[3]} -> {e[4]} {e[5]}")
print("declared wiring edges:", len({(e[1], e[5]) for e in wired}))
for k in sorted({(e[1], e[5]) for e in wired}): print(f"  {k[0]} -> {k[1]}: {WIRING[k]}")
print("declared stubs:", len({(e[1], e[3]) for e in stubbed}))
for k in sorted({(e[1], e[3]) for e in stubbed}):
    at = [e for e in stubbed if (e[1], e[3]) == k]
    print(f"  {at[0][0]} {k[0]}:{','.join(str(e[2]) for e in at)} uses {k[1]} ({at[0][4]}): {STUBS[k]}")
print("uses of code that is never ported:", len(unported), " without a named replacement:", len(unexplained))
for (t, why), n in sorted(collections.Counter((e[5], reason(e) or "UNEXPLAINED") for e in unported).items()):
    print(f"  {n:3} into {t}: {why}")
for e in unexplained: print(f"  UNEXPLAINED {e[0]} {e[1]}:{e[2]} uses {e[3]} in {e[5]}")
unused = [k for k in STUBS if k not in {(e[1], e[3]) for e in stubbed}]
print("declared stubs that matched nothing:", len(unused), unused)

# ---- scrub ordering ------------------------------------------------------------------------------
# Free text leaves the machine through #note (progress.note), #terminalize (finish.output/error) and
# reportSubagent (finish.output/error, native lane). The transcript (#record) stays local, scrubbed.
SENDERS = {"#note": 672, "#terminalize": 575, "reportSubagent": 708}
R = "src/process/runtime.ts"
first_slice = min((slice_at(R, l) for l in SENDERS.values()), key=ORDER.index)
scrub_slice = FILES["src/security/transcript_scrub.ts"]
print("\nfree-text senders: " + ", ".join(f"{k} -> {slice_at(R, v)}" for k, v in SENDERS.items()))
print(f"scrub is in {scrub_slice}; first sender is in {first_slice}; the local transcript (#record) is in {slice_at(R, 645)}")
ok_scrub = ORDER.index(scrub_slice) <= ORDER.index(first_slice)

# ---- owner commands (scripts/work.ts) ------------------------------------------------------------
if "--owner" in sys.argv:
    w = text("scripts/work.ts").splitlines()
    starts = [(n, m.group(1)) for n, l in enumerate(w, 1) for m in [re.match(r'^  (?:\} else )?if \(command === "([\w-]+)"\)', l)] if m]
    end = next(n for n, l in enumerate(w, 1) if n > starts[-1][0] and l.startswith("  } else {"))
    print(f"\nscripts/work.ts: {len(w)} lines; prelude 1-{starts[0][0] - 1} ({starts[0][0] - 1}); fallthrough {end}-{len(w)} ({len(w) - end + 1})")
    for (n, name), (m, _) in zip(starts, starts[1:] + [(end, None)]):
        print(f"  {name:10} {n}-{m - 1} ({m - n})")

sys.exit(1 if (bad or unexplained or unused or not ok_scrub) else 0)
