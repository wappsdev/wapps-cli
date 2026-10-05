#!/usr/bin/env python3
"""Read-only census for OD1, OD8 and OD10 of docs/broker-daemon-port.md.

usage: od10.py   (reads ~/.agent-broker/state/*/broker.sqlite through SQLite's read-only URI)

Prints counts and lengths only. No title, intent, question or transcript text is printed.

OD1  : handoff_packages rows in every store (has the orchestrator handoff ever been used?)
OD8  : job_transcript rows, payload bytes, and the bytes SQLite holds for the table
OD10 : for the four projects whose open items migrate, what a work_add replay meets in the
       cloud's add_locked (crates/workers/src/mission_lane/methods.rs): parent depth (a part
       cannot name a parent filed in the same batch), closed parents (parent_closed), parts
       carrying a horizon (child_horizon), the body ceilings (title 500, intent 100,000,
       trimmed non-empty), and the open questions (work_ask: question and proposal <= 4,000)
"""
import pathlib, sqlite3

STATE = pathlib.Path.home() / ".agent-broker" / "state"
MIGRATE = ["navlun", "ecommerce", "kick-clip-analyzer", "real-estate-analysis"]


def ro(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def has_table(db, name):
    return db.execute("select 1 from sqlite_master where type='table' and name=?", (name,)).fetchone() is not None


print("== OD1 + OD8: every store")
print("project|handoff_packages|transcript_rows|transcript_payload_MB|transcript_table_MB|db_MB")
tot_handoff = 0
for d in sorted(p for p in STATE.iterdir() if p.is_dir()):
    f = d / "broker.sqlite"
    if not f.exists():
        continue
    db = ro(f)
    handoffs = db.execute("select count(*) from handoff_packages").fetchone()[0]
    tot_handoff += handoffs
    rows, payload = db.execute("select count(*), coalesce(sum(length(cast(payload_json as blob))),0) from job_transcript").fetchone()
    try:
        table = db.execute("select coalesce(sum(pgsize),0) from dbstat where name in ('job_transcript','job_transcript_job')").fetchone()[0]
        table_mb = f"{table / 1e6:.1f}"
    except sqlite3.OperationalError:
        table_mb = "n/a (no dbstat)"
    page = db.execute("pragma page_size").fetchone()[0] * db.execute("pragma page_count").fetchone()[0]
    print(f"{d.name}|{handoffs}|{rows}|{payload / 1e6:.1f}|{table_mb}|{page / 1e6:.1f}")
    db.close()
print("handoff_packages, all stores:", tot_handoff)

print("\n== OD10: the four projects that migrate")
for name in MIGRATE:
    db = ro(STATE / name / "broker.sqlite")
    missions = [r[0] for r in db.execute("select id from missions")]
    items = {r[0]: r for r in db.execute(
        "select id, parent_id, horizon, title, intent, closed_at, discovered_from, source_job_id, position "
        "from work_items")}
    open_ids = [i for i, r in items.items() if r[5] is None]

    def depth(i):
        p = items[i][1]
        if p is None or p not in items or items[p][5] is not None:
            return 0
        return 1 + depth(p)

    levels = {}
    for i in open_ids:
        levels.setdefault(depth(i), 0)
        levels[depth(i)] += 1
    closed_parent = sum(1 for i in open_ids if items[i][1] and items[i][1] in items and items[items[i][1]][5] is not None)
    part_horizon = sum(1 for i in open_ids if items[i][1] and items[i][2] is not None)
    titles = [len(items[i][3]) for i in open_ids]
    intents = [len(items[i][4]) for i in open_ids]
    blank = sum(1 for i in open_ids if not items[i][3].strip() or not items[i][4].strip())
    padded = sum(1 for i in open_ids if items[i][3] != items[i][3].strip() or items[i][4] != items[i][4].strip())
    discovered = sum(1 for i in open_ids if items[i][6])
    discovered_open = sum(1 for i in open_ids if items[i][6] in items and items[items[i][6]][5] is None)
    same = sum(1 for i in open_ids if items[i][3] == items[i][4])
    long_ids = [i for i in open_ids if len(items[i][3]) > 500]
    long_same = sum(1 for i in long_ids if items[i][3] == items[i][4])
    long_astral = sum(1 for i in long_ids if any(ord(c) > 0xFFFF for c in items[i][3]))
    created = {r[0]: r[1] for r in db.execute("select id, date(created_at / 1000, 'unixepoch') from work_items")}
    long_dates = sorted(created[i] for i in long_ids)
    adopted = sum(1 for i in open_ids if items[i][7])
    print(f"{name}: missions={missions} open={len(open_ids)} by_depth={dict(sorted(levels.items()))} "
          f"open_with_closed_parent={closed_parent} parts_with_horizon={part_horizon} "
          f"title_max={max(titles, default=0)} (>500: {sum(t > 500 for t in titles)}) "
          f"intent_max={max(intents, default=0)} (>100000: {sum(t > 100000 for t in intents)}) "
          f"blank={blank} padded={padded} discovered_from_set={discovered} (to an open item: {discovered_open}) "
          f"adopted_from_job={adopted} title_equals_intent={same}")
    if long_ids:
        print(f"  titles over 500: {len(long_ids)}, title = intent: {long_same}, outside the BMP: {long_astral}, "
              f"created {long_dates[0]} .. {long_dates[-1]}")
    for q in db.execute(
        "select q.work_item_id, length(q.question), length(coalesce(q.proposal,'')), q.relayed_at is not null, "
        "q.delegate_provider, q.answer_job_id is not null, w.closed_at is null "
        "from work_questions q join work_items w on w.id = q.work_item_id "
        "where q.answered_at is null and q.withdrawn_at is null"):
        print(f"  open question: question_len={q[1]} proposal_len={q[2]} relayed={bool(q[3])} "
              f"delegated_to={q[4]} answer_job={bool(q[5])} item_open={bool(q[6])}")
    db.close()
