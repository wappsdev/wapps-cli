#!/usr/bin/env python3
"""Offline, one-shot OD10 replay preparation. No network or daemon integration."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

PROJECTS = {"navlun", "ecommerce", "kick-clip-analyzer", "real-estate-analysis"}
MISSION_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z", re.ASCII)
HORIZONS = {"now", "next", "later", "someday"}
# Application schema: body.rs NEW_ITEM/ITEMS/ASK. Byte budget is deliberately
# conservative preparation policy, NOT a claim about the deployed transport.
MAX_ITEMS = 500
BODY_BUDGET = 1_048_576
AUTHORITY_RESERVE = 4096
JS_SPACE = "\u0009\u000a\u000b\u000c\u000d                  　﻿"
ITEM_FIELDS = set("id mission_id parent_id title intent position created_at closed_at closed_reason source_job_id source_index horizon discovered_from".split())
QUESTION_FIELDS = set("id mission_id work_item_id question raised_at answered_at answer proposal delegate_provider answered_by answer_job_id relayed_at confirmed_at withdrawn_at withdrawn_reason relayed_by".split())


class PlanningError(Exception):
    """Only fixed codes, never source data, may cross the CLI boundary."""


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def units(text):
    return len(text.encode("utf-16-le")) // 2


def prefix(text, limit):
    return text.encode("utf-16-le")[:limit * 2].decode("utf-16-le", errors="ignore")


def open_snapshot(path):
    """Require an offline, self-contained snapshot; never recover or create WAL."""
    path = Path(path).resolve(strict=True)
    if not path.is_file() or any(Path(str(path) + suffix).exists()
                                 for suffix in ("-wal", "-shm", "-journal")):
        raise PlanningError("snapshot_not_standalone")
    # as_uri escapes spaces, ?, # and Unicode. immutable forbids locks/sidecars;
    # mode=ro independently forbids writes even if query_only is disabled.
    con = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA trusted_schema=OFF")
    return con


def validate_config(config):
    if not isinstance(config, dict) or set(config) != {"sources"}:
        raise PlanningError("invalid_config")
    sources = config["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 4:
        raise PlanningError("invalid_sources")
    projects, targets = set(), set()
    required = {"project", "snapshot", "source_mission_id", "target_mission_id",
                "selected_question_ids", "approved_lossy_transformations"}
    for source in sources:
        if not isinstance(source, dict) or set(source) != required:
            raise PlanningError("explicit_mapping_required")
        project = source["project"]
        if not isinstance(project, str) or project not in PROJECTS or project in projects:
            raise PlanningError("invalid_project_scope")
        projects.add(project)
        for field in ("source_mission_id", "target_mission_id"):
            if not isinstance(source[field], str) or not MISSION_ID.fullmatch(source[field]):
                raise PlanningError("invalid_mission_id")
        if source["target_mission_id"] in targets:
            raise PlanningError("duplicate_target_mission")
        targets.add(source["target_mission_id"])
        if not isinstance(source["snapshot"], str) or not Path(source["snapshot"]).is_absolute():
            raise PlanningError("absolute_snapshot_required")
        for field in ("selected_question_ids", "approved_lossy_transformations"):
            values = source[field]
            if (not isinstance(values, list) or
                    any(not isinstance(v, str) or not v for v in values) or
                    len(values) != len(set(values))):
                raise PlanningError("invalid_selection")
        if len(source["selected_question_ids"]) > (1 if project == "navlun" else 0):
            raise PlanningError("question_outside_od10_scope")
    return sorted(sources, key=lambda s: s["project"])


def read_source(source):
    path = Path(source["snapshot"]).resolve(strict=True)
    with path.open("rb") as f:
        before = hashlib.file_digest(f, "sha256").hexdigest()
    con = open_snapshot(path)
    try:
        con.execute("BEGIN")
        expected = {"missions": {"id", "status"}, "work_items": ITEM_FIELDS,
                    "work_questions": QUESTION_FIELDS}
        for table, required in expected.items():
            kind = con.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
            if kind is None or kind[0] != "table":
                raise PlanningError("unsupported_schema")
            columns = {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
            if not required <= columns:
                raise PlanningError("unsupported_schema")
        # Only work tables are read. Jobs, transcripts, leases and credentials
        # are neither queried nor exported. The hash fingerprints opaque bytes.
        missions = [dict(r) for r in con.execute("SELECT id,status FROM missions")]
        items = [dict(r) for r in con.execute("SELECT * FROM work_items")]
        questions = [dict(r) for r in con.execute("SELECT * FROM work_questions")]
    finally:
        con.close()
    with path.open("rb") as f:
        after = hashlib.file_digest(f, "sha256").hexdigest()
    if before != after:
        raise PlanningError("snapshot_changed")
    return before, missions, items, questions


def plan_project(source, issues):
    fingerprint, missions, all_items, all_questions = read_source(source)
    project = source["project"]
    mission = source["source_mission_id"]
    plan = {**source, "snapshot_sha256": fingerprint, "source_items": [],
            "source_questions": [], "unsupported_metadata": [], "transformations": [],
            "batches": [], "questions": []}

    def issue(code, source_id=None, field=None):
        entry = {"project": project, "code": code}
        if source_id is not None:
            entry["source_id"] = source_id
        if field is not None:
            entry["field"] = field
        issues.append(entry)

    def text(value, field, maximum, row_id):
        if not isinstance(value, str):
            issue("invalid_text_type", row_id, field)
            return False
        if not value.strip(JS_SPACE):
            issue("blank_text", row_id, field)
            return False
        if value != value.strip(JS_SPACE):
            issue("padded_text", row_id, field)
            plan["transformations"].append({"kind": "trim-requires-review", "source_id": row_id,
                                            "field": field, "lossy": True, "approved": False})
            return False
        if units(value) > maximum:
            issue(field + "_too_large", row_id, field)
            return False
        return True

    def archive(row, carried, kind):
        omitted = [field for field in sorted(row) if field not in carried and row[field] is not None]
        for field in omitted:
            reason = ("outside_od10_scope_but_cloud_supports_it" if field == "discovered_from"
                      else "not_replayed_by_work_add_or_work_ask")
            plan["unsupported_metadata"].append({"kind": kind, "source_id": row["id"],
                "field": field, "reason": reason, "preserved_in": "source_" + kind})
        if omitted:
            plan["transformations"].append({"kind": "archive-only-metadata", "source_id": row["id"],
                "entity": kind, "fields": omitted, "requires_review": True,
                "proposal": "Preserve original values in this private manifest; do not invent cloud provenance or timestamps."})

    selected_missions = [m for m in missions if m["id"] == mission]
    if len(selected_missions) != 1:
        issue("source_mission_missing_or_duplicate")
    elif selected_missions[0]["status"] != "active":
        issue("unsupported_mission_state")
    for rows, code in ((all_items, "duplicate_item_id"), (all_questions, "duplicate_question_id")):
        ids = [r["id"] for r in rows]
        if any(not isinstance(i, str) or not i for i in ids):
            issue("invalid_source_id")
            return plan
        for id, count in sorted(Counter(ids).items()):
            if count > 1:
                issue(code, id)
    # Do not create a dictionary until duplicate detection has succeeded.
    if any(i["project"] == project and i["code"].startswith("duplicate_") for i in issues):
        plan["source_items"] = [r for r in all_items if r["mission_id"] == mission]
        plan["source_questions"] = [r for r in all_questions if r["mission_id"] == mission]
        return plan
    known = {r["id"]: r for r in all_items}
    scoped = [r for r in all_items if r["mission_id"] == mission]
    opened = {r["id"]: r for r in scoped if r["closed_at"] is None}
    plan["source_items"] = sorted(opened.values(), key=lambda r: r["id"])
    plan["counts"] = {"open_items": len(opened), "closed_items_excluded": len(scoped) - len(opened),
                      "other_mission_items_excluded": len(all_items) - len(scoped)}
    for row in scoped:
        reason = row["closed_reason"]
        if (type(row["created_at"]) is not int or
                (row["closed_at"] is not None and type(row["closed_at"]) is not int) or
                (row["closed_at"] is None) != (reason is None) or
                (reason is not None and reason not in {"delivered", "dropped", "superseded"})):
            issue("unsupported_item_state", row["id"])
    bodies = {}
    used_approvals = set()
    for id, row in sorted(opened.items()):
        archive(row, {"id", "mission_id", "parent_id", "title", "intent", "horizon"}, "items")
        if any(row[k] is not None for k in row.keys() - ITEM_FIELDS):
            issue("unsupported_item_state", id)
        if type(row["position"]) is not int:
            issue("invalid_position", id)
        parent = row["parent_id"]
        if parent is not None:
            if not isinstance(parent, str) or parent not in known:
                issue("missing_parent", id)
            elif known[parent]["mission_id"] != mission:
                issue("cross_mission_parent", id)
            elif parent not in opened:
                issue("closed_parent", id)
            if row["horizon"] is not None:
                issue("child_horizon", id)
        if row["horizon"] is not None and row["horizon"] not in HORIZONS:
            issue("unsupported_horizon", id)
        title = row["title"]
        if isinstance(title, str) and units(title) > 500:
            token = "title-shortening:" + id
            # Equality is deliberately conservative: full text must remain in
            # the actual target intent, not only in this offline archive.
            lossless = title == row["intent"] and units(title) <= 100000
            approved = token in source["approved_lossy_transformations"]
            if approved:
                used_approvals.add(token)
            plan["transformations"].append({"kind": "title-shortening", "source_id": id,
                "approval_id": token, "lossy": not lossless, "approved": approved,
                "original_utf16_units": units(title), "target_utf16_limit": 500,
                "complete_source_preserved_in": "source_items", "full_title_in_target_intent": lossless})
            if not lossless and not approved:
                issue("approval_required", id, "title")
            title = prefix(title, 500)
        text(title, "title", 500, id)
        text(row["intent"], "intent", 100000, id)
        body = {"title": title, "intent": row["intent"]}
        if row["horizon"] is not None:
            body["horizon"] = row["horizon"]
        bodies[id] = {"source_id": id, "parent_source_id": parent, "body": body}
    for unused in sorted(set(source["approved_lossy_transformations"]) - used_approvals):
        issue("unused_transformation_approval", unused)

    questions = [q for q in all_questions if q["mission_id"] == mission]
    selected = set(source["selected_question_ids"])
    open_questions = [q for q in questions if q["answered_at"] is None and q["withdrawn_at"] is None]
    plan["source_questions"] = sorted([q for q in questions if q in open_questions or q["id"] in selected],
                                       key=lambda q: q["id"])
    plan["counts"]["open_questions"] = len(open_questions)
    for id in sorted(selected - {q["id"] for q in questions}):
        issue("selected_question_missing", id)
    for q in plan["source_questions"]:
        id = q["id"]
        archive(q, {"id", "mission_id", "work_item_id", "question", "proposal"}, "questions")
        if id not in selected:
            issue("unselected_open_question", id)
            continue
        if q["answered_at"] is not None or q["withdrawn_at"] is not None:
            issue("selected_question_not_open", id)
        states = QUESTION_FIELDS - {"id", "mission_id", "work_item_id", "question", "proposal", "raised_at"}
        if (type(q["raised_at"]) is not int or
                any(q[k] is not None for k in states | (q.keys() - QUESTION_FIELDS))):
            issue("unsupported_question_state", id)
        if q["work_item_id"] not in opened:
            issue("question_item_not_open_in_mission", id)
        text(q["question"], "question", 4000, id)
        body = {"question": q["question"]}
        if q["proposal"] is not None:
            text(q["proposal"], "proposal", 4000, id)
            body["proposal"] = q["proposal"]
        plan["questions"].append({"source_id": id, "work_item_source_id": q["work_item_id"], "body": body})

    if any(i["project"] == project for i in issues):
        return plan
    # Iterative topological levels avoid recursion limits on deep valid trees.
    remaining, done, depth = set(opened), set(), 0
    while remaining:
        level = sorted((i for i in remaining if opened[i]["parent_id"] is None or
                        opened[i]["parent_id"] in done), key=lambda i: (opened[i]["position"], i))
        if not level:
            issue("parent_cycle")
            return plan
        batch, size = [], len(encoded({"items": []})) + AUTHORITY_RESERVE

        def append_batch():
            plan["batches"].append({"depth": depth, "source_ids": [i["source_id"] for i in batch],
                                   "items": list(batch), "reserved_body_bytes": size})

        for id in level:
            item = bodies[id]
            placeholder = dict(item["body"])
            if item["parent_source_id"] is not None:
                # Worst-case JSON escaping for a 128 UTF-16-unit future id.
                placeholder["parentId"] = "\x01" * 128
            item_size = len(encoded(placeholder))
            if item_size + len(encoded({"items": []})) + AUTHORITY_RESERVE > BODY_BUDGET:
                issue("body_too_large", id)
                continue
            if batch and (len(batch) == MAX_ITEMS or size + item_size + 1 > BODY_BUDGET):
                append_batch()
                batch, size = [], len(encoded({"items": []})) + AUTHORITY_RESERVE
            size += item_size + (1 if batch else 0)
            batch.append(item)
        if batch:
            append_batch()
        done.update(level)
        remaining.difference_update(level)
        depth += 1
    return plan


def build_manifest(config):
    sources = validate_config(config)
    issues = []
    projects = [plan_project(s, issues) for s in sources]
    if issues:
        for project in projects:
            project["batches"] = []
            project["questions"] = []
    return {"format": "od10-offline-replay-v1", "status": "blocked" if issues else "ready_for_review",
            "live_replay_safe": False, "nothing_migrated": True,
            "selected_scope": sorted(PROJECTS), "projects_not_provided": sorted(PROJECTS - {s["project"] for s in sources}),
            "excluded_project": "wapps-platform", "issues": issues, "projects": projects,
            "limits": {"items_per_batch": MAX_ITEMS, "title_utf16": 500, "intent_utf16": 100000,
                       "question_utf16": 4000, "proposal_utf16": 4000,
                       "preparation_body_budget_bytes": BODY_BUDGET, "authority_reserve_bytes": AUTHORITY_RESERVE},
            "live_prerequisites": ["Freeze writers and take verified standalone snapshots.",
                "Review all transformations and archive-only metadata; confirm explicit mission mappings.",
                "Verify deployed schema, transport limits, permissions and real serialized request sizes.",
                "Implement a durable receipt journal and reconcile ambiguous commits before any retry.",
                "Claim, replay by completed depth and returned id mapping, ask selected question, verify, release."]}


def write_private(path, manifest):
    path = Path(path)
    if str(path) == "-":
        raise PlanningError("explicit_file_required")
    parent = path.parent.resolve(strict=True)
    if parent.stat().st_mode & 0o077:
        raise PlanningError("private_output_directory_required")
    payload = encoded(manifest) + b"\n"
    fd = os.open(parent / path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise PlanningError("invalid_arguments")


def main(argv=None):
    parser = QuietParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    try:
        args = parser.parse_args(argv)
        # Duplicate JSON keys are not an implicit last-wins approval mechanism.
        def unique_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise PlanningError("duplicate_config_key")
                result[key] = value
            return result
        config = json.loads(Path(args.config).read_text(), object_pairs_hook=unique_keys)
        manifest = build_manifest(config)
        write_private(args.output, manifest)
        return 3 if manifest["issues"] else 0
    except PlanningError as error:
        print("replay_plan: " + str(error), file=sys.stderr)
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, UnicodeError):
        # Never print exception messages: SQLite, paths and JSON can contain
        # source work text. There is no debug/traceback escape hatch.
        print("replay_plan: input_or_output_failure", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
