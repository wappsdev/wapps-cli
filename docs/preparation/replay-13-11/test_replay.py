"""Synthetic-only behavioral tests; never locate or open installed plugin stores."""
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parent
SCRIPT = BASE / "replay_plan.py"
# Match plugin columns, deliberately omit constraints to exercise corrupt snapshots.
SCHEMA = """
CREATE TABLE missions (id TEXT, repo_id TEXT, created_at INTEGER, status TEXT);
CREATE TABLE work_items (
 id TEXT, mission_id TEXT, parent_id TEXT, title TEXT, intent TEXT,
 position INTEGER, created_at INTEGER, closed_at INTEGER, closed_reason TEXT,
 source_job_id TEXT, source_index INTEGER, horizon TEXT, discovered_from TEXT);
CREATE TABLE work_questions (
 id TEXT, mission_id TEXT, work_item_id TEXT, question TEXT, raised_at INTEGER,
 answered_at INTEGER, answer TEXT, proposal TEXT, delegate_provider TEXT,
 answered_by TEXT, answer_job_id TEXT, relayed_at INTEGER, confirmed_at INTEGER,
 withdrawn_at INTEGER, withdrawn_reason TEXT, relayed_by TEXT);
"""


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-", dir=BASE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "snapshot ?#.sqlite"
        with closing(sqlite3.connect(self.db)) as con, con:
            con.executescript(SCHEMA)
            con.execute("INSERT INTO missions VALUES ('source-mission','synthetic',1,'active')")
        self.config = {"sources": [{
            "project": "navlun", "snapshot": str(self.db),
            "source_mission_id": "source-mission", "target_mission_id": "destination-mission",
            "selected_question_ids": [], "approved_lossy_transformations": []}]}

    def sql(self, statement, params=()):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute(statement, params)

    def item(self, id="root", **kw):
        row = dict(id=id, mission_id="source-mission", parent_id=None,
                   title="Synthetic title", intent="Synthetic intent", position=1,
                   created_at=100, closed_at=None, closed_reason=None, source_job_id=None,
                   source_index=None, horizon="next", discovered_from=None)
        row.update(kw)
        self.sql("INSERT INTO work_items (" + ",".join(row) + ") VALUES (" +
                 ",".join("?" for _ in row) + ")", tuple(row.values()))

    def question(self, id="q", **kw):
        row = dict(id=id, mission_id="source-mission", work_item_id="root",
                   question="Synthetic question?", raised_at=101, answered_at=None,
                   answer=None, proposal="Synthetic proposal", delegate_provider=None,
                   answered_by=None, answer_job_id=None, relayed_at=None, confirmed_at=None,
                   withdrawn_at=None, withdrawn_reason=None, relayed_by=None)
        row.update(kw)
        self.sql("INSERT INTO work_questions (" + ",".join(row) + ") VALUES (" +
                 ",".join("?" for _ in row) + ")", tuple(row.values()))

    def run_plan(self, expected=0, output="manifest.json", extra=()):
        config = self.root / "input.json"
        config.write_text(json.dumps(self.config))
        args = [sys.executable, "-B", str(SCRIPT), "--config", str(config)]
        if output is not None:
            args.extend(["--output", str(self.root / output)])
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        p = subprocess.run([*args, *extra], capture_output=True, text=True)
        self.assertEqual(p.returncode, expected, p.stderr)
        self.assertEqual(p.stdout, "")
        self.assertNotIn("Synthetic", p.stderr)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertFalse(Path(str(self.db) + "-journal").exists())
        self.assertFalse(Path(str(self.db) + "-wal").exists())
        if output is None or not (self.root / output).is_file():
            return None
        return json.loads((self.root / output).read_text())

    def blocked(self, code):
        result = self.run_plan(3)
        self.assertEqual(result["status"], "blocked")
        self.assertIn(code, [i["code"] for i in result["issues"]])
        self.assertEqual(result["projects"][0]["batches"], [])
        self.assertEqual(result["projects"][0]["questions"], [])
        return result

    def test_parent_first_stable_sibling_order_and_question_references(self):
        self.item("child", parent_id="root", horizon=None, position=0)
        self.item("z", position=2)
        self.item("a", position=2)
        self.item("root", position=1)
        self.question()
        self.config["sources"][0]["selected_question_ids"] = ["q"]
        m = self.run_plan()
        p = m["projects"][0]
        self.assertEqual(p["target_mission_id"], "destination-mission")
        self.assertEqual([b["source_ids"] for b in p["batches"]], [["root", "a", "z"], ["child"]])
        self.assertEqual(p["batches"][1]["items"][0]["parent_source_id"], "root")
        self.assertEqual(p["batches"][0]["items"][0]["body"],
                         {"title": "Synthetic title", "intent": "Synthetic intent", "horizon": "next"})
        self.assertEqual(p["questions"][0]["body"],
                         {"question": "Synthetic question?", "proposal": "Synthetic proposal"})
        self.assertEqual(p["questions"][0]["work_item_source_id"], "root")
        self.assertEqual(m, self.run_plan(output="second.json"))

    def test_actual_500_item_limit_splits_same_depth(self):
        for i in range(501):
            self.item(str(i), position=i)
        batches = self.run_plan()["projects"][0]["batches"]
        self.assertEqual([len(b["items"]) for b in batches], [500, 1])
        self.assertEqual([b["depth"] for b in batches], [0, 0])

    def test_encoded_byte_budget_splits_before_item_limit(self):
        for i in range(12):
            self.item(str(i), position=i, intent="x" * 100000)
        batches = self.run_plan()["projects"][0]["batches"]
        self.assertGreater(len(batches), 1)
        self.assertTrue(all(b["reserved_body_bytes"] <= 1048576 for b in batches))
        self.assertEqual(sum(len(b["items"]) for b in batches), 12)

    def test_lossless_title_shortening_uses_utf16_without_splitting_astral_character(self):
        title = "x" * 499 + "\U0001f600" + "tail"
        self.item(title=title, intent=title)
        p = self.run_plan()["projects"][0]
        self.assertEqual(p["batches"][0]["items"][0]["body"]["title"], "x" * 499)
        self.assertEqual(p["batches"][0]["items"][0]["body"]["intent"], title)
        self.assertEqual(p["source_items"][0]["title"], title)
        self.assertFalse(next(t for t in p["transformations"] if t["kind"] == "title-shortening")["lossy"])

    def test_lossy_title_requires_explicit_item_approval(self):
        self.item(title="x" * 501)
        p = self.blocked("approval_required")["projects"][0]
        self.assertTrue(next(t for t in p["transformations"] if t["kind"] == "title-shortening")["lossy"])
        self.config["sources"][0]["approved_lossy_transformations"] = ["title-shortening:root"]
        p = self.run_plan(output="approved.json")["projects"][0]
        self.assertEqual(p["batches"][0]["items"][0]["body"]["title"], "x" * 500)
        self.assertEqual(p["source_items"][0]["title"], "x" * 501)

    def test_provenance_and_adoption_links_are_preserved_and_reported(self):
        self.item(source_job_id="old-job", source_index=0, discovered_from="closed-origin")
        p = self.run_plan()["projects"][0]
        fields = {m["field"] for m in p["unsupported_metadata"]}
        self.assertTrue({"created_at", "source_job_id", "source_index", "discovered_from"} <= fields)
        self.assertEqual(p["source_items"][0]["source_job_id"], "old-job")
        self.assertEqual(p["source_items"][0]["discovered_from"], "closed-origin")
        self.assertTrue(any(t["kind"] == "archive-only-metadata" for t in p["transformations"]))

    def test_cycles_block_entire_manifest(self):
        self.item("a", parent_id="b", horizon=None)
        self.item("b", parent_id="a", horizon=None)
        self.blocked("parent_cycle")

    def test_missing_parent_is_not_silently_promoted(self):
        self.item(parent_id="absent", horizon=None)
        self.blocked("missing_parent")

    def test_closed_parent_is_not_silently_promoted(self):
        self.item("closed", closed_at=2, closed_reason="delivered")
        self.item(parent_id="closed", horizon=None)
        self.blocked("closed_parent")

    def test_cross_mission_parent_is_rejected(self):
        self.item("other", mission_id="other-mission")
        self.item(parent_id="other", horizon=None)
        self.blocked("cross_mission_parent")

    def test_duplicate_source_ids_are_not_overwritten(self):
        self.item()
        self.item()
        self.blocked("duplicate_item_id")

    def test_duplicate_question_ids_are_not_overwritten(self):
        self.item()
        self.question()
        self.question()
        self.config["sources"][0]["selected_question_ids"] = ["q"]
        self.blocked("duplicate_question_id")

    def test_child_horizon_is_rejected(self):
        self.item("parent")
        self.item(parent_id="parent")
        self.blocked("child_horizon")

    def test_invalid_horizon_and_unknown_state_block(self):
        self.item(horizon="tomorrow")
        self.blocked("unsupported_horizon")
        self.sql("UPDATE work_items SET horizon='next'")
        self.sql("ALTER TABLE work_items ADD COLUMN state TEXT")
        self.sql("UPDATE work_items SET state='in-progress'")
        m = self.run_plan(3, output="state.json")
        self.assertIn("unsupported_item_state", [i["code"] for i in m["issues"]])

    def test_inconsistent_closed_state_is_rejected(self):
        self.item(closed_reason="dropped")
        self.blocked("unsupported_item_state")

    def test_oversized_intent_blocks_instead_of_truncating(self):
        self.item(intent="\U0001f600" * 50001)
        self.blocked("intent_too_large")

    def test_cloud_trim_is_not_a_silent_text_change(self):
        self.item(title=" padded ")
        self.blocked("padded_text")

    def test_blank_required_text_is_rejected(self):
        self.item(intent="")
        self.blocked("blank_text")

    def test_selected_question_is_required_and_unselected_questions_are_visible(self):
        self.item()
        self.question()
        self.blocked("unselected_open_question")
        self.config["sources"][0]["selected_question_ids"] = ["absent"]
        m = self.run_plan(3, output="absent.json")
        self.assertIn("selected_question_missing", [i["code"] for i in m["issues"]])

    def test_question_limit_and_state_are_enforced(self):
        self.item()
        self.question(question="x" * 4001, delegate_provider="codex")
        self.config["sources"][0]["selected_question_ids"] = ["q"]
        m = self.blocked("unsupported_question_state")
        self.assertIn("question_too_large", [i["code"] for i in m["issues"]])

    def test_answered_or_withdrawn_selected_question_is_not_reasked(self):
        self.item()
        self.question(answered_at=3, answer="Synthetic answer")
        self.config["sources"][0]["selected_question_ids"] = ["q"]
        self.blocked("selected_question_not_open")

    def test_unsupported_timestamp_types_are_not_silently_treated_as_closed(self):
        self.item(closed_at="not-a-timestamp", closed_reason="delivered")
        self.blocked("unsupported_item_state")

    def test_invalid_source_timestamps_are_explicit(self):
        self.item(created_at="unknown")
        self.question(raised_at="unknown")
        self.config["sources"][0]["selected_question_ids"] = ["q"]
        m = self.blocked("unsupported_item_state")
        self.assertIn("unsupported_question_state", [i["code"] for i in m["issues"]])

    def test_all_four_projects_are_explicit_and_any_issue_blocks_all_batches(self):
        self.item()
        first = self.config["sources"][0]
        self.config["sources"] = [dict(first, project=p, target_mission_id="target-" + p)
                                  for p in ["navlun", "ecommerce", "kick-clip-analyzer", "real-estate-analysis"]]
        m = self.run_plan()
        self.assertEqual(m["projects_not_provided"], [])
        self.assertEqual(len(m["projects"]), 4)
        self.assertTrue(all(len(p["batches"]) == 1 for p in m["projects"]))
        self.config["sources"][0]["source_mission_id"] = "missing"
        m = self.run_plan(3, output="blocked-all.json")
        self.assertTrue(all(not p["batches"] and not p["questions"] for p in m["projects"]))

    def test_empty_mission_has_no_invented_historical_counts(self):
        p = self.run_plan()["projects"][0]
        self.assertEqual(p["counts"]["open_items"], 0)
        self.assertEqual(p["batches"], [])

    def test_deep_parent_chain_does_not_use_python_recursion(self):
        with closing(sqlite3.connect(self.db)) as con, con:
            con.executemany("INSERT INTO work_items (id,mission_id,parent_id,title,intent,position,created_at) "
                            "VALUES (?,'source-mission',?,'Synthetic title','Synthetic intent',?,1)",
                            [(str(i), str(i-1) if i else None, i) for i in range(1100)])
        batches = self.run_plan()["projects"][0]["batches"]
        self.assertEqual(len(batches), 1100)
        self.assertEqual(batches[-1]["source_ids"], ["1099"])
        self.assertEqual(batches[-1]["depth"], 1099)

    def test_question_proposal_utf16_limit_and_missing_item(self):
        self.item()
        self.question(work_item_id="missing", proposal="\U0001f600" * 2001)
        self.config["sources"][0]["selected_question_ids"] = ["q"]
        m = self.blocked("proposal_too_large")
        self.assertIn("question_item_not_open_in_mission", [i["code"] for i in m["issues"]])

    def test_js_whitespace_rules_not_python_strip_rules(self):
        self.item(title="﻿Synthetic title")
        self.blocked("padded_text")
        self.sql("UPDATE work_items SET title=?", ("\u0085Synthetic title\u0085",))
        body = self.run_plan(output="js-space.json")["projects"][0]["batches"][0]["items"][0]["body"]
        self.assertEqual(body["title"], "\u0085Synthetic title\u0085")

    def test_unknown_approval_does_not_authorize_a_different_item(self):
        self.item(title="x" * 501)
        self.config["sources"][0]["approved_lossy_transformations"] = ["title-shortening:other"]
        m = self.blocked("approval_required")
        self.assertIn("unused_transformation_approval", [i["code"] for i in m["issues"]])

    def test_missing_snapshot_is_never_created(self):
        missing = self.root / "missing.sqlite"
        self.config["sources"][0]["snapshot"] = str(missing)
        self.run_plan(2)
        self.assertFalse(missing.exists())
        self.assertFalse((self.root / "manifest.json").exists())

    def test_world_readable_output_directory_is_refused(self):
        self.item()
        public = self.root / "public"
        public.mkdir(mode=0o755)
        os.chmod(public, 0o755)
        self.run_plan(2, output="public/manifest.json")
        self.assertFalse((public / "manifest.json").exists())

    def test_unknown_schema_is_not_silently_interpreted(self):
        self.sql("ALTER TABLE work_items RENAME COLUMN horizon TO old_horizon")
        self.run_plan(2)
        self.assertFalse((self.root / "manifest.json").exists())

    def test_mission_mapping_and_scope_are_explicit(self):
        self.item()
        for index, bad in enumerate(["Upper", "a/b", "x" * 129, " leading"]):
            self.config["sources"][0]["target_mission_id"] = bad
            self.run_plan(2, output=f"bad-{index}.json")
        del self.config["sources"][0]["target_mission_id"]
        self.run_plan(2, output="missing.json")
        self.config["sources"][0]["target_mission_id"] = "destination"
        self.config["sources"][0]["project"] = "wapps-platform"
        self.run_plan(2, output="excluded.json")

    def test_unknown_or_inactive_source_mission_is_rejected(self):
        self.item()
        self.sql("UPDATE missions SET status='completed'")
        self.blocked("unsupported_mission_state")

    def test_missing_output_is_rejected_without_dumping_work(self):
        self.item()
        self.run_plan(2, output=None)

    def test_private_file_no_overwrite_and_no_symlink_following(self):
        self.item()
        self.run_plan()
        output = self.root / "manifest.json"
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        original = output.read_bytes()
        self.run_plan(2)
        self.assertEqual(output.read_bytes(), original)
        (self.root / "link.json").symlink_to(output)
        self.run_plan(2, output="link.json")
        self.assertEqual(output.read_bytes(), original)

    def test_readonly_connection_rejects_writes_even_after_query_only_disabled(self):
        self.assertTrue(SCRIPT.exists(), "offline planner is not implemented")
        spec = importlib.util.spec_from_file_location("planner", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        before = self.db.read_bytes()
        con = module.open_snapshot(self.db)
        try:
            con.execute("PRAGMA query_only=OFF")
            with self.assertRaises(sqlite3.OperationalError):
                con.execute("CREATE TABLE forbidden (x)")
        finally:
            con.close()
        self.assertEqual(before, self.db.read_bytes())

    def test_sidecars_are_rejected_not_ignored_by_immutable_read(self):
        self.item()
        sidecar = Path(str(self.db) + "-wal")
        sidecar.write_bytes(b"synthetic WAL sentinel")
        config = self.root / "input.json"
        config.write_text(json.dumps(self.config))
        p = subprocess.run([sys.executable, "-B", str(SCRIPT), "--config", str(config),
                            "--output", str(self.root / "manifest.json")], capture_output=True)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")
        self.assertEqual(sidecar.read_bytes(), b"synthetic WAL sentinel")
        self.assertFalse((self.root / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
