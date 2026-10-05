"""Synthetic-only recovery tests: real private receipts, no network or work stores."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
SCRIPT = BASE / "replay_recovery.py"


from synthetic_recovery import synthetic_manifest


class Crash(BaseException):
    """Deliberately bypass ordinary exception handling like process death."""


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), "fake-only recovery model is not implemented")
        spec = importlib.util.spec_from_file_location("recovery", SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-recovery-", dir=BASE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "receipt.json"
        self.manifest = synthetic_manifest()
        self.server = self.m.FakeWorkServer({("navlun", "target")})

    def replay(self, resume=False, server=None, manifest=None):
        return self.m.replay(manifest or self.manifest, self.path, server or self.server, resume=resume)

    def receipt(self):
        return json.loads(self.path.read_text())["receipt"]

    def test_parent_and_question_use_actual_returned_ids_not_source_ids(self):
        self.assertEqual(self.replay(), 0)
        items = self.server.items[("navlun", "target")]
        self.assertEqual(len(items), 3)
        self.assertEqual(items["fake-item-3"]["parentId"], "fake-item-1")
        self.assertEqual(items["fake-item-1"]["horizon"], "next")
        self.assertNotIn("parentId", items["fake-item-2"])
        questions = self.server.questions[("navlun", "target")]
        self.assertEqual(questions["fake-question-1"]["workItemId"], "fake-item-3")
        self.assertEqual([e["state"] for e in self.receipt()["entries"]], ["acknowledged"] * 3)

    def test_same_title_different_sources_remain_distinct_on_restart(self):
        self.replay()
        original = copy.deepcopy(self.server.items)
        self.assertEqual(self.replay(resume=True), 0)
        self.assertEqual(self.server.items, original)
        ids = self.receipt()["entries"][0]["destination_ids"]
        self.assertEqual(ids, ["fake-item-1", "fake-item-2"])

    def test_partial_success_crash_before_next_intent_resumes_without_duplicates(self):
        save = self.m.ReceiptFile.save

        def interrupt(journal, data):
            if data["entries"][1]["state"] == "in_flight":
                raise Crash()
            save(journal, data)

        with patch.object(self.m.ReceiptFile, "save", interrupt), self.assertRaises(Crash):
            self.replay()
        self.assertEqual(len(self.server.items[("navlun", "target")]), 2)
        self.assertEqual(self.receipt()["entries"][1]["state"], "pending")
        self.assertEqual(self.replay(resume=True), 0)
        self.assertEqual(len(self.server.items[("navlun", "target")]), 3)

    def test_committed_write_with_lost_response_is_unresolved_never_resent(self):
        parent = self.m.FakeWorkServer

        class LostResponse(parent):
            def add(self, scope, body):
                super().add(scope, body)
                raise TimeoutError()

        server = LostResponse({("navlun", "target")})
        self.assertEqual(self.replay(server=server), 3)
        first = self.receipt()["entries"][0]
        self.assertEqual(first["state"], "unresolved")
        self.assertEqual(first["reason"], "outcome_not_proven")
        self.assertEqual(first["destination_ids"], [])
        self.assertEqual(first["before_ids"], [])
        self.assertEqual(self.replay(resume=True, server=server), 3)
        self.assertEqual(len(server.items[("navlun", "target")]), 2)
        self.assertEqual(self.receipt()["entries"][1]["state"], "pending")

    def test_crash_after_commit_before_ack_and_crash_before_send_both_stop(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                self.path = self.root / f"crash-{committed}.json"
                server = self.m.FakeWorkServer({("navlun", "target")})
                save = self.m.ReceiptFile.save

                def interrupt(journal, data):
                    state = data["entries"][0]["state"]
                    if committed and state == "acknowledged":
                        raise Crash()
                    save(journal, data)
                    if not committed and state == "in_flight":
                        raise Crash()

                with patch.object(self.m.ReceiptFile, "save", interrupt), self.assertRaises(Crash):
                    self.replay(server=server)
                self.assertEqual(self.receipt()["entries"][0]["state"], "in_flight")
                self.assertEqual(self.replay(resume=True, server=server), 3)
                self.assertEqual(self.receipt()["entries"][0]["state"], "unresolved")
                self.assertEqual(len(server.items[("navlun", "target")]), 2 if committed else 0)

    def test_explicit_failed_batch_does_not_apply_partial_items_or_retry(self):
        parent = self.m.FakeWorkServer

        class RejectBatch(parent):
            def add(self, scope, body):
                changed = copy.deepcopy(body)
                changed["items"][-1]["parentId"] = "absent-parent"
                return super().add(scope, changed)

        server = RejectBatch({("navlun", "target")})
        self.assertEqual(self.replay(server=server), 3)
        self.assertEqual(server.items[("navlun", "target")], {})
        self.assertEqual(self.receipt()["entries"][0]["state"], "failed")
        self.assertEqual(self.replay(resume=True, server=server), 3)

    def test_question_response_loss_is_not_retried_even_when_items_are_known(self):
        parent = self.m.FakeWorkServer

        class LostQuestion(parent):
            def ask(self, scope, body):
                super().ask(scope, body)
                raise TimeoutError()

        server = LostQuestion({("navlun", "target")})
        self.assertEqual(self.replay(server=server), 3)
        self.assertEqual([e["state"] for e in self.receipt()["entries"]],
                         ["acknowledged", "acknowledged", "unresolved"])
        self.assertEqual(self.replay(resume=True, server=server), 3)
        self.assertEqual(len(server.questions[("navlun", "target")]), 1)

    def test_changed_manifest_snapshot_title_approval_or_mission_rejected(self):
        self.replay()
        original = self.path.read_bytes()
        for field, value in (("target_mission_id", "other"), ("snapshot_sha256", "b" * 64),
                             ("approved_lossy_transformations", ["operator-assertion"])):
            changed = copy.deepcopy(self.manifest)
            changed["projects"][0][field] = value
            with self.subTest(field=field), self.assertRaises(self.m.RecoveryError):
                self.replay(resume=True, manifest=changed)
        changed = copy.deepcopy(self.manifest)
        changed["projects"][0]["batches"][0]["items"][0]["body"]["title"] = "Edited"
        with self.assertRaises(self.m.RecoveryError):
            self.replay(resume=True, manifest=changed)
        self.assertEqual(self.path.read_bytes(), original)

    def test_operation_identity_separate_from_mutable_text(self):
        ops = self.m.operations(self.manifest)
        changed = copy.deepcopy(self.manifest)
        changed["projects"][0]["batches"][0]["items"][0]["body"]["title"] = "New title"
        edited = self.m.operations(changed)
        self.assertEqual(ops[0]["operation_id"], edited[0]["operation_id"])
        self.assertNotEqual(ops[0]["records"], edited[0]["records"])

    def test_same_source_ids_in_two_projects_cannot_cross_map(self):
        second = copy.deepcopy(self.manifest["projects"][0])
        second.update(project="ecommerce", target_mission_id="second-target", questions=[])
        self.manifest["projects"].append(second)
        self.server = self.m.FakeWorkServer({("navlun", "target"), ("ecommerce", "second-target")})
        self.assertEqual(self.replay(), 0)
        first = self.server.items[("navlun", "target")]
        second_items = self.server.items[("ecommerce", "second-target")]
        self.assertEqual(first["fake-item-3"]["parentId"], "fake-item-1")
        self.assertEqual(second_items["fake-item-6"]["parentId"], "fake-item-4")
        self.assertEqual(len({e["operation_id"] for e in self.receipt()["entries"]}), 5)
        self.assertEqual(self.replay(resume=True), 0)

    def test_wrong_destination_is_rejected_before_writes(self):
        server = self.m.FakeWorkServer({("navlun", "not-target")})
        with self.assertRaises(self.m.RecoveryError):
            self.replay(server=server)
        self.assertFalse(self.path.exists())
        self.assertEqual(server.items[("navlun", "not-target")], {})

    def test_acknowledged_destination_drift_blocks_restart(self):
        self.replay()
        self.server.items[("navlun", "target")]["fake-item-3"]["parentId"] = "fake-item-2"
        with self.assertRaises(self.m.RecoveryError):
            self.replay(resume=True)

    def test_corruption_or_checksum_tampering_is_not_overwritten(self):
        self.replay()
        original = self.path.read_bytes()
        altered = json.loads(original)
        altered["receipt"]["entries"][0]["destination_ids"][0] = "forged"
        for data in (b"{", b"", original[:50], json.dumps(altered).encode(),
                     b'{"receipt":{},"receipt":{},"sha256":"x"}'):
            self.path.write_bytes(data)
            with self.subTest(data=data[:40]), self.assertRaises(self.m.RecoveryError):
                self.replay(resume=True)
            self.assertEqual(self.path.read_bytes(), data)

    def test_recomputed_checksum_does_not_bypass_mapping_or_operation_validation(self):
        self.replay()
        original = json.loads(self.path.read_text())
        for field, value in (("destination_ids", ["fake-item-2", "fake-item-1"]),
                             ("operation_id", "f" * 64), ("state", "pending")):
            data = copy.deepcopy(original)
            data["receipt"]["entries"][0][field] = value
            # Identical root bodies mean a reordered root mapping is caught by
            # child request validation, not by matching title or content alone.
            data["sha256"] = hashlib.sha256(self.m.encoded(data["receipt"])).hexdigest()
            self.path.write_bytes(self.m.encoded(data))
            with self.subTest(field=field), self.assertRaises(self.m.RecoveryError):
                self.replay(resume=True)

    def test_private_modes_exclusive_creation_no_symlink_or_hardlink(self):
        self.replay()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.with_name("receipt.json.lock").stat().st_mode & 0o777, 0o600)
        original = self.path.read_bytes()
        with self.assertRaises(self.m.RecoveryError):
            self.replay()
        self.assertEqual(self.path.read_bytes(), original)
        for kind in ("symlink", "hardlink"):
            other = self.root / (kind + ".json")
            if kind == "symlink":
                other.symlink_to(self.path)
            else:
                os.link(self.path, other)
            with self.assertRaises(self.m.RecoveryError):
                self.m.replay(self.manifest, other, self.server, resume=True)
            other.unlink()
        os.chmod(self.path, 0o644)
        with self.assertRaises(self.m.RecoveryError):
            self.replay(resume=True)
        self.assertEqual(self.path.read_bytes(), original)

    def test_public_directory_and_missing_resume_refused(self):
        os.chmod(self.root, 0o755)
        with self.assertRaises(self.m.RecoveryError):
            self.replay()
        self.assertFalse(self.path.exists())
        os.chmod(self.root, 0o700)
        with self.assertRaises(self.m.RecoveryError):
            self.replay(resume=True)
        self.assertFalse(self.path.exists())

    def test_second_writer_refused_and_external_edit_never_replaced(self):
        with self.m.ReceiptFile(self.path, resume=False) as file:
            data = self.m.new_receipt(self.manifest)
            file.save(data)
            with self.assertRaises(self.m.RecoveryError):
                with self.m.ReceiptFile(self.path, resume=True):
                    pass
            self.path.write_bytes(b"user sentinel")
            with self.assertRaises(self.m.RecoveryError):
                file.save(data)
        self.assertEqual(self.path.read_bytes(), b"user sentinel")

    def test_failed_atomic_replace_preserves_previous_complete_receipt(self):
        self.replay()
        original = self.path.read_bytes()
        with self.m.ReceiptFile(self.path, resume=True) as file:
            data = file.load()
            with patch.object(self.m.os, "replace", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    file.save(data)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.root.glob("*.tmp")), [])
        self.assertEqual(self.replay(resume=True), 0)

    def test_file_fsync_failure_prevents_publication(self):
        with self.m.ReceiptFile(self.path, resume=False) as file:
            with patch.object(self.m.os, "fsync", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    file.save(self.m.new_receipt(self.manifest))
        self.assertFalse(self.path.exists())

    def test_malformed_ack_is_unresolved_not_success(self):
        parent = self.m.FakeWorkServer

        class BadAck(parent):
            def add(self, scope, body):
                super().add(scope, body)
                return {"ok": True, "workItemIds": ["fake-item-1", "fake-item-1"]}

        server = BadAck({("navlun", "target")})
        self.assertEqual(self.replay(server=server), 3)
        self.assertEqual(self.receipt()["entries"][0]["state"], "unresolved")
        self.assertEqual(self.replay(resume=True, server=server), 3)
        self.assertEqual(len(server.items[("navlun", "target")]), 2)

    def test_blocked_manifest_and_duplicate_source_identity_rejected(self):
        blocked = copy.deepcopy(self.manifest)
        blocked["status"] = "blocked"
        with self.assertRaises(self.m.RecoveryError):
            self.replay(manifest=blocked)
        duplicate = copy.deepcopy(self.manifest)
        duplicate["projects"][0]["batches"][0]["items"][1]["source_id"] = "root-a"
        with self.assertRaises(self.m.RecoveryError):
            self.replay(manifest=duplicate)
        self.assertFalse(self.path.exists())

    def test_bad_json_types_have_fixed_corruption_errors_and_preserve_bytes(self):
        self.replay()
        original = json.loads(self.path.read_text())
        for field, value in (("state", []), ("before_ids", {}), ("destination_ids", [None]),
                             ("request", []), ("request_sha256", 42)):
            data = copy.deepcopy(original)
            data["receipt"]["entries"][0][field] = value
            data["sha256"] = hashlib.sha256(self.m.encoded(data["receipt"])).hexdigest()
            raw = self.m.encoded(data)
            self.path.write_bytes(raw)
            with self.subTest(field=field):
                try:
                    self.replay(resume=True)
                except Exception as error:
                    self.assertIsInstance(error, self.m.RecoveryError)
                else:
                    self.fail("corrupt receipt was accepted")
            self.assertEqual(self.path.read_bytes(), raw)

    def test_private_directory_is_rechecked_before_update(self):
        self.replay()
        original = self.path.read_bytes()
        with self.m.ReceiptFile(self.path, resume=True) as file:
            data = file.load()
            os.chmod(self.root, 0o755)
            with self.assertRaises(self.m.RecoveryError):
                file.save(data)
        self.assertEqual(self.path.read_bytes(), original)

    def test_crash_during_atomic_replace_leaves_complete_old_or_new_document(self):
        self.replay()
        original = self.path.read_bytes()
        # A hard process exit after replacement skips cleanup/context-manager
        # handlers and tests a real reopened file, not just object reconstruction.
        code = '''import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import replay_recovery as r
with r.ReceiptFile(Path(sys.argv[2]), resume=True) as file:
    data = file.load()
    data["crash_probe"] = True
    replace = r.os.replace
    def crash(*args, **kwargs):
        replace(*args, **kwargs)
        os._exit(71)
    r.os.replace = crash
    file.save(data)
'''
        result = subprocess.run([sys.executable, "-B", "-c", code, str(BASE), str(self.path)],
                                capture_output=True)
        self.assertEqual(result.returncode, 71, result.stderr)
        raw = self.path.read_bytes()
        envelope = json.loads(raw)
        self.assertEqual(envelope["sha256"], hashlib.sha256(self.m.encoded(envelope["receipt"])).hexdigest())
        self.assertNotEqual(raw, original)
        self.assertTrue(envelope["receipt"]["crash_probe"])
        # The durable-format reader rejects the injected unknown field; it never
        # treats any parseable JSON as permission to resume.
        with self.assertRaises(self.m.RecoveryError):
            self.replay(resume=True)

    def test_directory_fsync_failure_halts_before_fake_send(self):
        fsync = self.m.os.fsync
        calls = 0

        def fail_directory(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("directory durability failure")
            fsync(fd)

        with patch.object(self.m.os, "fsync", fail_directory), self.assertRaises(OSError):
            self.replay()
        self.assertEqual(self.server.items[("navlun", "target")], {})
        self.assertEqual(self.receipt()["entries"][0]["state"], "pending")
        self.assertEqual(self.replay(resume=True), 0)

    def test_baseline_inventory_does_not_claim_preexisting_identical_work(self):
        body = self.manifest["projects"][0]["batches"][0]["items"][0]["body"]
        self.server.add(("navlun", "target"), {"items": [body]})
        self.assertEqual(self.replay(), 0)
        first = self.receipt()["entries"][0]
        self.assertEqual(first["before_ids"], ["fake-item-1"])
        self.assertEqual(first["destination_ids"], ["fake-item-2", "fake-item-3"])
        self.assertEqual(len(self.server.items[("navlun", "target")]), 4)

    def test_real_planner_manifest_runs_through_fake_recovery(self):
        # Reuse only synthetic fixture construction, then invoke the existing
        # planner itself; this catches drift between preparation stages.
        from test_replay import ReplayTests
        from replay_plan import build_manifest
        fixture = ReplayTests()
        fixture.setUp()
        try:
            fixture.item()
            fixture.item("child", parent_id="root", horizon=None)
            fixture.question(work_item_id="child")
            fixture.config["sources"][0]["selected_question_ids"] = ["q"]
            manifest = build_manifest(fixture.config)
            server = self.m.FakeWorkServer({("navlun", "destination-mission")})
            self.assertEqual(self.replay(manifest=manifest, server=server), 0)
            self.assertEqual(self.replay(resume=True, manifest=manifest, server=server), 0)
            self.assertEqual(server.items[("navlun", "destination-mission")]["fake-item-2"]["parentId"],
                             "fake-item-1")
        finally:
            fixture.doCleanups()

    def test_demo_subprocess_exact_exit_codes_and_no_overwrite(self):
        demo = BASE / "recovery_demo.py"
        self.assertTrue(demo.exists(), "synthetic-only demonstration CLI missing")
        for scenario, expected in (("success", 0), ("response-loss", 3), ("failed-batch", 3)):
            path = self.root / (scenario + ".json")
            command = [sys.executable, "-B", str(demo), "--scenario", scenario, "--receipt", str(path)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            original = path.read_bytes()
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 2, refused.stderr)
            self.assertEqual(refused.stdout, "")
            self.assertNotIn("Synthetic", refused.stderr)
            self.assertEqual(path.read_bytes(), original)

    def test_subprocess_restart_uses_receipt_not_process_memory(self):
        self.replay()
        code = '''import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import replay_recovery as r
from test_recovery import synthetic_manifest
s = r.FakeWorkServer({("navlun", "target")})
# Synthetic server survives outside the restarted client; rehydrate only
# the hand-built fake's state, never a real server or database.
s.items[("navlun", "target")] = json.loads(sys.argv[3])
s.questions[("navlun", "target")] = json.loads(sys.argv[4])
sys.exit(r.replay(synthetic_manifest(), Path(sys.argv[2]), s, resume=True))
'''
        result = subprocess.run([sys.executable, "-B", "-c", code, str(BASE), str(self.path),
                                 json.dumps(self.server.items[("navlun", "target")]),
                                 json.dumps(self.server.questions[("navlun", "target")])],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
