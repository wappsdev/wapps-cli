"""Synthetic durable keyed contract tests. No deployed Worker or transport is used."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from replay_recovery import ReceiptFile, RecoveryError
from synthetic_recovery import synthetic_manifest

BASE = Path(__file__).resolve().parent
SCRIPT = BASE / "replay_keyed.py"
PRINCIPAL = "svc:synthetic"
AUTHORITY = {"capability": "synthetic-cap-1", "fencingToken": 1}


class Crash(BaseException):
    """Process death bypasses ordinary response-loss handling."""


class KeyedTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), "source-backed keyed model is not implemented")
        spec = importlib.util.spec_from_file_location("keyed", SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-keyed-", dir=BASE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "client.json"
        self.destination = self.root / "destination.json"
        self.manifest = synthetic_manifest()
        self.server = self.m.KeyedFakeServer.create(
            self.destination, ["target", "other-target"], PRINCIPAL, AUTHORITY)
        self.body = {"items": [{"title": "same", "intent": "recover"},
                               {"title": "same", "intent": "recover"}]}

    def call(self, *, body=None, key="shared", kind="work_add", principal=PRINCIPAL,
             authority=None, mission="target"):
        return self.server.call(mission, principal, authority or AUTHORITY, kind, key,
                                copy.deepcopy(body if body is not None else self.body))

    def run_replay(self, *, resume=False, approved_retry=False, principal=PRINCIPAL,
                   authority=None, manifest=None):
        return self.m.replay_keyed(manifest or self.manifest, self.path, self.server,
                                   principal=principal, authority=authority or AUTHORITY,
                                   resume=resume, approved_retry=approved_retry)

    def receipt(self):
        with ReceiptFile(self.path, resume=True) as file:
            return file.load()

    def rewrite(self, value):
        with ReceiptFile(self.path, resume=True) as file:
            file.load()
            file.save(value)

    def test_same_key_returns_original_ordered_result_after_destination_reopen(self):
        first = self.call()
        self.assertEqual(first["status"], 201)
        self.server = self.m.KeyedFakeServer(self.destination)
        self.assertEqual(self.call(), first)
        self.assertEqual(len(self.server.inventory("target", "work_add")), 2)
        self.assertEqual(len(set(first["body"]["workItemIds"])), 2)

    def test_normalized_text_and_object_order_replay_but_batch_order_conflicts(self):
        body = {"items": [{"title": "a", "intent": "é\n", "horizon": "now"},
                           {"title": "b", "intent": "j"}]}
        first = self.call(body=body)
        reordered = {"items": [{"horizon": "now", "intent": " é\n ", "title": " a "},
                                {"intent": "j", "title": "b"}]}
        # Trailing newline is semantic trim, hence normalized original is "é".
        self.assertEqual(self.call(body=reordered), first)
        conflict = self.call(body={"items": list(reversed(body["items"]))})
        self.assertEqual(conflict, {"status": 409, "body": {
            "error": "OPERATION_KEY_CONFLICT", "details": {"refusal": "operation_key_conflict"},
            "retryable": False}})
        self.assertEqual(len(self.server.inventory("target", "work_add")), 2)

    def test_changed_content_conflicts_for_both_verbs_without_new_ids(self):
        first = self.call()
        changed = copy.deepcopy(self.body)
        changed["items"][0]["intent"] = "changed"
        self.assertEqual(self.call(body=changed)["status"], 409)
        ask = {"workItemId": first["body"]["workItemIds"][0], "question": "why?", "proposal": "this"}
        original = self.call(body=ask, kind="work_ask")
        self.assertEqual(self.call(body=ask, kind="work_ask"), original)
        self.assertEqual(self.call(body={**ask, "proposal": "other"}, kind="work_ask")["status"], 409)
        self.assertEqual(len(self.server.inventory("target", "work_ask")), 1)

    def test_server_principal_mission_and_operation_scopes_are_independent(self):
        first = self.call()
        self.server.set_grant("target", "svc:other", True)
        another = self.call(principal="svc:other")
        elsewhere = self.call(mission="other-target")
        self.assertNotEqual(first["body"], another["body"])
        self.assertNotEqual(first["body"], elsewhere["body"])
        ask = {"workItemId": first["body"]["workItemIds"][0], "question": "why?"}
        question = self.call(body=ask, kind="work_ask")
        self.assertEqual(question["status"], 201)
        self.assertEqual(self.call(body=ask, kind="work_ask"), question)
        self.assertEqual(self.call(), first)

    def test_case_sensitive_keys_allow_intentionally_separate_operations(self):
        self.assertNotEqual(self.call(key="Key")["body"], self.call(key="key")["body"])
        self.assertEqual(len(self.server.inventory("target", "work_add")), 4)

    def test_invalid_authority_schema_cannot_replay_a_committed_key(self):
        self.call()
        for authority in ({**AUTHORITY, "fencingToken": True},
                          {**AUTHORITY, "fencingToken": 0},
                          {**AUTHORITY, "fencingToken": 1.5},
                          {**AUTHORITY, "fencingToken": 9007199254740992},
                          {**AUTHORITY, "capability": ""},
                          {**AUTHORITY, "capability": None},
                          {**AUTHORITY, "extra": "unknown"}):
            self.assertEqual(self.call(authority=authority)["status"], 400)
        self.assertEqual(len(self.server.inventory("target", "work_add")), 2)

    def test_truthy_nonboolean_retry_action_does_not_authorize_synthetic_retry(self):
        self.run_replay()
        before = self.path.read_bytes()
        for value in ("false", "true", 1, {"approved": True}):
            self.assertEqual(self.run_replay(resume=True, approved_retry=value), 3)
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_keys_unknown_fields_and_null_optionals_never_write(self):
        for key in ("", " padded", "padded ", "a\n", "a/b", "é", "a" * 129, None, 1):
            with self.subTest(key=key):
                self.assertEqual(self.call(key=key)["status"], 400)
        for item in ({"title": "a", "intent": "i", "parentId": None},
                     {"title": "a", "intent": "i", "extra": "not allowed"},
                     {"title": "a\ud800", "intent": "i"}):
            self.assertEqual(self.call(body={"items": [item]})["status"], 400)
        self.assertEqual(self.server.inventory("target", "work_add"), {})
        self.assertEqual(self.call(key="A" * 128)["status"], 201)

    def test_actual_utf16_and_batch_bounds_apply_before_receipt_replay(self):
        for items in ([], [{"title": "x", "intent": "i"}] * 501,
                      [{"title": "😀" * 251, "intent": "i"}],
                      [{"title": "x", "intent": "i" * 100001}]):
            self.assertEqual(self.call(body={"items": items})["status"], 400)
        body = {"items": [{"title": "😀" * 250, "intent": "i" * 100000}]}
        first = self.call(body=body)
        self.assertEqual(first["status"], 201)
        self.assertEqual(self.call(body=body), first)
        ask = {"workItemId": first["body"]["workItemIds"][0], "question": "q" * 4000}
        self.assertEqual(self.call(body=ask, kind="work_ask")["status"], 201)
        for extra in ({"question": "q" * 4001}, {"proposal": None}, {"proposal": " "}, {"question": " "}):
            self.assertEqual(self.call(body={**ask, **extra}, kind="work_ask")["status"], 400)

    def test_new_live_capability_replays_but_revoked_expired_and_stale_do_not(self):
        first = self.call()
        new = {"capability": "synthetic-cap-2", "fencingToken": 2}
        self.server.set_lease("target", new, active=True)
        self.assertEqual(self.call(authority=new), first)
        self.assertEqual(self.call()["status"], 403)
        self.assertEqual(self.call(authority={**new, "capability": "wrong"})["status"], 403)
        self.server.set_grant("target", PRINCIPAL, False)
        self.assertEqual(self.call(authority=new)["status"], 403)
        self.server.set_grant("target", PRINCIPAL, True)
        self.server.set_lease("target", new, active=False)
        self.assertEqual(self.call(authority=new)["status"], 403)
        self.assertEqual(len(self.server.inventory("target", "work_add")), 2)

    def test_replay_does_not_recheck_mutable_creation_preconditions(self):
        first = self.call()
        parent = first["body"]["workItemIds"][0]
        child = {"items": [{"title": "child", "intent": "i", "parentId": parent}]}
        filed = self.call(body=child, key="child")
        ask = {"workItemId": parent, "question": "why?"}
        asked = self.call(body=ask, kind="work_ask")
        self.server.close_item("target", parent)
        self.assertEqual(self.call(body=child, key="child"), filed)
        self.assertEqual(self.call(body=ask, kind="work_ask"), asked)
        self.assertEqual(self.call(body=child, key="new")["status"], 409)
        self.assertEqual(self.call(body=ask, kind="work_ask", key="new")["status"], 409)

    def test_refused_creation_does_not_reserve_key(self):
        self.assertEqual(self.call(body={"items": [{"title": "bad", "intent": "i", "parentId": "absent"}]})["status"], 409)
        self.assertEqual(self.call()["status"], 201)

    def test_stable_key_excludes_titles_snapshot_and_current_lease(self):
        original = self.m.keyed_operations(self.manifest)
        changed = copy.deepcopy(self.manifest)
        changed["projects"][0]["snapshot_sha256"] = "b" * 64
        changed["projects"][0]["batches"][0]["items"][0]["body"]["title"] = "changed"
        revised = self.m.keyed_operations(changed)
        self.assertEqual([o["operation_key"] for o in original], [o["operation_key"] for o in revised])
        for op in original:
            self.assertRegex(op["operation_key"], r"\Aod10k1-[0-9a-f]{64}\Z")
            self.assertLessEqual(len(op["operation_key"]), 128)
        changed["projects"][0]["target_mission_id"] = "other-target"
        self.assertNotEqual(original[0]["operation_key"], self.m.keyed_operations(changed)[0]["operation_key"])

    def test_ordered_source_ids_and_verb_enter_key_identity(self):
        first = self.m.keyed_operations(self.manifest)[0]["operation_key"]
        changed = copy.deepcopy(self.manifest)
        batch = changed["projects"][0]["batches"][0]
        batch["items"].reverse()
        batch["source_ids"].reverse()
        self.assertNotEqual(first, self.m.keyed_operations(changed)[0]["operation_key"])
        self.assertEqual(len(set(o["operation_key"] for o in self.m.keyed_operations(self.manifest))), 3)

    def test_ordered_parent_and_question_substitution_survives_repeated_complete_replay(self):
        self.assertEqual(self.run_replay(), 0)
        receipt = self.receipt()
        self.assertEqual([e["state"] for e in receipt["entries"]], ["acknowledged"] * 3)
        roots, child, question = receipt["entries"]
        self.assertEqual(child["request"]["items"][0]["parentId"], roots["destination_ids"][0])
        self.assertEqual(question["request"]["workItemId"], child["destination_ids"][0])
        self.server = self.m.KeyedFakeServer(self.destination)
        self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
        self.assertEqual(self.receipt(), receipt)
        self.assertEqual(len(self.server.inventory("target", "work_add")), 3)
        self.assertEqual(len(self.server.inventory("target", "work_ask")), 1)

    def test_response_loss_after_commit_requires_approval_and_replays_original_ids(self):
        original = self.server.call
        committed = []
        def loss(*args):
            result = original(*args)
            committed.append(result)
            raise TimeoutError()
        with patch.object(self.server, "call", loss):
            self.assertEqual(self.run_replay(), 3)
        self.assertEqual(len(self.server.inventory("target", "work_add")), 2)
        before = self.path.read_bytes()
        self.assertEqual(self.run_replay(resume=True), 3)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
        self.assertEqual(self.receipt()["entries"][0]["destination_ids"], committed[0]["body"]["workItemIds"])
        self.assertEqual(len(self.server.inventory("target", "work_add")), 3)

    def test_question_response_loss_reconciles_separately_without_second_question(self):
        original = self.server.call
        committed = []
        def loss(mission, principal, authority, kind, key, body):
            result = original(mission, principal, authority, kind, key, body)
            if kind == "work_ask":
                committed.append(result)
                raise TimeoutError()
            return result
        with patch.object(self.server, "call", loss):
            self.assertEqual(self.run_replay(), 3)
        self.assertEqual([e["state"] for e in self.receipt()["entries"]], ["acknowledged", "acknowledged", "unresolved"])
        self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
        self.assertEqual(self.receipt()["entries"][2]["destination_ids"], [committed[0]["body"]["questionId"]])
        self.assertEqual(len(self.server.inventory("target", "work_ask")), 1)

    def test_interruption_before_send_after_commit_and_after_ack_restarts(self):
        for moment in ("before_send", "after_commit", "after_ack"):
            with self.subTest(moment=moment):
                self.path = self.root / (moment + ".json")
                destination = self.root / (moment + "-destination.json")
                self.server = self.m.KeyedFakeServer.create(destination, ["target"], PRINCIPAL, AUTHORITY)
                save, call = ReceiptFile.save, self.server.call
                def interrupt_save(file, data):
                    save(file, data)
                    if file.path == self.path and data["entries"][0]["state"] == (
                            "in_flight" if moment == "before_send" else "acknowledged"):
                        raise Crash()
                def interrupt_call(*args):
                    call(*args)
                    raise Crash()
                with self.assertRaises(Crash):
                    if moment == "after_commit":
                        with patch.object(self.server, "call", interrupt_call):
                            self.run_replay()
                    else:
                        with patch.object(ReceiptFile, "save", interrupt_save):
                            self.run_replay()
                self.server = self.m.KeyedFakeServer(destination)
                self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
                self.assertEqual(len(self.server.inventory("target", "work_add")), 3)
                self.assertEqual(len(self.server.inventory("target", "work_ask")), 1)

    def test_no_send_if_durable_intent_save_fails(self):
        original = ReceiptFile.save
        def fail(file, data):
            if file.path == self.path and data["entries"][0]["state"] == "in_flight":
                raise OSError()
            return original(file, data)
        with patch.object(ReceiptFile, "save", fail), self.assertRaises(OSError):
            self.run_replay()
        self.assertEqual(self.server.inventory("target", "work_add"), {})

    def test_complete_receipt_never_bypasses_current_revocation_or_fencing(self):
        self.run_replay()
        before = self.path.read_bytes()
        self.server.set_grant("target", PRINCIPAL, False)
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True)
        self.server.set_grant("target", PRINCIPAL, True)
        self.server.set_lease("target", {"capability": "new", "fencingToken": 2}, active=True)
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.run_replay(resume=True, approved_retry=True,
                                        authority={"capability": "new", "fencingToken": 2}), 0)

    def test_principal_target_snapshot_or_content_change_refuses_history_reuse(self):
        self.run_replay()
        self.server.set_grant("target", "svc:other", True)
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True, principal="svc:other")
        for field, value in (("target_mission_id", "other-target"), ("snapshot_sha256", "b" * 64)):
            manifest = copy.deepcopy(self.manifest)
            manifest["projects"][0][field] = value
            with self.assertRaises(RecoveryError):
                self.run_replay(resume=True, approved_retry=True, manifest=manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest["projects"][0]["batches"][0]["items"][0]["body"]["intent"] = "changed"
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True, manifest=manifest)
        self.assertEqual(len(self.server.inventory("target", "work_add")), 3)

    def test_coherent_entry_key_verb_payload_and_id_corruption_refused_before_send(self):
        self.run_replay()
        original = self.receipt()
        for field, value in (("operation_key", "wrong"), ("kind", "work_ask"),
                             ("request", {"items": []}), ("destination_ids", ["forged", "forged"])):
            data = copy.deepcopy(original)
            data["entries"][0][field] = value
            self.rewrite(data)
            before = self.destination.read_bytes()
            with self.assertRaises(RecoveryError):
                self.run_replay(resume=True, approved_retry=True)
            self.assertEqual(self.destination.read_bytes(), before)
            self.rewrite(original)

    def test_legacy_receipt_and_server_cannot_enter_keyed_mode(self):
        from replay_recovery import FakeWorkServer, replay
        legacy = FakeWorkServer({("navlun", "target")})
        self.assertEqual(replay(self.manifest, self.path, legacy), 0)
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True)
        with self.assertRaises(RecoveryError):
            self.m.replay_keyed(self.manifest, self.root / "new.json", legacy,
                                principal=PRINCIPAL, authority=AUTHORITY)

    def test_destination_corruption_is_not_permission_to_create(self):
        first = self.call()
        self.destination.write_bytes(b'{"partial":')
        with self.assertRaises(RecoveryError):
            self.call()
        self.assertEqual(first["status"], 201)
        self.assertEqual(self.destination.read_bytes(), b'{"partial":')

    def test_receipt_symlink_permissions_and_checksum_refused(self):
        self.run_replay()
        raw = self.path.read_bytes()
        self.path.chmod(0o644)
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True)
        self.path.chmod(0o600)
        self.path.write_bytes(raw.replace(b'"sha256":"', b'"sha256":"0', 1))
        with self.assertRaises(RecoveryError):
            self.run_replay(resume=True, approved_retry=True)
        self.path.write_bytes(raw)
        link = self.root / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(RecoveryError):
            self.m.replay_keyed(self.manifest, link, self.server, principal=PRINCIPAL,
                                authority=AUTHORITY, resume=True, approved_retry=True)

    def test_returned_ids_cannot_alias_an_earlier_acknowledged_batch(self):
        original = self.server.call
        # Capture returned IDs without reopening the locked client receipt.
        roots = []
        def alias_without_read(mission, principal, authority, kind, key, body):
            result = original(mission, principal, authority, kind, key, body)
            if kind == "work_add":
                if not roots:
                    roots.extend(result["body"]["workItemIds"])
                else:
                    result["body"]["workItemIds"] = [roots[0]]
            return result
        with patch.object(self.server, "call", alias_without_read):
            self.assertEqual(self.run_replay(), 3)
        self.assertEqual(self.receipt()["entries"][1]["state"], "unresolved")
        self.assertEqual(self.server.inventory("target", "work_ask"), {})
        self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)

    def test_destination_publication_failures_leave_no_partial_mutation_or_recover_exact_commit(self):
        save = ReceiptFile.save
        for after in (False, True):
            with self.subTest(after=after):
                self.path = self.root / f"fault-client-{after}.json"
                self.destination = self.root / f"fault-server-{after}.json"
                self.server = self.m.KeyedFakeServer.create(self.destination, ["target"], PRINCIPAL, AUTHORITY)
                def fail(file, state):
                    if file.path == self.destination:
                        if after:
                            save(file, state)
                        raise OSError()
                    return save(file, state)
                with patch.object(ReceiptFile, "save", fail):
                    self.assertEqual(self.run_replay(), 3)
                self.assertEqual(len(self.server.inventory("target", "work_add")), 2 if after else 0)
                self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
                self.assertEqual(len(self.server.inventory("target", "work_add")), 3)

    def test_current_admission_is_rechecked_after_preflight_and_question_replays_need_live_lease(self):
        original = self.server.call
        def revoke(mission, principal, authority, kind, key, body):
            self.server.set_grant(mission, principal, False)
            return original(mission, principal, authority, kind, key, body)
        with patch.object(self.server, "call", revoke):
            self.assertEqual(self.run_replay(), 3)
        self.assertEqual(self.server.inventory("target", "work_add"), {})
        self.server.set_grant("target", PRINCIPAL, True)
        self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
        entry = self.receipt()["entries"][2]
        first = self.call(body=entry["request"], kind="work_ask", key=entry["operation_key"])
        current = {"capability": "rotated", "fencingToken": 2}
        self.server.set_lease("target", current, active=True)
        self.assertEqual(self.call(body=entry["request"], kind="work_ask", key=entry["operation_key"], authority=current), first)
        self.assertEqual(self.call(body=entry["request"], kind="work_ask", key=entry["operation_key"])["status"], 403)
        self.server.set_grant("target", PRINCIPAL, False)
        self.assertEqual(self.call(body=entry["request"], kind="work_ask", key=entry["operation_key"], authority=current)["status"], 403)

    def test_unreadable_committed_server_result_is_not_a_missing_receipt(self):
        self.call()
        with ReceiptFile(self.destination, resume=True) as file:
            state = file.load()
            state["missions"]["target"]["receipts"][0]["result"] = {"questionId": "wrong-verb"}
            file.save(state)
        before = self.destination.read_bytes()
        with self.assertRaises(RecoveryError):
            self.call()
        self.assertEqual(self.destination.read_bytes(), before)

    def test_actual_client_process_exit_at_send_commit_and_ack_boundaries(self):
        code = '''import os, sys
sys.path.insert(0, sys.argv[1])
from replay_keyed import KeyedFakeServer, replay_keyed
from replay_recovery import ReceiptFile
from synthetic_recovery import synthetic_manifest
path, destination, moment = sys.argv[2:]
server = KeyedFakeServer(destination)
save, call = ReceiptFile.save, server.call
if moment == "after_commit":
 def interrupted(*args):
  call(*args)
  os._exit(47)
 server.call = interrupted
else:
 def interrupted(file, data):
  save(file, data)
  if str(file.path) == path and data["entries"][0]["state"] == ("in_flight" if moment == "before_send" else "acknowledged"):
   os._exit(47)
 ReceiptFile.save = interrupted
replay_keyed(synthetic_manifest(), path, server, principal="svc:synthetic",
 authority={"capability":"synthetic-cap-1","fencingToken":1})
'''
        for moment in ("before_send", "after_commit", "after_ack"):
            with self.subTest(moment=moment):
                self.path = self.root / ("process-" + moment + ".json")
                destination = self.root / ("process-server-" + moment + ".json")
                self.server = self.m.KeyedFakeServer.create(destination, ["target"], PRINCIPAL, AUTHORITY)
                result = subprocess.run([sys.executable, "-B", "-c", code, str(BASE), str(self.path),
                                         str(destination), moment], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 47)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")
                committed = list(self.server.inventory("target", "work_add"))
                self.assertEqual(len(committed), 0 if moment == "before_send" else 2)
                self.server = self.m.KeyedFakeServer(destination)
                self.assertEqual(self.run_replay(resume=True, approved_retry=True), 0)
                if committed:
                    self.assertEqual(set(self.receipt()["entries"][0]["destination_ids"]), set(committed))
                self.assertEqual(len(self.server.inventory("target", "work_add")), 3)
                self.assertEqual(len(self.server.inventory("target", "work_ask")), 1)

    def test_fresh_client_process_reopens_same_durable_destination(self):
        self.run_replay()
        before = self.receipt()
        code = '''import sys
sys.path.insert(0, sys.argv[1])
from replay_keyed import KeyedFakeServer, replay_keyed
from synthetic_recovery import synthetic_manifest
result = replay_keyed(synthetic_manifest(), sys.argv[2], KeyedFakeServer(sys.argv[3]),
 principal="svc:synthetic", authority={"capability":"synthetic-cap-1","fencingToken":1},
 resume=True, approved_retry=True)
raise SystemExit(result)
'''
        result = subprocess.run([sys.executable, "-B", "-c", code, str(BASE), str(self.path), str(self.destination)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.receipt(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
