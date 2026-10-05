"""OFFLINE receipt/reconciliation model. Only FakeWorkServer, never a live adapter.

No database, credential, HTTP, MCP, or arbitrary-manifest CLI input exists here.
Legacy operation identities stay local: this model deliberately uses no server key.
The later merged keyed source contract is modeled separately in replay_keyed.py.
"""
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from replay_plan import MISSION_ID, PROJECTS, encoded


class RecoveryError(Exception):
    """Fixed diagnostic codes only; callers must not print raw I/O exceptions."""


def require(condition, code="invalid_receipt"):
    if not condition:
        raise RecoveryError(code)


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


class ReceiptFile:
    """One private receipt, exclusive nonblocking writer, atomic durable snapshots.

    Keep the lock inode forever: unlinking it could let two writers lock different
    inodes. New data is fsynced before link/replace, then the directory is fsynced.
    Resume is explicit and never creates, repairs, or truncates a missing receipt.
    """

    def __init__(self, path, *, resume):
        self.path = Path(path)
        self.resume = resume
        self.directory = self.lock = None
        self.previous = None

    @staticmethod
    def _private(fd, directory=False):
        info = os.fstat(fd)
        require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and info.st_uid == os.getuid() and not info.st_mode & 0o077
                and (directory or info.st_nlink == 1), "unsafe_receipt_file")

    def __enter__(self):
        try:
            require(self.path.name not in {"", ".", ".."}, "invalid_receipt_path")
            self.directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._private(self.directory, directory=True)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                self.lock = os.open(self.path.name + ".lock", flags | os.O_CREAT | os.O_EXCL,
                                    0o600, dir_fd=self.directory)
            except FileExistsError:
                self.lock = os.open(self.path.name + ".lock", flags, dir_fd=self.directory)
            self._private(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.resume:
                self.previous = self._read()
            else:
                try:
                    os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RecoveryError("receipt_already_exists")
            return self
        except (OSError, RecoveryError):
            self.__exit__(None, None, None)
            raise RecoveryError("receipt_open_refused") from None

    def __exit__(self, *unused):
        for name in ("lock", "directory"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def _read(self):
        try:
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=self.directory)
            with os.fdopen(fd, "rb") as file:
                self._private(file.fileno())
                return file.read()
        except OSError:
            raise RecoveryError("receipt_read_refused") from None

    def load(self):
        try:
            raw = self._read()
            require(raw == self.previous, "receipt_changed")
            envelope = json.loads(raw, object_pairs_hook=unique_keys)
            require(isinstance(envelope, dict) and set(envelope) == {"receipt", "sha256"})
            require(envelope["sha256"] == digest(envelope["receipt"]), "receipt_checksum_mismatch")
            return envelope["receipt"]
        except (ValueError, TypeError, UnicodeError):
            raise RecoveryError("receipt_corrupt") from None

    def save(self, receipt):
        self._private(self.directory, directory=True)
        data = encoded({"receipt": receipt, "sha256": digest(receipt)}) + b"\n"
        temporary = "." + self.path.name + "." + uuid.uuid4().hex + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.directory)
        try:
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), 0o600)
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            if self.previous is None:
                # Atomic publication without overwriting ANY existing file.
                os.link(temporary, self.path.name, src_dir_fd=self.directory,
                        dst_dir_fd=self.directory, follow_symlinks=False)
            else:
                require(self._read() == self.previous, "receipt_changed")
                os.replace(temporary, self.path.name, src_dir_fd=self.directory,
                           dst_dir_fd=self.directory)
            if self.previous is None:
                os.unlink(temporary, dir_fd=self.directory)
            os.fsync(self.directory)
            self.previous = data
        finally:
            try:
                os.unlink(temporary, dir_fd=self.directory)
            except FileNotFoundError:
                pass


def operations(manifest):
    """Bind identity to scope + source IDs, never title; fingerprint content separately."""
    try:
        require(manifest["format"] == "od10-offline-replay-v1"
                and manifest["status"] == "ready_for_review" and manifest["issues"] == []
                and manifest["nothing_migrated"] is True and manifest["live_replay_safe"] is False,
                "manifest_not_ready")
        projects, targets, result = set(), set(), []
        require(isinstance(manifest["projects"], list) and 1 <= len(manifest["projects"]) <= 4,
                "invalid_manifest")
        for project in manifest["projects"]:
            name, target = project["project"], project["target_mission_id"]
            require(name in PROJECTS and name not in projects and target not in targets,
                    "invalid_project_mapping")
            projects.add(name)
            targets.add(target)
            require(MISSION_ID.fullmatch(target) and MISSION_ID.fullmatch(project["source_mission_id"]),
                    "invalid_mission_mapping")
            require(re.fullmatch(r"[0-9a-f]{64}", project["snapshot_sha256"]), "invalid_snapshot_digest")
            scope = {k: project[k] for k in ("project", "source_mission_id", "target_mission_id", "snapshot_sha256")}
            seen = set()
            for batch in project["batches"]:
                records = batch["items"]
                ids = [r["source_id"] for r in records]
                require(1 <= len(records) <= 500 and ids == batch["source_ids"]
                        and len(ids) == len(set(ids)) and not seen.intersection(ids), "invalid_batch_identity")
                for row in records:
                    require(isinstance(row["source_id"], str) and row["source_id"], "invalid_source_id")
                    require(row["parent_source_id"] is None or row["parent_source_id"] in seen,
                            "parent_not_in_earlier_batch")
                    require(isinstance(row["body"], dict) and {"title", "intent"} <= row["body"].keys()
                            and row["body"].keys() <= {"title", "intent", "horizon"}, "invalid_item_body")
                result.append(make_operation(scope, "work_add", records))
                seen.update(ids)
            questions = project["questions"]
            require(len(questions) <= (1 if name == "navlun" else 0), "question_outside_scope")
            for question in questions:
                require(isinstance(question["source_id"], str) and question["source_id"]
                        and question["work_item_source_id"] in seen, "invalid_question_reference")
                require(isinstance(question["body"], dict) and "question" in question["body"]
                        and question["body"].keys() <= {"question", "proposal"}, "invalid_question_body")
                result.append(make_operation(scope, "work_ask", [question]))
        return result
    except (KeyError, TypeError, AttributeError, ValueError):
        raise RecoveryError("invalid_manifest") from None


def make_operation(scope, kind, records):
    identity = {"scope": scope, "kind": kind, "source_ids": [r["source_id"] for r in records]}
    return {**identity, "operation_id": digest(identity), "records": deepcopy(records)}


def new_receipt(manifest):
    return {"format": "od10-fake-receipt-v1", "fake_only": True,
            "manifest_sha256": digest(manifest), "entries": [
                {"operation_id": op["operation_id"], "state": "pending", "request": None,
                 "request_sha256": None, "before_ids": [], "destination_ids": [], "reason": None}
                for op in operations(manifest)]}


def scope_of(op):
    return (op["scope"]["project"], op["scope"]["target_mission_id"])


def mapping_key(op, source_id):
    scope = op["scope"]
    return (scope["project"], scope["source_mission_id"], scope["target_mission_id"],
            scope["snapshot_sha256"], source_id)


def request_for(op, mappings):
    bodies = []
    for record in op["records"]:
        body = deepcopy(record["body"])
        reference = record["parent_source_id"] if op["kind"] == "work_add" else record["work_item_source_id"]
        if reference is not None:
            key = mapping_key(op, reference)
            require(key in mappings, "unacknowledged_parent")
            body["parentId" if op["kind"] == "work_add" else "workItemId"] = mappings[key]
        bodies.append(body)
    return {"items": bodies} if op["kind"] == "work_add" else bodies[0]


def valid_ids(ids):
    return isinstance(ids, list) and all(isinstance(i, str) and 0 < len(i) <= 128 for i in ids) and len(ids) == len(set(ids))


def validate_receipt(receipt, manifest, ops):
    require(isinstance(receipt, dict) and set(receipt) == {"format", "fake_only", "manifest_sha256", "entries"})
    require(receipt["format"] == "od10-fake-receipt-v1" and receipt["fake_only"] is True)
    require(receipt["manifest_sha256"] == digest(manifest), "manifest_changed")
    require(isinstance(receipt["entries"], list) and len(receipt["entries"]) == len(ops))
    mappings, used, stopped = {}, set(), False
    pending_keys = {"operation_id", "state", "request", "request_sha256", "before_ids", "destination_ids", "reason"}
    for op, entry in zip(ops, receipt["entries"]):
        require(isinstance(entry, dict) and set(entry) == pending_keys)
        require(entry["operation_id"] == op["operation_id"])
        state = entry["state"]
        require(isinstance(state, str) and state in {"pending", "in_flight", "acknowledged", "unresolved", "failed"})
        require(valid_ids(entry["before_ids"]) and valid_ids(entry["destination_ids"]))
        if state == "pending":
            require(entry["request"] is None and entry["request_sha256"] is None and entry["reason"] is None
                    and entry["before_ids"] == [] and entry["destination_ids"] == [])
            stopped = True
            continue
        require(not stopped, "invalid_operation_order")
        expected = request_for(op, mappings)
        require(entry["request"] == expected and entry["request_sha256"] == digest(expected))
        if state == "acknowledged":
            require(entry["reason"] is None and len(entry["destination_ids"]) == len(op["records"])
                    and not set(entry["before_ids"]).intersection(entry["destination_ids"]))
            for source, destination in zip(op["source_ids"], entry["destination_ids"]):
                key = (*scope_of(op), op["kind"], destination)
                require(key not in used, "duplicate_destination_id")
                used.add(key)
                if op["kind"] == "work_add":
                    mappings[mapping_key(op, source)] = destination
        else:
            require(entry["destination_ids"] == [])
            require(entry["reason"] == {"in_flight": None, "unresolved": "outcome_not_proven",
                                        "failed": "server_refused"}[state])
            stopped = True
    return mappings


class FakeWorkServer:
    """In-memory synthetic destination; no idempotency key or operation lookup.

    Only the relevant creation/parent/batch semantics are modeled. No lease,
    authentication, deployment, timestamps, or real inventory API is simulated.
    Tests inject crashes/loss by subclassing this fake, not by contacting a server.
    """

    def __init__(self, scopes):
        self.items = {scope: {} for scope in scopes}
        self.questions = {scope: {} for scope in scopes}
        self.item_sequence = self.question_sequence = 0

    def inventory(self, scope, kind):
        require(scope in self.items, "destination_mission_mismatch")
        return deepcopy((self.items if kind == "work_add" else self.questions)[scope])

    def add(self, scope, body):
        known = self.inventory(scope, "work_add")
        for item in body["items"]:
            if "parentId" in item and item["parentId"] not in known:
                return {"ok": False, "refusal": "unknown_parent"}
            if "parentId" in item and "horizon" in item:
                return {"ok": False, "refusal": "child_horizon"}
        # Validate the WHOLE batch before committing any member.
        created = []
        for item in body["items"]:
            self.item_sequence += 1
            id = "fake-item-" + str(self.item_sequence)
            self.items[scope][id] = deepcopy(item)
            created.append(id)
        return {"ok": True, "workItemIds": created}

    def ask(self, scope, body):
        if body["workItemId"] not in self.inventory(scope, "work_add"):
            return {"ok": False, "refusal": "question_item_unknown"}
        self.question_sequence += 1
        id = "fake-question-" + str(self.question_sequence)
        self.questions[scope][id] = deepcopy(body)
        return {"ok": True, "questionId": id}


def verify_ack(op, entry, server):
    inventory = server.inventory(scope_of(op), op["kind"])
    request = entry["request"]
    bodies = request["items"] if op["kind"] == "work_add" else [request]
    for id, body in zip(entry["destination_ids"], bodies):
        require(inventory.get(id) == body, "acknowledged_destination_drift")


def replay(manifest, path, server, *, resume=False):
    """Return 0 (fake reconciled) or 3 (stopped); invalid input/I/O must fail closed.

    A durable in_flight entry is an uncertainty boundary, NOT permission to retry.
    Even an empty or uniquely matching inventory cannot prove which caller wrote it.
    """
    require(isinstance(server, FakeWorkServer), "fake_server_required")
    ops = operations(manifest)
    for project in manifest["projects"]:
        require((project["project"], project["target_mission_id"]) in server.items,
                "destination_mission_mismatch")
    with ReceiptFile(path, resume=resume) as journal:
        receipt = journal.load() if resume else new_receipt(manifest)
        mappings = validate_receipt(receipt, manifest, ops)
        for op, entry in zip(ops, receipt["entries"]):
            if entry["state"] == "acknowledged":
                verify_ack(op, entry, server)
        if not resume:
            journal.save(receipt)
        for op, entry in zip(ops, receipt["entries"]):
            if entry["state"] == "acknowledged":
                continue
            if entry["state"] == "in_flight":
                entry.update(state="unresolved", reason="outcome_not_proven")
                journal.save(receipt)
            if entry["state"] in {"unresolved", "failed"}:
                return 3
            body = request_for(op, mappings)
            entry.update(state="in_flight", request=body, request_sha256=digest(body),
                         before_ids=sorted(server.inventory(scope_of(op), op["kind"])))
            journal.save(receipt)  # No send unless the intent is durably published.
            try:
                response = (server.add if op["kind"] == "work_add" else server.ask)(scope_of(op), deepcopy(body))
                if (response.get("ok") is False and response.get("refusal") in
                        {"unknown_parent", "child_horizon", "question_item_unknown"}):
                    entry.update(state="failed", reason="server_refused")
                else:
                    require(response.get("ok") is True, "invalid_ack")
                    ids = response.get("workItemIds") if op["kind"] == "work_add" else [response.get("questionId")]
                    require(valid_ids(ids) and len(ids) == len(op["records"])
                            and not set(ids).intersection(entry["before_ids"]), "invalid_ack")
                    entry.update(state="acknowledged", destination_ids=ids)
                    verify_ack(op, entry, server)
            except Exception:
                # A transport failure, malformed response or failed readback proves
                # neither commit nor rollback. Do NOT infer success by content.
                entry.update(state="unresolved", destination_ids=[], reason="outcome_not_proven")
            journal.save(receipt)
            if entry["state"] != "acknowledged":
                return 3
            for source, destination in zip(op["source_ids"], entry["destination_ids"]):
                if op["kind"] == "work_add":
                    mappings[mapping_key(op, source)] = destination
        return 0
