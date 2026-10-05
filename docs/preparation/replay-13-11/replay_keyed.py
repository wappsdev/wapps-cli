"""OFFLINE keyed preparation model, not a Worker, adapter or migration executor.

Result-on-retry follows inspected Rust sources, NOT a deployed-service assertion.
The legacy/no-server-key model remains separate and fail-closed. Only synthetic
private JSON destinations are supported; there is no transport or store discovery.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import uuid

from replay_recovery import (ReceiptFile, RecoveryError, digest, mapping_key,
                             operations, request_for, require, valid_ids)

KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
JS_SPACE = "\u0009\u000a\u000b\u000c\u000d   " + "".join(
    chr(i) for i in range(0x2000, 0x200b)) + "    　﻿"


def trimmed(value, limit):
    require(isinstance(value, str), "invalid_body")
    value = value.strip(JS_SPACE)
    try:
        size = len(value.encode("utf-16-le")) // 2
    except UnicodeError:
        raise RecoveryError("invalid_body") from None
    require(1 <= size <= limit, "invalid_body")
    return value


def validate_authority(authority):
    require(isinstance(authority, dict) and set(authority) == {"capability", "fencingToken"}, "invalid_authority")
    capability, token = authority["capability"], authority["fencingToken"]
    require(isinstance(capability, str) and len(capability) >= 1, "invalid_authority")
    require(type(token) in (int, float) and 1 <= token <= 9007199254740991
            and int(token) == token, "invalid_authority")


def semantic(kind, body):
    """Mirror normalized typed v1 values, not arbitrary JSON serialization.

    Dict insertion order here is NewWorkItem's serde field order. Optional
    omissions serialize to null. Ask's typed tuple serializes as an array.
    The HTTP reader rejects empty proposal before handler empty filtering.
    """
    require(isinstance(body, dict), "invalid_body")
    if kind == "work_add":
        require(set(body) == {"items"} and isinstance(body["items"], list)
                and 1 <= len(body["items"]) <= 500, "invalid_body")
        result = []
        for row in body["items"]:
            require(isinstance(row, dict) and {"title", "intent"} <= row.keys()
                    and row.keys() <= {"title", "intent", "parentId", "horizon", "discoveredFrom"}, "invalid_body")
            item = {"title": trimmed(row["title"], 500), "intent": trimmed(row["intent"], 100000)}
            for name in ("parentId", "horizon", "discoveredFrom"):
                if name == "horizon":
                    if name in row:
                        require(isinstance(row[name], str) and row[name] in {"now", "next", "later", "someday"}, "invalid_body")
                    item[name] = row.get(name)
                else:
                    item[name] = trimmed(row[name], 128) if name in row else None
            result.append(item)
        return result
    require(kind == "work_ask" and {"workItemId", "question"} <= body.keys()
            and body.keys() <= {"workItemId", "question", "proposal"}, "invalid_body")
    return [trimmed(body["workItemId"], 128), trimmed(body["question"], 4000),
            trimmed(body["proposal"], 4000) if "proposal" in body else None]


def semantic_fingerprint(value):
    # serde_json UTF-8, compact JSON; field order is supplied by semantic().
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def keyed_operations(manifest):
    result = []
    for op in operations(manifest):
        scope = op["scope"]
        identity = {"version": 1, "project": scope["project"],
                    "source_mission_id": scope["source_mission_id"],
                    "target_mission_id": scope["target_mission_id"],
                    "kind": op["kind"], "source_ids": op["source_ids"]}
        # Snapshot/content are journal bindings, not key identity. Changed text
        # must never silently mint a different key for the same operation.
        result.append({**op, "operation_key": "od10k1-" + digest(identity)})
    require(len({o["operation_key"] for o in result}) == len(result), "duplicate_operation_key")
    return result


def refusal(status, code):
    return {"status": status, "body": {"error": code.upper(), "details": {"refusal": code}, "retryable": False}}


class KeyedFakeServer:
    """Durable synthetic destination using private atomic JSON snapshots.

    The synthetic caller argument stands for router-vouched Access identity,
    not a public body field. Per-mission admission and current lease checks are
    modeled; no Access verification, alarm or real lease clock exists here.
    One exclusive destination lock serializes mutation + receipt publication.
    Storage mechanism/IDs are synthetic, not production SQLite/crypto UUIDs.
    """

    def __init__(self, path):
        self.path = Path(path)

    @classmethod
    def create(cls, path, missions, principal, authority):
        require(missions and len(missions) == len(set(missions)), "invalid_fake_scope")
        state = {"format": "od10-keyed-destination-v1", "fake_only": True, "missions": {
            mission: {"items": {}, "questions": {}, "receipts": [], "sequence": 0,
                      "authority": deepcopy(authority), "active": True,
                      "grants": {principal: True}, "touches": 0} for mission in missions}}
        with ReceiptFile(path, resume=False) as file:
            file.save(state)
        return cls(path)

    @staticmethod
    def _load(file):
        state = file.load()
        require(isinstance(state, dict) and set(state) == {"format", "fake_only", "missions"}
                and state["format"] == "od10-keyed-destination-v1" and state["fake_only"] is True
                and isinstance(state["missions"], dict), "invalid_fake_destination")
        for row in state["missions"].values():
            require(isinstance(row, dict) and set(row) == {
                "items", "questions", "receipts", "sequence", "authority", "active", "grants", "touches"},
                "invalid_fake_destination")
            require(isinstance(row["items"], dict) and isinstance(row["questions"], dict)
                    and isinstance(row["receipts"], list) and isinstance(row["grants"], dict)
                    and type(row["active"]) is bool and type(row["sequence"]) is int
                    and row["sequence"] >= 0 and type(row["touches"]) is int and row["touches"] >= 0,
                    "invalid_fake_destination")
            scopes = set()
            for entry in row["receipts"]:
                require(isinstance(entry, dict) and set(entry) == {"principal", "kind", "key", "fingerprint", "result"},
                        "invalid_fake_destination")
                require(isinstance(entry["principal"], str) and entry["kind"] in {"work_add", "work_ask"}
                        and isinstance(entry["key"], str) and KEY_PATTERN.fullmatch(entry["key"])
                        and isinstance(entry["fingerprint"], str)
                        and re.fullmatch(r"[0-9a-f]{64}", entry["fingerprint"]), "invalid_fake_destination")
                scope = (entry["principal"], entry["kind"], entry["key"])
                require(scope not in scopes, "invalid_fake_destination")
                scopes.add(scope)
                result_ids(entry["kind"], {"status": 201, "body": entry["result"]})
        return state

    @staticmethod
    def _authorise(state, mission, principal, authority):
        require(mission in state["missions"], "destination_mission_mismatch")
        row = state["missions"][mission]
        require(row["grants"].get(principal) is True, "grant_revoked")
        require(row["active"] is True, "lease_expired")
        validate_authority(authority)
        require(authority["fencingToken"] == row["authority"]["fencingToken"], "stale_fencing_token")
        require(authority["capability"] == row["authority"]["capability"], "wrong_capability")
        return row

    def authorise(self, mission, principal, authority):
        with ReceiptFile(self.path, resume=True) as file:
            self._authorise(self._load(file), mission, principal, authority)

    def inventory(self, mission, kind):
        # Inspection is only a test utility, never a replay reconciliation facility.
        with ReceiptFile(self.path, resume=True) as file:
            state = self._load(file)
            return deepcopy(state["missions"][mission]["items" if kind == "work_add" else "questions"])

    def _edit(self, mission, change):
        with ReceiptFile(self.path, resume=True) as file:
            state = self._load(file)
            change(state["missions"][mission])
            file.save(state)

    def set_grant(self, mission, principal, allowed):
        def change(row):
            row["grants"][principal] = allowed
        self._edit(mission, change)

    def set_lease(self, mission, authority, *, active):
        self._edit(mission, lambda row: row.update(authority=deepcopy(authority), active=active))

    def close_item(self, mission, item_id):
        self._edit(mission, lambda row: row["items"][item_id].update(closed=True))

    def call(self, mission, principal, authority, kind, key, body):
        try:
            require(isinstance(key, str) and KEY_PATTERN.fullmatch(key), "invalid_body")
            validate_authority(authority)
            value = semantic(kind, body)
        except RecoveryError:
            return refusal(400, "invalid_body")
        fingerprint = semantic_fingerprint(value)
        with ReceiptFile(self.path, resume=True) as file:
            state = self._load(file)
            try:
                row = self._authorise(state, mission, principal, authority)
            except RecoveryError as error:
                return refusal(403, str(error))
            # Current grant and lease MUST precede receipt decision.
            for entry in row["receipts"]:
                if (entry["principal"], entry["kind"], entry["key"]) == (principal, kind, key):
                    if entry["fingerprint"] != fingerprint:
                        return refusal(409, "operation_key_conflict")
                    row["touches"] += 1
                    file.save(state)
                    return {"status": 201, "body": deepcopy(entry["result"])}
            if kind == "work_add":
                for item in value:
                    parent = item["parentId"]
                    if parent is not None:
                        if parent not in row["items"]:
                            return refusal(409, "unknown_parent")
                        if row["items"][parent]["closed"]:
                            return refusal(409, "parent_closed")
                        if item["horizon"] is not None:
                            return refusal(409, "child_horizon")
                    if item["discoveredFrom"] is not None and item["discoveredFrom"] not in row["items"]:
                        return refusal(409, "unknown_discovery")
                ids = []
                for item in value:
                    row["sequence"] += 1
                    item_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"synthetic:{mission}:item:{row['sequence']}"))
                    row["items"][item_id] = {**item, "closed": False}
                    ids.append(item_id)
                result = {"workItemIds": ids}
            else:
                work_id, question, proposal = value
                if work_id not in row["items"]:
                    return refusal(409, "question_item_unknown")
                if row["items"][work_id]["closed"]:
                    return refusal(409, "question_item_closed")
                row["sequence"] += 1
                question_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"synthetic:{mission}:question:{row['sequence']}"))
                row["questions"][question_id] = {"workItemId": work_id, "question": question, "proposal": proposal}
                result = {"questionId": question_id}
            row["receipts"].append({"principal": principal, "kind": kind, "key": key,
                                     "fingerprint": fingerprint, "result": result})
            row["touches"] += 1
            file.save(state)  # Mutation + receipt + touch in ONE durable publication.
            return {"status": 201, "body": deepcopy(result)}


def result_ids(kind, response):
    require(isinstance(response, dict) and set(response) == {"status", "body"}
            and response["status"] == 201 and isinstance(response["body"], dict), "invalid_ack")
    body = response["body"]
    require(set(body) == ({"workItemIds"} if kind == "work_add" else {"questionId"}), "invalid_ack")
    ids = body["workItemIds"] if kind == "work_add" else [body["questionId"]]
    require(valid_ids(ids) and len(ids) >= 1, "invalid_ack")
    return ids


def initial_receipt(manifest, principal, ops):
    return {"format": "od10-keyed-fake-receipt-v1", "fake_only": True,
            "manifest_sha256": digest(manifest), "principal": principal, "entries": [
                {"operation_key": op["operation_key"], "kind": op["kind"], "state": "pending",
                 "request": None, "request_sha256": None, "destination_ids": [], "reason": None}
                for op in ops]}


def validate_keyed_receipt(receipt, manifest, principal, ops):
    require(isinstance(receipt, dict) and set(receipt) == {"format", "fake_only", "manifest_sha256", "principal", "entries"})
    require(receipt["format"] == "od10-keyed-fake-receipt-v1" and receipt["fake_only"] is True)
    require(receipt["principal"] == principal, "principal_changed")
    require(receipt["manifest_sha256"] == digest(manifest), "manifest_changed")
    require(isinstance(receipt["entries"], list) and len(receipt["entries"]) == len(ops))
    mappings, used, stopped = {}, set(), False
    for op, entry in zip(ops, receipt["entries"]):
        require(isinstance(entry, dict) and set(entry) == {
            "operation_key", "kind", "state", "request", "request_sha256", "destination_ids", "reason"})
        require(entry["operation_key"] == op["operation_key"] and entry["kind"] == op["kind"])
        state = entry["state"]
        require(isinstance(state, str) and state in {"pending", "in_flight", "acknowledged", "unresolved"})
        require(valid_ids(entry["destination_ids"]))
        if state == "pending":
            require(entry["request"] is None and entry["request_sha256"] is None
                    and entry["destination_ids"] == [] and entry["reason"] is None)
            stopped = True
            continue
        require(not stopped, "invalid_operation_order")
        request = request_for(op, mappings)
        require(entry["request"] == request and entry["request_sha256"] == digest(request))
        semantic(op["kind"], request)
        if state == "acknowledged":
            require(entry["reason"] is None and len(entry["destination_ids"]) == len(op["records"]))
            for source, destination in zip(op["source_ids"], entry["destination_ids"]):
                identity = (op["scope"]["target_mission_id"], op["kind"], destination)
                require(identity not in used, "duplicate_destination_id")
                used.add(identity)
                if op["kind"] == "work_add":
                    mappings[mapping_key(op, source)] = destination
        else:
            require(entry["destination_ids"] == [] and entry["reason"] == (
                None if state == "in_flight" else "outcome_not_proven"))
            stopped = True
    return mappings


def replay_keyed(manifest, path, server, *, principal, authority, resume=False, approved_retry=False):
    """0 synthetic reconciled, 3 stopped, exceptions fail closed.

    approved_retry is ONLY synthetic test orchestration, never human consent or
    permission for live replay. No retry loop or inventory-based adoption exists.
    Resume validates the full journal BEFORE any operation, including stale IDs.
    Every acknowledged entry is confirmed by the SAME authenticated keyed call;
    local completion is not a bypass of current admission/lease or server receipts.
    """
    require(isinstance(server, KeyedFakeServer), "keyed_fake_server_required")
    require(isinstance(principal, str) and re.fullmatch(r"(?:human|svc):[^\s,]+", principal), "invalid_principal")
    require(Path(path).absolute() != server.path.absolute(), "receipt_destination_alias")
    ops = keyed_operations(manifest)
    with ReceiptFile(path, resume=resume) as journal:
        receipt = journal.load() if resume else initial_receipt(manifest, principal, ops)
        validate_keyed_receipt(receipt, manifest, principal, ops)
        # Even an entirely acknowledged journal must pass CURRENT authority.
        for project in manifest["projects"]:
            server.authorise(project["target_mission_id"], principal, authority)
        if resume and approved_retry is not True and any(e["state"] != "pending" for e in receipt["entries"]):
            return 3
        if not resume:
            journal.save(receipt)
        mappings, used = {}, set()
        for op, entry in zip(ops, receipt["entries"]):
            request = request_for(op, mappings)
            semantic(op["kind"], request)
            acknowledged = entry["state"] == "acknowledged"
            if entry["state"] == "pending":
                entry.update(state="in_flight", request=deepcopy(request), request_sha256=digest(request))
                journal.save(receipt)  # Never call unless exact intent is durable.
            try:
                response = server.call(op["scope"]["target_mission_id"], principal, authority,
                                       op["kind"], entry["operation_key"], deepcopy(entry["request"]))
                ids = result_ids(op["kind"], response)
                require(len(ids) == len(op["records"]), "invalid_ack")
                identities = {(op["scope"]["target_mission_id"], op["kind"], id) for id in ids}
                require(not used.intersection(identities), "duplicate_destination_id")
                if acknowledged:
                    require(ids == entry["destination_ids"], "original_result_changed")
                else:
                    entry.update(state="acknowledged", destination_ids=ids, reason=None)
                    journal.save(receipt)
            except Exception:
                if not acknowledged:
                    entry.update(state="unresolved", destination_ids=[], reason="outcome_not_proven")
                    journal.save(receipt)
                return 3
            used.update(identities)
            for source, destination in zip(op["source_ids"], ids):
                if op["kind"] == "work_add":
                    mappings[mapping_key(op, source)] = destination
        return 0
