"""Canned synthetic data and fault injection shared by the demo and tests."""
from copy import deepcopy

from replay_recovery import FakeWorkServer


def synthetic_manifest():
    """Minimal planner-shaped fixture; identical titles deliberately aren't identity."""
    items = [dict(source_id=s, parent_source_id=None,
                  body=dict(title="Same synthetic title", intent="Synthetic intent", horizon="next"))
             for s in ("root-a", "root-b")]
    child = dict(source_id="child", parent_source_id="root-a",
                 body=dict(title="Synthetic child", intent="Child intent"))
    return dict(format="od10-offline-replay-v1", status="ready_for_review", issues=[],
                nothing_migrated=True, live_replay_safe=False, projects=[dict(
                    project="navlun", source_mission_id="source", target_mission_id="target",
                    snapshot_sha256="a" * 64, approved_lossy_transformations=[],
                    batches=[dict(items=items, source_ids=["root-a", "root-b"]),
                             dict(items=[child], source_ids=["child"])],
                    questions=[dict(source_id="q", work_item_source_id="child",
                                    body=dict(question="Synthetic question?", proposal="Proposal"))])])


class LostResponse(FakeWorkServer):
    def add(self, scope, body):
        super().add(scope, body)
        raise TimeoutError()


class RejectedBatch(FakeWorkServer):
    def add(self, scope, body):
        changed = deepcopy(body)
        changed["items"][-1]["parentId"] = "absent-parent"
        return super().add(scope, changed)
