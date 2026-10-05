#!/usr/bin/env python3
"""Verify this Git-indexed preparation inventory in a private synthetic home.

Does not stage files or run installed CLIs. Unstaged differences refuse execution.
All executed Python sources are extracted from the index, not copied from dirty files.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "docs/preparation/"
REPLAY = PREFIX + "replay-13-11/"
WORKER = PREFIX + "worker-cli-13-5/"
REQUIRED = {REPLAY + name for name in (
    "replay_plan.py", "replay_recovery.py", "replay_keyed.py", "synthetic_recovery.py",
    "recovery_demo.py", "test_replay.py", "test_recovery.py", "test_keyed.py")}
REQUIRED.update({WORKER + "probe.py", WORKER + "test_probe.py", PREFIX + "verify.py"})


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, check=True).stdout


def main():
    inventory = {}
    try:
        for entry in git("ls-files", "--stage", "-z", "--", PREFIX).split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, oid, stage = metadata.split()
            path = raw_path.decode()
            if stage != b"0" or mode not in (b"100644", b"100755"):
                raise ValueError("nonregular_or_unmerged_inventory")
            raw = git("cat-file", "blob", oid.decode())
            local = ROOT / path
            if local.is_symlink() or local.read_bytes() != raw:
                raise ValueError("unstaged_preparation_difference")
            inventory[path] = raw
        if not REQUIRED <= inventory.keys():
            raise ValueError("missing_indexed_inventory")
        fingerprint = hashlib.sha256(json.dumps(
            {path: hashlib.sha256(raw).hexdigest() for path, raw in sorted(inventory.items())},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="broker-preparation-") as temporary:
            scratch = Path(temporary)
            env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"),
                   "TMPDIR": str(scratch / "tmp"), "CLAUDE_CONFIG_DIR": str(scratch / "config"),
                   "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1"}
            for name in ("home", "tmp", "config"):
                (scratch / name).mkdir(mode=0o700)
            for path, raw in inventory.items():
                destination = scratch / path
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                destination.write_bytes(raw)
            base, worker = scratch / REPLAY, scratch / WORKER
            gates = [("planner", [str(base / "test_replay.py")], 0),
                     ("legacy", [str(base / "test_recovery.py")], 0),
                     ("keyed", [str(base / "test_keyed.py")], 0),
                     ("replay_98", ["-m", "unittest", "discover", "-s", str(base), "-p", "test_*.py"], 0),
                     ("safe_probe", [str(worker / "test_probe.py")], 0)]
            for scenario, expected in (("success", 0), ("response-loss", 3), ("failed-batch", 3)):
                gates.append(("demo_" + scenario, [str(base / "recovery_demo.py"), "--scenario", scenario,
                              "--receipt", str(scratch / (scenario + ".json"))], expected))
            passed = True
            for name, args, expected in gates:
                # Capture the child return code itself, never a pipeline's status.
                child = subprocess.run([sys.executable, "-B", *args], cwd=scratch, env=env,
                                       capture_output=True, text=True, timeout=120)
                print(json.dumps({"gate": name, "exit_code": child.returncode, "expected": expected,
                                  "inventory_sha256": fingerprint}), flush=True)
                if child.returncode != expected:
                    passed = False
                    print(child.stderr, file=sys.stderr)
            return 0 if passed else 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("preparation_verify: indexed_source_or_execution_failure", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
