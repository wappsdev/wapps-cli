#!/usr/bin/env python3
"""Help/version only. Explicit binary, private new output, no native source excerpts.

A zero probe exit means evidence was recorded, not that the CLI cases passed or
that main-thread skills, effort, hooks or cancellation are verified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

FLAGS = ("--agent", "--agents", "--effort", "--model", "--tools", "--allowedTools",
         "--disallowedTools", "--settings", "--setting-sources", "--strict-mcp-config",
         "--input-format", "--output-format", "--include-hook-events", "--bare")


def child_environment(scratch):
    for name in ("home", "config", "tmp", "project"):
        (scratch / name).mkdir(mode=0o700)
    return {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"),
            "CLAUDE_CONFIG_DIR": str(scratch / "config"), "TMPDIR": str(scratch / "tmp"),
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"}


def run_case(binary, args, cwd, env):
    if not args or args[-1] not in ("--help", "--version") or any(
            value in args for value in ("-p", "--print", "--resume", "--continue")):
        raise ValueError("help_or_version_required")
    try:
        result = subprocess.run([str(binary), *args], env=env, cwd=cwd,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "timeout_seconds": 20}
    version = re.fullmatch(r"\d+\.\d+\.\d+ \(Claude Code\)", result.stdout.strip())
    return {"exit_code": result.returncode,
            "version": version.group(0) if version and args == ["--version"] else None,
            "documented_flags_in_help": [flag for flag in FLAGS if re.search(
                r"(?<!\S)" + re.escape(flag) + r"(?=[\s,=]|$)", result.stdout)],
            "invalid_effort_warning": "ignored" in result.stderr and "effort" in result.stderr,
            "stdout_present": bool(result.stdout), "stderr_present": bool(result.stderr)}


def collect(binary, scratch):
    env = child_environment(scratch)
    agent = {"synthetic-worker": {"description": "Synthetic fixture", "prompt": "Synthetic fixture",
                                 "effort": "high", "tools": ["Read"], "skills": ["synthetic-contract"]}}
    cases = {
        "version": ["--version"], "help": ["--help"],
        "role_flags_help_only": ["--agents", json.dumps(agent), "--agent", "synthetic-worker",
                                 "--effort", "high", "--tools", "Read", "--setting-sources=",
                                 "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--help"],
        "invalid_agents_help_short_circuit": ["--agents", "NOT_JSON", "--help"],
        "invalid_effort_help_only": ["--effort", "definitely-invalid", "--help"],
        "skills_switch_help_only": ["--skills", "synthetic-contract", "--help"],
        "event_flags_help_only": ["--input-format", "stream-json", "--output-format", "stream-json",
                                  "--verbose", "--include-hook-events", "--include-partial-messages", "--help"],
    }
    with binary.open("rb") as file:
        fingerprint = hashlib.file_digest(file, "sha256").hexdigest()
    return {"format": "worker-cli-offline-probe-v1", "binary_sha256": fingerprint,
            "no_model_execution": True, "runtime_verified": False,
            "proof_limit": "Help short-circuits startup; inspect each case exit separately.",
            "commands": [{"case": name, "argv": args, **run_case(binary, args, scratch / "project", env)}
                         for name, args in cases.items()]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.binary.is_absolute() or not args.output.is_absolute():
            raise ValueError("absolute_paths_required")
        parent = args.output.parent
        info = parent.stat()
        if not parent.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("private_output_directory_required")
        # Reserve output BEFORE any child is started. Never overwrite prior evidence.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            os.fchmod(file.fileno(), 0o600)
            with tempfile.TemporaryDirectory(prefix="synthetic-probe-", dir=parent) as temporary:
                evidence = collect(args.binary, Path(temporary))
            json.dump(evidence, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        print(json.dumps({"recorded": True, "runtime_verified": False,
                          "exit_codes": [{"case": row["case"], "exit_code": row["exit_code"]}
                                         for row in evidence["commands"]]}))
        return 0
    except (OSError, ValueError, UnicodeError):
        print("worker_cli_probe: input_or_output_failure", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
