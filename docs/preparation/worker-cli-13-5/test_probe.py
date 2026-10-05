"""Synthetic executable tests for the safe help/version probe; no installed CLI."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("probe.py")


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "curated safe probe is not implemented")
        spec = importlib.util.spec_from_file_location("safe_probe", SCRIPT)
        self.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.probe)
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-probe-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.binary = self.root / "fake-cli"
        self.binary.write_text('#!/bin/sh\ncase "$*" in\n*--version) echo "0.0.0 (Synthetic CLI)";;\n*--help) echo "--effort --agent --agents --tools";;\n*) exit 91;;\nesac\n')
        self.binary.chmod(0o700)
        self.output = self.root / "evidence.json"

    def run_probe(self):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "--binary", str(self.binary),
                               "--output", str(self.output)], capture_output=True, text=True,
                              timeout=30)

    def test_all_cases_are_help_or_version_and_capture_individual_exits(self):
        result = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(len(evidence["commands"]), 7)
        self.assertTrue(all(row["exit_code"] == 0 for row in evidence["commands"]))
        self.assertTrue(all(row["argv"][-1] in ("--help", "--version") for row in evidence["commands"]))
        self.assertFalse(evidence["runtime_verified"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_existing_output_is_not_overwritten(self):
        self.output.write_bytes(b"synthetic sentinel")
        result = self.run_probe()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.output.read_bytes(), b"synthetic sentinel")

    def test_public_output_directory_is_refused(self):
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        self.output = public / "evidence.json"
        self.assertEqual(self.run_probe().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_probe_child_never_inherits_parent_secret_or_configuration(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        env = self.probe.child_environment(scratch)
        self.assertEqual(set(env), {"PATH", "HOME", "CLAUDE_CONFIG_DIR", "TMPDIR",
                                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_AUTOUPDATER"})
        self.assertTrue(all(Path(env[key]).is_relative_to(scratch)
                            for key in ("HOME", "CLAUDE_CONFIG_DIR", "TMPDIR")))

    def test_non_help_case_is_rejected_before_spawn(self):
        with self.assertRaises(ValueError):
            self.probe.run_case(self.binary, ["-p", "Synthetic task"], self.root, {})

    def test_raw_output_and_binary_paths_are_not_published(self):
        self.binary.write_text('#!/bin/sh\necho "SYNTHETIC_PRIVATE_OUTPUT" >&2\necho "--effort SYNTHETIC_PRIVATE_OUTPUT"\nexit 7\n')
        result = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = self.output.read_text()
        self.assertNotIn("SYNTHETIC_PRIVATE_OUTPUT", raw)
        self.assertNotIn(str(self.root), raw)
        self.assertTrue(all(row["exit_code"] == 7 for row in json.loads(raw)["commands"]))


if __name__ == "__main__":
    unittest.main()
