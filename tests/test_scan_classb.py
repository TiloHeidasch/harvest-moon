#!/usr/bin/env python3
"""Focused, network-free tests for scan-classb.sh."""

import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from tools.run_nmap import Runner


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scan-classb.sh"
PARSER = ROOT / "tools/parse_nmap_xml.py"
POLICY_CHECKER = ROOT / "tools/check_exclusions.py"


MOCK_NMAP = r'''#!/usr/bin/env python3
import fcntl
import json
import os
from pathlib import Path
import signal
import sys
import time

state_path = Path(os.environ["MOCK_STATE"])
state_path.parent.mkdir(parents=True, exist_ok=True)
target = sys.argv[-1].split("/")[0]
parts = target.split(".")
classc = int(parts[2])
mode = os.environ.get("MOCK_MODE", "zero")
delay = float(os.environ.get("MOCK_DELAY", "0.01"))

with state_path.open("a+") as state_file:
    fcntl.flock(state_file, fcntl.LOCK_EX)
    state_file.seek(0)
    try:
        state = json.load(state_file)
    except (json.JSONDecodeError, EOFError):
        state = {"calls": 0, "active": 0, "max_active": 0, "targets": {}, "argv": []}
    state["calls"] += 1
    state["active"] += 1
    state["max_active"] = max(state["max_active"], state["active"])
    state["targets"][target] = state["targets"].get(target, 0) + 1
    target_calls = state["targets"][target]
    if not state["argv"]:
        state["argv"] = sys.argv[1:]
    state_file.seek(0)
    state_file.truncate()
    json.dump(state, state_file)
    state_file.flush()
    fcntl.flock(state_file, fcntl.LOCK_UN)

def xml_document(up=0, hosts="", total=256, down=256, finished="success"):
    return ("<?xml version=\"1.0\"?>\n<!DOCTYPE nmaprun>\n"
            f"<nmaprun scanner=\"nmap\" version=\"7.95\">{hosts}"
            f"<runstats><finished exit=\"{finished}\"/>"
            f"<hosts up=\"{up}\" down=\"{down}\" total=\"{total}\"/>"
            "</runstats></nmaprun>\n")

try:
    if mode in ("timeout", "signal", "fork-exit") and classc == 0:
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(60)
            os._exit(0)
        Path(os.environ["MOCK_CHILD_PID"]).write_text(str(child))
        if mode in ("timeout", "signal"):
            time.sleep(60)
    if mode == "fail" and classc == 0:
        raise SystemExit(7)
    if mode == "retry" and classc == 0 and target_calls == 1:
        raise SystemExit(7)
    if mode in {"malformed", "empty", "comment", "truncated", "wrong-total", "mismatch", "duplicate", "outside", "noncanonical", "bad-status", "not-finished"} and classc == 0:
        if mode == "malformed":
            print("not nmap output")
        elif mode == "empty":
            pass
        elif mode == "comment":
            print("<!-- no document -->")
        elif mode == "truncated":
            print("<nmaprun><runstats><finished exit=\"success\"/>", end="")
        elif mode == "wrong-total":
            print(xml_document(total=255, down=255), end="")
        elif mode == "mismatch":
            print(xml_document(up=1, hosts="", down=255), end="")
        elif mode == "duplicate":
            host = f"<host><status state=\"up\"/><address addr=\"{parts[0]}.{parts[1]}.{parts[2]}.1\" addrtype=\"ipv4\"/></host>"
            print(xml_document(up=2, hosts=host + host, down=254), end="")
        elif mode == "outside":
            host = f"<host><status state=\"up\"/><address addr=\"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}.1\" addrtype=\"ipv4\"/></host>"
            print(xml_document(up=1, hosts=host, down=255), end="")
        elif mode == "noncanonical":
            host = f"<host><status state=\"up\"/><address addr=\"08.{parts[1]}.{parts[2]}.1\" addrtype=\"ipv4\"/></host>"
            print(xml_document(up=1, hosts=host, down=255), end="")
        elif mode == "bad-status":
            host = f"<host><status state=\"unknown\"/><address addr=\"{parts[0]}.{parts[1]}.{parts[2]}.1\" addrtype=\"ipv4\"/></host>"
            print(xml_document(up=1, hosts=host, down=255), end="")
        else:
            print("<nmaprun><runstats><hosts up=\"0\" down=\"256\" total=\"256\"/></runstats></nmaprun>")
    elif mode == "fork-exit" and classc == 0:
        print(xml_document(), end="", flush=True)
    elif mode == "sparse" and classc == 0:
        host = f"<host><status state=\"up\" reason=\"mock\"/><address addr=\"{parts[0]}.{parts[1]}.{parts[2]}.1\" addrtype=\"ipv4\"/></host>"
        print(xml_document(up=1, hosts=host, down=255), end="")
    else:
        print(xml_document(), end="")
    time.sleep(delay)
finally:
    with state_path.open("a+") as state_file:
        fcntl.flock(state_file, fcntl.LOCK_EX)
        state_file.seek(0)
        try:
            state = json.load(state_file)
        except (json.JSONDecodeError, EOFError):
            state = {"calls": 0, "active": 0, "max_active": 0, "targets": {}, "argv": []}
        state["active"] -= 1
        state_file.seek(0)
        state_file.truncate()
        json.dump(state, state_file)
        state_file.flush()
        fcntl.flock(state_file, fcntl.LOCK_UN)
'''


class ScanClassBTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.work = Path(self.tempdir.name)
        self.mock = self.work / "mock-nmap"
        self.state = self.work / "mock-state.json"
        self.child_pid_file = self.work / "child.pid"
        self.mock.write_text(MOCK_NMAP)
        self.mock.chmod(self.mock.stat().st_mode | stat.S_IXUSR)
        self._reset_state()

    def tearDown(self):
        self.tempdir.cleanup()

    def _reset_state(self):
        self.state.write_text(json.dumps({"calls": 0, "active": 0, "max_active": 0, "targets": {}, "argv": []}))

    def _env(self, mode="zero", workers="3", attempts="1", delay="0"):
        env = os.environ.copy()
        env.update(
            {
                "NMAP_BIN": str(self.mock),
                "MOCK_STATE": str(self.state),
                "MOCK_MODE": mode,
                "MOCK_DELAY": "0.02",
                "MOCK_CHILD_PID": str(self.child_pid_file),
                "SCAN_WORKERS": workers,
                "SCAN_ATTEMPTS": attempts,
                "SCAN_RETRY_DELAY": delay,
                "NMAP_TIMEOUT_SECONDS": "5",
                "NMAP_MAX_RATE": "20",
            }
        )
        return env

    def _run(self, *args, mode="zero", workers="3", attempts="1", delay="0", timeout=30):
        return subprocess.run(
            ["bash", str(SCRIPT), *map(str, args)],
            cwd=self.work,
            env=self._env(mode, workers, attempts, delay),
            text=True,
            capture_output=True,
            timeout=timeout,
        )

    def _state(self):
        return json.loads(self.state.read_text())

    def _envelope(self, class_a, class_b=0, count=1):
        path = self.work / f"artifacts/scan-{class_a}-{class_b}-{count}.tar"
        self.assertTrue(path.is_file(), path)
        with tarfile.open(path) as archive:
            names = set(archive.getnames())
            self.assertIn(f"results/{class_a}.{class_b}.txt", names)
            self.assertIn(f"coverage/{class_a}.{class_b}.json", names)
            result_file = archive.extractfile(f"results/{class_a}.{class_b}.txt")
            coverage_file = archive.extractfile(f"coverage/{class_a}.{class_b}.json")
            self.assertIsNotNone(result_file)
            self.assertIsNotNone(coverage_file)
            assert result_file is not None
            assert coverage_file is not None
            results = result_file.read().decode()
            coverage = json.load(coverage_file)
        return path, results, coverage

    @staticmethod
    def _gone(pid):
        for _ in range(40):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            status = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], text=True, capture_output=True)
            if status.returncode != 0 or not status.stdout.strip() or status.stdout.strip().startswith("Z"):
                return True
            time.sleep(0.05)
        return False

    def test_invalid_arguments_and_hard_bounds_make_zero_mock_calls(self):
        invalid = [
            ("8", "0", "0"),
            ("08", "0"),
            ("8", "256"),
            ("8", "255", "2"),
            ("8", "0", "999999999999999999999999999999999"),
            ("8", "0", "1", "extra"),
            ("-1", "0"),
        ]
        for args in invalid:
            result = self._run(*args)
            self.assertNotEqual(result.returncode, 0, args)
        env = self._env()
        env["SCAN_WORKERS"] = "33"
        result = subprocess.run(["bash", str(SCRIPT), "8", "0", "1"], cwd=self.work, env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._state()["calls"], 0)

    def test_realistic_xml_is_parsed_and_exact_arguments_are_used(self):
        result = self._run("8", "0", "1", mode="sparse", workers="3")
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self._state()
        self.assertEqual(state["calls"], 256)
        self.assertGreater(state["max_active"], 1)
        self.assertLessEqual(state["max_active"], 3)
        self.assertEqual(
            state["argv"][:-1],
            [
                "-sn", "-n", "-T5", "--max-rate", "20", "--max-rtt-timeout", "200ms",
                "--max-retries", "1", "--host-timeout", "300ms", "--min-hostgroup", "256",
                "-oX", "-",
            ],
        )
        self.assertTrue(state["argv"][-1].startswith("8.0."))
        _, results, coverage = self._envelope(8)
        self.assertEqual(results, "8.0.0.0,1\n")
        self.assertEqual(coverage["states"], "S" + "Z" * 255)
        self.assertTrue(coverage["artifact_only"])
        self.assertNotIn("F", coverage["states"])
        self.assertEqual(coverage["provenance"]["retry_delay_seconds"], 0)
        self.assertEqual(coverage["provenance"]["nmap_options"][-2:], ["-oX", "-"])
        self.assertFalse((self.work / "results").exists())
        self.assertFalse((self.work / "coverage").exists())

    def test_zero_and_policy_excluded_states(self):
        zero = self._run("8", "0", "1", mode="zero")
        self.assertEqual(zero.returncode, 0, zero.stderr)
        _, results, coverage = self._envelope(8)
        self.assertEqual(results, "")
        self.assertEqual(coverage["states"], "Z" * 256)

        self._reset_state()
        excluded = self._run("10", "0", "1", mode="zero")
        self.assertEqual(excluded.returncode, 0, excluded.stderr)
        self.assertEqual(self._state()["calls"], 0)
        _, results, coverage = self._envelope(10)
        self.assertEqual(results, "")
        self.assertEqual(coverage["states"], "E" * 256)

    def test_child_failure_retries_and_then_blocks_publication(self):
        retry = self._run("8", "0", "1", mode="retry", attempts="2")
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual(self._state()["targets"]["8.0.0.0"], 2)

        self._reset_state()
        failed = self._run("8", "0", "1", mode="fail", attempts="2")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("no publishable output", failed.stderr)
        self.assertTrue((self.work / "artifacts/scan-8-0-1.tar").exists())

    def test_xml_rejections_never_become_zero(self):
        for mode in ("empty", "comment", "truncated", "wrong-total", "mismatch", "duplicate", "outside", "noncanonical", "bad-status", "not-finished"):
            with self.subTest(mode=mode):
                result = self._run("8", "0", "1", mode=mode, attempts="1")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.work / "artifacts/scan-8-0-1.tar").exists())

    def test_atomic_envelope_preserves_previous_complete_output_on_failure(self):
        first = self._run("8", "0", "1", mode="sparse")
        self.assertEqual(first.returncode, 0, first.stderr)
        target = self.work / "artifacts/scan-8-0-1.tar"
        original = target.read_bytes()
        failed = self._run("8", "0", "1", mode="malformed")
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse(list((self.work / "artifacts").glob(".*.tmp.*")))

    def test_timeout_and_external_signal_kill_mock_descendants(self):
        timed_out = self._run("8", "0", "1", mode="timeout", workers="1", timeout=15)
        self.assertNotEqual(timed_out.returncode, 0)
        timeout_child = int(self.child_pid_file.read_text())
        self.assertTrue(self._gone(timeout_child), timeout_child)
        self.assertFalse((self.work / "artifacts/scan-8-0-1.tar").exists())

        self.child_pid_file.unlink(missing_ok=True)
        process = subprocess.Popen(
            ["bash", str(SCRIPT), "8", "0", "1"],
            cwd=self.work,
            env=self._env("signal", workers="1"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(100):
            if self.child_pid_file.exists():
                break
            time.sleep(0.05)
        self.assertTrue(self.child_pid_file.exists())
        signal_sent_child = int(self.child_pid_file.read_text())
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=15)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        self.assertNotEqual(process.returncode, 0)
        self.assertTrue(self._gone(signal_sent_child), signal_sent_child)
        self.assertFalse((self.work / "artifacts/scan-8-0-1.tar").exists())

    def test_successful_scanner_exit_kills_residual_descendant(self):
        result = self._run("8", "0", "1", mode="fork-exit", workers="3", timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        child_pid = int(self.child_pid_file.read_text())
        self.assertTrue(self._gone(child_pid), child_pid)
        self.assertEqual(self._state()["calls"], 256)

    def test_signal_decision_reaps_exited_parent_and_kills_residual_descendant(self):
        registry = self.work / "runner-registry"
        runner = Runner(30, registry, ["mock-nmap"])
        child = Mock()
        child.pid = 4242
        child.poll.return_value = 0
        runner.signal_number = signal.SIGTERM
        runner.wait_for_exit = Mock(return_value=None)

        descendant_alive = True
        group_signals = []

        def signal_group(number):
            nonlocal descendant_alive
            group_signals.append(number)
            if number == signal.SIGKILL:
                descendant_alive = False

        runner.group_signal = signal_group
        runner.group_exists = lambda: descendant_alive

        try:
            with patch("tools.run_nmap.subprocess.Popen", return_value=child), patch(
                "tools.run_nmap.signal.signal"
            ), patch("tools.run_nmap.KILL_GRACE_SECONDS", 0.0), patch(
                "tools.run_nmap.time.monotonic", return_value=1.0
            ):
                result = runner.run()
        finally:
            runner.cleanup()

        self.assertEqual(result, 128 + signal.SIGTERM)
        child.wait.assert_called_once_with()
        self.assertEqual(group_signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertFalse(descendant_alive)

    def test_default_budget_values_are_recorded(self):
        env = self._env()
        for name in ("SCAN_WORKERS", "NMAP_MAX_RATE", "NMAP_TIMEOUT_SECONDS"):
            env.pop(name)
        result = subprocess.run(
            ["bash", str(SCRIPT), "10", "0", "1"],
            cwd=self.work,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._state()["calls"], 0)
        _, _, coverage = self._envelope(10)
        provenance = coverage["provenance"]
        self.assertEqual(provenance["scan_workers"], 2)
        self.assertEqual(provenance["nmap_max_rate"], 25)
        self.assertEqual(provenance["nmap_timeout_seconds"], 120)

    def test_policy_checker_digest_equivalence_and_boundaries(self):
        checked = subprocess.run(["python3", str(POLICY_CHECKER), "--check"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        shell = ROOT / "config/exclusions.sh"
        command = (
            f'. "{shell}"; '
            'for x in "192 88 98" "192 88 99" "192 88 100" '
            '"192 31 195" "192 31 196" "192 31 197" '
            '"192 52 193" "192 175 48"; do '
            'set -- $x; printf "%s:%s\\n" "$x" "$(exclusion_rule_for "$@")"; done'
        )
        boundary = subprocess.run(["bash", "-c", command], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(boundary.returncode, 0, boundary.stderr)
        lines = dict(line.split(":", 1) for line in boundary.stdout.splitlines())
        self.assertEqual(lines["192 88 99"].split("\t", 1)[0], "192.88.99.0/24")
        for key in ("192 88 98", "192 88 100", "192 31 195", "192 31 196", "192 31 197", "192 52 193", "192 175 48"):
            if key in {"192 31 196", "192 52 193", "192 175 48"}:
                self.assertEqual(lines[key], "")
            elif key != "192 88 99":
                self.assertEqual(lines[key], "")


if __name__ == "__main__":
    unittest.main()
