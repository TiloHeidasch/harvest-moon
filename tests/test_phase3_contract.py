#!/usr/bin/env python3
"""Network-free Phase-3 integration and transaction contract tests."""

from __future__ import annotations

import hashlib
import io
import json
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest

import yaml

from tools.coverage_contract import expected_nmap_options
from tools.publish_result import json_policy, validate_archives


ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "tools/csv2bin.py"
PUBLISH = ROOT / "bin/publish-result.sh"
GENERATOR = ROOT / "bin/generate-workflows.sh"


def policy() -> dict:
    return json.loads((ROOT / "config/exclusions.json").read_text(encoding="utf-8"))


def provenance(run_id: str = "42", job_id: str = "scan-8-0") -> dict:
    return {
        "executor": "scan-classb.sh",
        "nmap_bin": "nmap",
        "nmap_options": expected_nmap_options(25),
        "nmap_max_rate": 25,
        "nmap_timeout_seconds": 120,
        "retry_delay_seconds": 1,
        "scan_attempts": 2,
        "scan_workers": 4,
        "source_run_id": run_id,
        "source_job_id": job_id,
        "nmap_version": None,
    }


def fragment(
    class_a: int,
    class_b: int,
    run_id: str = "42",
    states: str | None = None,
    descriptor: dict | None = None,
) -> dict:
    descriptor = descriptor or policy()
    return {
        "artifact_only": True,
        "class_a": class_a,
        "class_b": class_b,
        "policy_digest": descriptor["policy_digest"],
        "policy_name": descriptor["policy_name"],
        "policy_version": descriptor["policy_version"],
        "provenance": provenance(run_id, f"scan-{class_a}-{class_b}"),
        "schema": "harvest-moon.coverage-fragment",
        "schema_version": 2,
        "states": states if states is not None else "Z" * 256,
    }


def write_tar(
    path: Path,
    class_a: int,
    class_b: int,
    run_id: str = "42",
    states: str | None = None,
    rows: bytes = b"",
    descriptor: dict | None = None,
) -> None:
    with tarfile.open(path, "w") as archive:
        for directory in ("results", "coverage"):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        values = (
            (f"results/{class_a}.{class_b}.txt", rows),
            (
                f"coverage/{class_a}.{class_b}.json",
                (
                    json.dumps(fragment(class_a, class_b, run_id, states, descriptor), sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode(),
            ),
        )
        for name, data in values:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class ConverterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "results").mkdir()
        (self.root / "coverage").mkdir()
        (self.root / "out").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_converter(self, input_path: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CSV), str(input_path or self.root / "results"), "--out", str(self.root / "out")],
            text=True,
            capture_output=True,
        )

    def canonical_coverage(self, states: list[str]) -> dict:
        descriptor = policy()
        return {
            "schema": "harvest-moon.coverage",
            "schema_version": 1,
            "class_a": 8,
            "policy": {
                "name": descriptor["policy_name"],
                "version": descriptor["policy_version"],
                "digest": descriptor["policy_digest"],
            },
            "provenance": {"run_id": "42", "run_number": 42, "run_attempt": 1, "source": "github-actions"},
            "class_b": [
                {
                    "class_b": b,
                    "states": states[b],
                    "policy_name": descriptor["policy_name"],
                    "policy_version": descriptor["policy_version"],
                    "policy_digest": descriptor["policy_digest"],
                    "provenance": provenance("42", f"scan-8-{b}"),
                }
                for b in range(256)
            ],
        }

    def test_mapping_saturation_manifest_hash_and_legacy_u_are_deterministic(self) -> None:
        raw = "8.2.3.0,256\n8.0.1.0,3\n"
        (self.root / "results/8.txt").write_text(raw)
        first = self.run_converter()
        self.assertEqual(first.returncode, 0, first.stderr)
        binary = (self.root / "out/8.bin").read_bytes()
        self.assertEqual(len(binary), 65536)
        self.assertEqual(binary[2 * 256 + 3], 255)
        self.assertEqual(binary[1], 3)
        manifest = json.loads((self.root / "out/manifest.json").read_text())
        asset = manifest["assets"][0]
        self.assertEqual(manifest["classas"], [8])
        self.assertEqual(asset["byte_length"], 65536)
        self.assertEqual(asset["sha256"], hashlib.sha256(binary).hexdigest())
        self.assertEqual(asset["coverage_status"], "U")
        original_manifest = (self.root / "out/manifest.json").read_bytes()
        second = self.run_converter()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((self.root / "out/manifest.json").read_bytes(), original_manifest)

    def test_single_file_uses_sibling_coverage_directory_and_is_verified(self) -> None:
        (self.root / "results/8.txt").write_text("8.0.1.0,3\n")
        states = ["Z" * 256 for _ in range(256)]
        states[0] = "ZS" + "Z" * 254
        (self.root / "coverage/8.json").write_text(json.dumps(self.canonical_coverage(states)))
        result = self.run_converter(self.root / "results/8.txt")
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.root / "out/manifest.json").read_text())
        self.assertEqual(manifest["assets"][0]["coverage_status"], "V")
        self.assertEqual(manifest["assets"][0]["coverage_path"], "coverage/8.json")

    def test_coverage_state_must_agree_with_sparse_rows_after_valid_provenance(self) -> None:
        (self.root / "results/8.txt").write_text("8.0.1.0,1\n")
        states = ["Z" * 256 for _ in range(256)]
        states[0] = "ZZ" + "Z" * 254
        (self.root / "coverage/8.json").write_text(json.dumps(self.canonical_coverage(states)))
        result = self.run_converter()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has a raw row", result.stderr)

    def test_u_coverage_with_legacy_rows_is_unverified(self) -> None:
        (self.root / "results/8.txt").write_text("8.0.1.0,3\n")
        states = ["U" * 256 for _ in range(256)]
        (self.root / "coverage/8.json").write_text(json.dumps(self.canonical_coverage(states)))
        result = self.run_converter()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.root / "out/manifest.json").read_text())
        asset = manifest["assets"][0]
        self.assertEqual(asset["coverage_status"], "U")
        self.assertEqual(asset["coverage_summary"]["U"], 65536)


class WorkflowContractTests(unittest.TestCase):
    def test_generated_numbered_workflows_are_dispatch_only_and_drift_free_without_checkout_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [str(GENERATOR)],
                cwd=ROOT,
                env={**os.environ, "WORKFLOW_OUTPUT_DIR": directory},
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = {path.name: path.read_bytes() for path in Path(directory).glob("*.yml")}
        checked_in = {path.name: path.read_bytes() for path in (ROOT / ".github/workflows").glob("*.yml") if path.stem.isdigit()}
        self.assertEqual(generated, checked_in)
        self.assertEqual(len(generated), 16)
        for content in generated.values():
            text = content.decode()
            workflow = yaml.safe_load(text)
            jobs = workflow["jobs"]
            wave_ids = [f"scan_wave_{wave}" for wave in range(16)]
            self.assertEqual([job_id for job_id in jobs if job_id.startswith("scan_wave_")], wave_ids)
            self.assertEqual(jobs["aggregate"]["needs"], ["select_scope", *wave_ids])
            self.assertNotIn("schedule:", text)
            self.assertNotIn("cron:", text)
            self.assertNotIn("inputs:", text)
            self.assertNotIn("inputs.", text)
            self.assertIn("group: authorized-internet-scan", text)
            self.assertIn("queue: max", text)
            self.assertIn("group: result-publisher", text)
            self.assertIn("timeout-minutes: 360", text)
            self.assertIn("SCAN_WORKERS: 4", text)
            self.assertIn("NMAP_MAX_RATE: 25", text)
            self.assertNotRegex(text, r"\$\{\{[^}\n]*\+[^}\n]*\}\}")
            selector = jobs["select_scope"]
            self.assertEqual(selector["permissions"], {"contents": "read"})
            self.assertEqual(selector["outputs"], {
                "class_a": "${{ steps.scope.outputs.class_a }}",
                "class_b_block_start": "${{ steps.scope.outputs.class_b_block_start }}",
            })
            self.assertEqual(len(selector["steps"]), 1)
            scope_step = selector["steps"][0]
            self.assertEqual(scope_step["id"], "scope")
            self.assertEqual(scope_step["env"]["RUN_NUMBER"], "${{ github.run_number }}")
            self.assertIn("slot=$(( (10#$RUN_NUMBER - 1) % 64 ))", scope_step["run"])
            self.assertIn("class_a=$((10#$WORKFLOW_A_START + slot / 4))", scope_step["run"])
            self.assertIn("class_b_block_start=$(( (slot % 4) * 64 ))", scope_step["run"])
            self.assertIn('printf \'class_a=%s\\n\' "$class_a" >> "$GITHUB_OUTPUT"', scope_step["run"])
            self.assertIn('printf \'class_b_block_start=%s\\n\' "$class_b_block_start" >> "$GITHUB_OUTPUT"', scope_step["run"])
            for wave, wave_id in enumerate(wave_ids):
                job = jobs[wave_id]
                expected_needs = ["select_scope"] + ([wave_ids[wave - 1]] if wave else [])
                self.assertEqual(job["needs"], expected_needs)
                self.assertEqual(job["if"], "${{ github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}")
                self.assertEqual(job["environment"], "internet-scan")
                self.assertEqual(job["permissions"], {"contents": "read"})
                self.assertEqual(job["timeout-minutes"], 360)
                self.assertEqual(job["strategy"]["max-parallel"], 2)
                self.assertEqual(job["strategy"]["matrix"], {"classb_offset": [0, 1, 2, 3]})
                scan_step = next(step for step in job["steps"] if step.get("id") == "scan")
                self.assertEqual(scan_step["env"]["WAVE_OFFSET_BASE"], wave * 4)
                self.assertEqual(scan_step["env"]["CLASS_B_OFFSET"], "${{ matrix.classb_offset }}")
                self.assertEqual(scan_step["env"]["BLOCK_START"], "${{ needs.select_scope.outputs.class_b_block_start }}")
                self.assertEqual(scan_step["env"]["CLASS_A"], "${{ needs.select_scope.outputs.class_a }}")
                self.assertIn("classb=$((10#$BLOCK_START + 10#$WAVE_OFFSET_BASE + 10#$CLASS_B_OFFSET))", scan_step["run"])
                self.assertIn("printf 'classb=%s\\n' \"$classb\" >> \"$GITHUB_OUTPUT\"", scan_step["run"])
                self.assertIn('export SCAN_JOB_ID="${JOB_ID}-${CLASS_A}-${classb}"', scan_step["run"])
                upload_step = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
                self.assertIn("needs.select_scope.outputs.class_a", upload_step["with"]["name"])
                self.assertIn("steps.scan.outputs.classb", upload_step["with"]["name"])
                self.assertIn("steps.scan.outputs.classb", upload_step["with"]["path"])
            self.assertEqual(text.count("steps.scan.outputs.classb"), 32)
            self.assertNotIn("classb_offset: [0,1,2,3,4", text)
            self.assertIn("--count 1", text)
            self.assertIn("--class-a-start ${{ needs.select_scope.outputs.class_a }}", text)
            self.assertIn("--class-b-block-start ${{ needs.select_scope.outputs.class_b_block_start }}", text)


class PublisherContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_one(self, class_a: int = 8, class_b: int = 0, run_id: str = "42", states: str | None = None) -> None:
        for current_b in range(class_b, class_b + 64):
            write_tar(
                self.artifacts / f"scan-{class_a}-{current_b}-1.tar",
                class_a,
                current_b,
                run_id,
                states,
            )

    def publish_one(self, *extra: str, class_a: int = 8) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(ROOT / "tools/publish_result.py"),
                "--artifacts",
                str(self.artifacts),
                "--class-a-start",
                str(class_a),
                "--class-a-end",
                str(class_a),
                "--class-b-block-start",
                "0",
                "--count",
                "1",
                "--run-id",
                "42",
                "--run-number",
                "42",
                "--run-attempt",
                "1",
                "--policy",
                str(ROOT / "config/exclusions.json"),
                *extra,
            ],
            text=True,
            capture_output=True,
        )

    def test_policy_e_mismatch_and_provenance_mismatch_are_rejected(self) -> None:
        self.make_one(class_a=10, states="Z" * 256)
        rejected = self.publish_one(class_a=10)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("disagrees with policy", rejected.stderr)

        for path in self.artifacts.iterdir():
            path.unlink()
        self.make_one(run_id="wrong")
        rejected = self.publish_one()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("source run", rejected.stderr)

    def test_tar_oversized_and_unsafe_members_are_rejected_before_payload_use(self) -> None:
        self.make_one()
        oversized = self.artifacts / "scan-8-0-1.tar"
        with tarfile.open(oversized, "w") as archive:
            for name in ("results", "coverage"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            info = tarfile.TarInfo("results/8.0.txt")
            info.size = 9 * 1024
            archive.addfile(info, io.BytesIO(b"x" * info.size))
            info = tarfile.TarInfo("coverage/8.0.json")
            info.size = 0
            archive.addfile(info, io.BytesIO())
        rejected = self.publish_one()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("oversized", rejected.stderr)

        oversized.unlink()
        unsafe = self.artifacts / "scan-8-0-1.tar"
        with tarfile.open(unsafe, "w") as archive:
            for name in ("results", "coverage"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            for name, data in (("../escape", b""), ("coverage/8.0.json", b""), ("results/8.0.txt", b"")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        rejected = self.publish_one()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unsafe path", rejected.stderr)

    def test_count_one_is_required(self) -> None:
        self.make_one()
        command = self.publish_one("--count", "64")
        self.assertNotEqual(command.returncode, 0)

    def test_policy_exclusion_uses_overlap_for_a_sub24_rule(self) -> None:
        descriptor = policy()
        descriptor["rules"].append(
            {
                "cidr": "8.0.0.128/25",
                "id": "test-narrow-opt-out",
                "rationale": "boundary regression",
                "source": "phase-3-test",
            }
        )
        without_digest = dict(descriptor)
        without_digest.pop("policy_digest")
        descriptor["policy_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(without_digest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        policy_path = self.root / "narrow-policy.json"
        policy_path.write_text(json.dumps(descriptor))
        for class_b in range(64):
            states = ("E" + "Z" * 255) if class_b == 0 else "Z" * 256
            write_tar(self.artifacts / f"scan-8-{class_b}-1.tar", 8, class_b, states=states, descriptor=descriptor)
        document, digest, networks = json_policy(policy_path)
        args = argparse.Namespace(
            class_a_start=8,
            class_a_end=8,
            class_b_block_start=0,
            class_b_starts=None,
            count=1,
            run_id="42",
        )
        fragments = validate_archives(
            self.artifacts,
            args,
            (document["policy_name"], document["policy_version"], digest),
            networks,
        )
        self.assertEqual(len(fragments[8]), 64)


class PublisherGitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.source = self.root / "source"
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        self.source.mkdir()
        self.git("init")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "phase3-test")
        (self.source / "config").mkdir()
        shutil.copy(ROOT / "config/exclusions.json", self.source / "config/exclusions.json")
        self.git("add", ".")
        self.git("commit", "-m", "source")
        self.git("branch", "-M", "main")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "HEAD:main")
        self.seed_result()
        self.git("checkout", "main")
        self.make_artifacts()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-C", str(self.source), *args], check=check, text=True, capture_output=True)

    def seed_result(self) -> None:
        self.git("checkout", "--orphan", "result")
        self.git("rm", "-rf", ".")
        (self.source / "99.bin").write_bytes(b"stale")
        self.git("add", "99.bin")
        self.git("commit", "-m", "seed-result")
        self.git("push", "origin", "result")

    def make_artifacts(self, run_id: str = "2", block_start: int = 0) -> None:
        for path in self.artifacts.glob("*.tar"):
            path.unlink()
        for class_b in range(block_start, block_start + 64):
            write_tar(self.artifacts / f"scan-8-{class_b}-1.tar", 8, class_b, run_id)

    def publish_command(
        self, run_number: int, retries: int = 1, bootstrap: bool = False, block_start: int = 0
    ) -> list[str]:
        command = [
            "bash",
            str(PUBLISH),
            "--repo",
            str(self.source),
            "--artifacts",
            str(self.artifacts),
            "--class-a-start",
            "8",
            "--class-a-end",
            "8",
            "--class-b-block-start",
            str(block_start),
            "--count",
            "1",
            "--run-id",
            str(run_number),
            "--run-number",
            str(run_number),
            "--run-attempt",
            "1",
            "--policy",
            str(self.source / "config/exclusions.json"),
            "--retries",
            str(retries),
            "--backoff-seconds",
            "0",
        ]
        if bootstrap:
            command.append("--bootstrap-orphan")
        return command

    def publish(
        self, run_number: int, retries: int = 1, bootstrap: bool = False, block_start: int = 0
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.publish_command(run_number, retries, bootstrap, block_start), text=True, capture_output=True
        )

    def remote_ref(self) -> str:
        return subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "result"], check=True, text=True, capture_output=True
        ).stdout.strip()

    def test_result_worktree_is_built_from_captured_immutable_sha(self) -> None:
        source = (ROOT / "tools/publish_result.py").read_text(encoding="utf-8")
        self.assertIn('git(["worktree", "add", "--detach", str(worktree), result_sha]', source)
        self.assertNotIn('str(worktree), f"refs/remotes/{args.remote}/result"', source)

    def test_transaction_noop_stale_cleanup_and_exact_lease(self) -> None:
        lease_record = self.root / "lease-record"
        hook = self.remote / "hooks/pre-receive"
        hook.write_text(f"#!/bin/sh\ncat > '{lease_record}'\nexit 0\n")
        hook.chmod(0o755)
        expected_lease = self.remote_ref()
        first = self.publish(2)
        self.assertEqual(first.returncode, 0, first.stderr)
        old_sha, _new_sha, ref_name = lease_record.read_text().split()
        self.assertEqual(old_sha, expected_lease)
        self.assertEqual(ref_name, "refs/heads/result")
        tree = subprocess.run(["git", "--git-dir", str(self.remote), "ls-tree", "--name-only", "result"], check=True, text=True, capture_output=True).stdout
        self.assertNotIn("99.bin", tree.splitlines())
        commits = int(subprocess.run(["git", "--git-dir", str(self.remote), "rev-list", "--count", "result"], check=True, text=True, capture_output=True).stdout.strip())
        noop = self.publish(2)
        self.assertEqual(noop.returncode, 0, noop.stderr)
        self.assertIn("no commit or push", noop.stdout)
        self.assertEqual(int(subprocess.run(["git", "--git-dir", str(self.remote), "rev-list", "--count", "result"], check=True, text=True, capture_output=True).stdout.strip()), commits)
        self.make_artifacts(run_id="1")
        stale = self.publish(1)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("stale run rejected", stale.stderr)
        self.assertEqual(self.git("branch", "--list", "publisher-result-*", check=True).stdout.strip(), "")

    def test_selected_blocks_merge_and_unscanned_ranges_remain_u(self) -> None:
        first = self.publish(2)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_coverage = json.loads(
            subprocess.run(
                ["git", "--git-dir", str(self.remote), "show", "result:coverage/8.json"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
        )
        self.assertEqual(first_coverage["class_b"][0]["states"], "Z" * 256)
        self.assertEqual(first_coverage["class_b"][64]["states"], "U" * 256)
        self.assertEqual(first_coverage["class_b"][64]["provenance"], None)

        self.make_artifacts(run_id="3", block_start=64)
        second = self.publish(3, block_start=64)
        self.assertEqual(second.returncode, 0, second.stderr)
        merged = json.loads(
            subprocess.run(
                ["git", "--git-dir", str(self.remote), "show", "result:coverage/8.json"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout
        )
        self.assertEqual(merged["class_b"][0]["states"], "Z" * 256)
        self.assertEqual(merged["class_b"][64]["states"], "Z" * 256)
        self.assertEqual(merged["class_b"][128]["states"], "U" * 256)

    def test_noop_generation_change_and_deletion_are_not_accepted(self) -> None:
        first = self.publish(2)
        self.assertEqual(first.returncode, 0, first.stderr)
        from tools.publish_result import ResultRef, captured_ref_is_current

        captured = ResultRef(True, self.remote_ref())
        self.assertTrue(captured_ref_is_current(self.source, "origin", captured))

        self.git("checkout", "-B", "result", "origin/result")
        (self.source / "generation-marker").write_text("changed")
        self.git("add", "generation-marker")
        self.git("commit", "-m", "advance result generation")
        self.git("push", "origin", "result")
        self.git("checkout", "main")
        self.assertFalse(captured_ref_is_current(self.source, "origin", captured))

        subprocess.run(
            ["git", "--git-dir", str(self.remote), "update-ref", "-d", "refs/heads/result"],
            check=True,
        )
        self.assertFalse(captured_ref_is_current(self.source, "origin", captured))

    def test_push_rejection_rebuilds_and_succeeds_with_bounded_retries(self) -> None:
        self.make_artifacts(run_id="3")
        hook = self.remote / "hooks/pre-receive"
        state = self.root / "hook-state"
        hook.write_text(f"#!/bin/sh\nif [ ! -e '{state}' ]; then touch '{state}'; exit 1; fi\nexit 0\n")
        hook.chmod(0o755)
        result = self.publish(3, retries=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state.exists())
        self.assertEqual(self.git("branch", "--list", "publisher-result-*", check=True).stdout.strip(), "")

    def test_ref_deletion_after_rejection_never_recreates_old_tip(self) -> None:
        self.make_artifacts(run_id="4")
        hook = self.remote / "hooks/pre-receive"
        marker = self.root / "hook-entered"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nsleep 2\nexit 1\n")
        hook.chmod(0o755)
        process = subprocess.Popen(self.publish_command(4, retries=2), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            if marker.exists():
                break
            time.sleep(0.02)
        self.assertTrue(marker.exists())
        subprocess.run(["git", "--git-dir", str(self.remote), "update-ref", "-d", "refs/heads/result"], check=True)
        stdout, stderr = process.communicate(timeout=30)
        rejected = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("disappeared", rejected.stderr)
        missing = subprocess.run(["git", "--git-dir", str(self.remote), "show-ref", "--verify", "--quiet", "refs/heads/result"])
        self.assertNotEqual(missing.returncode, 0)

    def test_missing_result_requires_explicit_absent_ref_bootstrap_lease(self) -> None:
        self.make_artifacts(run_id="5")
        subprocess.run(["git", "--git-dir", str(self.remote), "update-ref", "-d", "refs/heads/result"], check=True)
        rejected = self.publish(5)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("--bootstrap-orphan", rejected.stderr)
        bootstrapped = self.publish(5, bootstrap=True)
        self.assertEqual(bootstrapped.returncode, 0, bootstrapped.stderr)

    def test_hostile_result_tree_symlink_is_rejected_before_reads(self) -> None:
        self.make_artifacts(run_id="6")
        self.git("checkout", "result")
        (self.source / "target").mkdir()
        os.symlink("target", self.source / "results")
        self.git("add", "target", "results")
        self.git("commit", "-m", "hostile result tree")
        self.git("push", "--force", "origin", "result")
        self.git("checkout", "main")
        rejected = self.publish(6)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("symbolic link", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
