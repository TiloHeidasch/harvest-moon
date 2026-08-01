#!/usr/bin/env python3
"""Validate scan envelopes and publish one transactional result snapshot.

This program intentionally keeps downloaded artifacts, the source checkout,
and the temporary result worktree separate.  A result branch is never based on
the checkout's current branch; every attempt starts at a freshly fetched
``origin/result`` commit.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any

try:
    from coverage_contract import (
        ContractError,
        REVIEWED_SCAN_CONFIG,
        canonical_json_bytes,
        validate_canonical_coverage,
        expected_nmap_options,
        load_json_bytes,
        validate_fragment,
    )
except ModuleNotFoundError:  # Importable as tools.publish_result in tests.
    from tools.coverage_contract import (
        ContractError,
        REVIEWED_SCAN_CONFIG,
        canonical_json_bytes,
        validate_canonical_coverage,
        expected_nmap_options,
        load_json_bytes,
        validate_fragment,
    )


class PublishError(RuntimeError):
    pass


TAR_NAME = re.compile(r"^scan-(0|[1-9][0-9]*)-(0|[1-9][0-9]*)-(0|[1-9][0-9]*)\.tar$")
ROW_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.0,(0|[1-9][0-9]*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")

# A one-Class-B envelope has two directories and one result/coverage pair.
# These limits are deliberately derived from that format rather than from an
# arbitrary large extraction allowance.
MAX_TAR_MEMBERS = 6
MAX_RESULT_MEMBER_BYTES = 8 * 1024
MAX_COVERAGE_MEMBER_BYTES = 64 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 96 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_PUBLISH_RETRIES = 8
MAX_BACKOFF_SECONDS = 60.0
CLASS_B_BLOCK_STARTS = (0, 64, 128, 192)
CLASS_B_BLOCK_SIZE = 64


@dataclass(frozen=True)
class ResultRef:
    exists: bool
    sha: str | None


def git(command: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        ["git", *command], cwd=cwd, text=True, capture_output=True, check=False
    )
    if check and process.returncode != 0:
        detail = (process.stderr or process.stdout).strip()
        raise PublishError(f"git {' '.join(command)} failed ({process.returncode}): {detail}")
    return process


def regular_path(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise PublishError(f"cannot stat {label} {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise PublishError(f"{label} is not a regular non-symlink file: {path}")


def json_policy(path: Path) -> tuple[dict[str, Any], str, list[ipaddress.IPv4Network]]:
    regular_path(path, "policy descriptor")
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_POLICY_BYTES:
            raise PublishError("policy descriptor is oversized")
        document = load_json_bytes(raw, str(path))
    except OSError as exc:
        raise PublishError(f"cannot read policy descriptor {path}: {exc}") from exc
    if document.get("schema_version") != 2:
        raise PublishError("policy descriptor has an unsupported schema_version")
    for key in ("policy_name", "policy_version", "source_date"):
        if not isinstance(document.get(key), str) or not document[key]:
            raise PublishError(f"policy descriptor has no valid {key}")
    scope = document.get("scope")
    if not isinstance(scope, dict) or scope.get("granularity") != "whole-/24-conservative":
        raise PublishError("policy descriptor does not declare whole-/24 granularity")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PublishError("policy descriptor rules must be a non-empty array")
    networks: list[ipaddress.IPv4Network] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or set(rule) != {"cidr", "id", "rationale", "source"}:
            raise PublishError(f"policy rule {index} has an invalid schema")
        if any(not isinstance(rule[key], str) or not rule[key] for key in ("cidr", "id", "rationale", "source")):
            raise PublishError(f"policy rule {index} has an invalid field")
        try:
            network = ipaddress.ip_network(rule["cidr"], strict=True)
        except ValueError as exc:
            raise PublishError(f"policy rule {index} has an invalid CIDR") from exc
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != rule["cidr"]:
            raise PublishError(f"policy rule {index} is not a canonical IPv4 CIDR")
        networks.append(network)
    exceptions = document.get("safe_routable_exceptions", [])
    if not isinstance(exceptions, list):
        raise PublishError("policy safe_routable_exceptions must be an array")
    for index, exception in enumerate(exceptions):
        if not isinstance(exception, dict) or set(exception) != {"cidr", "id", "rationale", "source"}:
            raise PublishError(f"policy exception {index} has an invalid schema")
        if any(not isinstance(exception[key], str) or not exception[key] for key in ("cidr", "id", "rationale", "source")):
            raise PublishError(f"policy exception {index} has an invalid field")
        try:
            network = ipaddress.ip_network(exception["cidr"], strict=True)
        except ValueError as exc:
            raise PublishError(f"policy exception {index} has an invalid CIDR") from exc
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != exception["cidr"]:
            raise PublishError(f"policy exception {index} is not a canonical IPv4 CIDR")
    without_digest = dict(document)
    supplied = without_digest.pop("policy_digest", None)
    digest = "sha256:" + hashlib.sha256(
        json.dumps(without_digest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if supplied != digest:
        raise PublishError(f"policy descriptor digest is {supplied!r}, expected {digest}")
    return document, digest, networks


def parse_row_bytes(raw: bytes, label: str, expected_a: int, expected_b: int) -> dict[int, int]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublishError(f"{label} is not UTF-8") from exc
    rows: dict[int, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        if line != line.strip():
            raise PublishError(f"{label}:{number}: surrounding whitespace is not allowed")
        match = ROW_RE.fullmatch(line)
        if not match:
            raise PublishError(f"{label}:{number}: malformed sparse result row")
        a, b, c, count = (int(value) for value in match.groups())
        if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255):
            raise PublishError(f"{label}:{number}: address outside IPv4 range")
        if a != expected_a or b != expected_b:
            raise PublishError(f"{label}:{number}: row is outside its artifact Class-B shard")
        if not 1 <= count <= 256:
            raise PublishError(f"{label}:{number}: count must be in 1..256")
        if c in rows:
            raise PublishError(f"{label}:{number}: duplicate/conflicting row")
        rows[c] = count
    return rows


def safe_member_name(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name:
        return False
    parts = PurePosixPath(name).parts
    return ".." not in parts and not name.startswith("./")


def discover_archives(root: Path) -> list[Path]:
    if root.is_symlink():
        raise PublishError(f"symbolic link used as artifact input: {root}")
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise PublishError(f"artifact input does not exist: {root}")
    archives: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PublishError(f"symbolic link in artifact input: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PublishError(f"special file in artifact input: {path}")
        if path.is_file():
            if path.suffix != ".tar":
                raise PublishError(f"unexpected non-tar file in artifact input: {path}")
            archives.append(path)
    return sorted(archives)


def expected_cells(args: argparse.Namespace) -> set[tuple[int, int]]:
    if not 0 <= args.class_a_start <= args.class_a_end <= 255:
        raise PublishError("Class-A range must be within 0..255")
    if args.class_a_start != args.class_a_end:
        raise PublishError("publisher scope must contain exactly one Class A")
    if args.count != 1:
        raise PublishError("publisher artifact count must be exactly one Class B")
    block_start = getattr(args, "class_b_block_start", None)
    if block_start is not None:
        if block_start not in CLASS_B_BLOCK_STARTS:
            raise PublishError("Class-B block start must be one of 0, 64, 128, or 192")
        starts = list(range(block_start, block_start + CLASS_B_BLOCK_SIZE))
    else:
        # Keep the explicit form useful to local callers, but retain the same
        # bounded matrix contract as the generated workflows.
        starts = getattr(args, "class_b_starts", None)
        if not starts or len(starts) != CLASS_B_BLOCK_SIZE or len(set(starts)) != len(starts):
            raise PublishError("Class-B starts must contain exactly one 64-Class-B block")
        ordered = sorted(starts)
        if ordered not in [list(range(start, start + CLASS_B_BLOCK_SIZE)) for start in CLASS_B_BLOCK_STARTS]:
            raise PublishError("Class-B starts must be one contiguous 64-Class-B block")
    if any(start < 0 or start > 255 or start + args.count > 256 for start in starts):
        raise PublishError("Class-B start/count range is outside 0..255")
    return {(class_a, start) for class_a in range(args.class_a_start, args.class_a_end + 1) for start in starts}


def validate_archives(
    artifact_root: Path,
    args: argparse.Namespace,
    policy: tuple[str, str, str],
    policy_networks: list[ipaddress.IPv4Network],
) -> dict[int, list[dict[str, Any]]]:
    expected = expected_cells(args)
    archives = discover_archives(artifact_root)
    if len(archives) != len(expected):
        raise PublishError(f"expected exactly {len(expected)} tar artifacts, found {len(archives)}")
    seen_cells: set[tuple[int, int]] = set()
    per_a: dict[int, list[dict[str, Any]]] = {class_a: [] for class_a in range(args.class_a_start, args.class_a_end + 1)}
    global_provenance_signature: tuple[Any, ...] | None = None
    for archive_path in archives:
        try:
            archive_size = archive_path.stat().st_size
        except OSError as exc:
            raise PublishError(f"cannot stat {archive_path}: {exc}") from exc
        if archive_size > MAX_ARCHIVE_BYTES:
            raise PublishError(f"oversized artifact archive: {archive_path.name}")
        match = TAR_NAME.fullmatch(archive_path.name)
        if not match:
            raise PublishError(f"unexpected artifact filename: {archive_path.name}")
        class_a, class_b_start, count = (int(value) for value in match.groups())
        cell = (class_a, class_b_start)
        if cell not in expected:
            raise PublishError(f"unexpected artifact matrix cell: {archive_path.name}")
        if count != args.count or cell in seen_cells:
            raise PublishError(f"duplicate or wrong-count artifact: {archive_path.name}")
        seen_cells.add(cell)
        expected_names = {"results", "coverage"}
        for class_b in range(class_b_start, class_b_start + args.count):
            expected_names.add(f"results/{class_a}.{class_b}.txt")
            expected_names.add(f"coverage/{class_a}.{class_b}.json")
        try:
            with tarfile.open(archive_path, mode="r:*") as tar:
                members = []
                while True:
                    member = tar.next()
                    if member is None:
                        break
                    members.append(member)
                    if len(members) > MAX_TAR_MEMBERS:
                        raise PublishError(f"{archive_path.name}: too many tar members")
                names = [member.name for member in members]
                if any(not safe_member_name(name) for name in names):
                    raise PublishError(f"unsafe path in {archive_path.name}")
                if len(names) != len(set(names)):
                    raise PublishError(f"duplicate tar member in {archive_path.name}")
                if set(names) != expected_names:
                    raise PublishError(f"{archive_path.name} does not contain exactly its result/coverage envelope")
                total_size = sum(member.size for member in members)
                if any(member.size < 0 for member in members) or total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    raise PublishError(f"{archive_path.name}: uncompressed archive is oversized")
                payload: dict[str, bytes] = {}
                for member in members:
                    if member.name in ("results", "coverage"):
                        if not member.isdir() or member.size != 0:
                            raise PublishError(f"{archive_path.name}: directory member is not a directory")
                        continue
                    member_limit = MAX_RESULT_MEMBER_BYTES if member.name.startswith("results/") else MAX_COVERAGE_MEMBER_BYTES
                    if not member.isreg() or member.size > member_limit:
                        raise PublishError(f"{archive_path.name}: unsafe or oversized member {member.name}")
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        raise PublishError(f"cannot read tar member {member.name}")
                    data = extracted.read(member_limit + 1)
                    if len(data) != member.size or len(data) > member_limit:
                        raise PublishError(f"{archive_path.name}: member size changed while reading")
                    payload[member.name] = data
        except (OSError, tarfile.TarError) as exc:
            raise PublishError(f"cannot read {archive_path}: {exc}") from exc

        fragments: list[dict[str, Any]] = []
        for class_b in range(class_b_start, class_b_start + args.count):
            result_name = f"results/{class_a}.{class_b}.txt"
            coverage_name = f"coverage/{class_a}.{class_b}.json"
            rows = parse_row_bytes(payload[result_name], f"{archive_path.name}:{result_name}", class_a, class_b)
            document = load_json_bytes(payload[coverage_name], f"{archive_path.name}:{coverage_name}")
            try:
                validate_fragment(document, class_a, class_b, f"{archive_path.name}:{coverage_name}")
            except ContractError as exc:
                raise PublishError(str(exc)) from exc
            fragment_policy = (document["policy_name"], document["policy_version"], document["policy_digest"])
            if fragment_policy != policy:
                raise PublishError(f"{archive_path.name}:{coverage_name}: policy does not match current descriptor")
            provenance = document["provenance"]
            if provenance["source_run_id"] != str(args.run_id):
                raise PublishError(f"{archive_path.name}:{coverage_name}: source run does not match publisher run")
            for key, expected_value in REVIEWED_SCAN_CONFIG.items():
                if provenance[key] != expected_value:
                    raise PublishError(f"{archive_path.name}:{coverage_name}: unreviewed scan configuration")
            expected_options = expected_nmap_options(provenance["nmap_max_rate"])
            if provenance["nmap_options"] != expected_options:
                raise PublishError(f"{archive_path.name}:{coverage_name}: Nmap options do not match configuration")
            provenance_signature = tuple(
                provenance.get(key) for key in (
                    "executor",
                    "nmap_bin",
                    "nmap_options",
                    "nmap_max_rate",
                    "nmap_timeout_seconds",
                    "retry_delay_seconds",
                    "scan_attempts",
                    "scan_workers",
                    "source_run_id",
                    "nmap_version",
                )
            )
            if global_provenance_signature is not None and provenance_signature != global_provenance_signature:
                raise PublishError(f"{archive_path.name}:{coverage_name}: inconsistent fragment provenance")
            global_provenance_signature = provenance_signature
            states = document["states"]
            for class_c, state in enumerate(states):
                has_row = class_c in rows
                address = ipaddress.IPv4Network(f"{class_a}.{class_b}.{class_c}.0/24")
                # The policy is conservative at whole-/24 granularity.  Use
                # overlap rather than containment so a future narrow opt-out
                # still excludes the complete affected /24.
                excluded = any(address.overlaps(network) for network in policy_networks)
                if (state == "E") != excluded:
                    expected = "E" if excluded else "S/Z"
                    raise PublishError(
                        f"{archive_path.name}:{coverage_name}: state {state} disagrees with policy (expected {expected})"
                    )
                if state == "S" and not has_row:
                    raise PublishError(f"{archive_path.name}:{coverage_name}: S without a raw row")
                if state in "ZE" and has_row:
                    raise PublishError(f"{archive_path.name}:{coverage_name}: {state} has a raw row")
            fragments.append(
                {
                    "class_b": class_b,
                    "states": states,
                    "document": document,
                    "rows": rows,
                    "artifact": archive_path.name,
                    "provenance_signature": provenance_signature,
                }
            )
        per_a[class_a].extend(fragments)
    if seen_cells != expected:
        missing = sorted(expected - seen_cells)
        raise PublishError(f"missing expected artifact matrix cells: {missing}")
    for class_a, fragments in per_a.items():
        if len(fragments) != CLASS_B_BLOCK_SIZE:
            raise PublishError(
                f"Class A {class_a} has {len(fragments)} fragments instead of {CLASS_B_BLOCK_SIZE}"
            )
        fragments.sort(key=lambda item: item["class_b"])
    return per_a


def run_provenance(args: argparse.Namespace) -> dict[str, Any]:
    if args.run_number < 0 or args.run_attempt < 1 or not str(args.run_id):
        raise PublishError("run provenance is invalid")
    return {
        "run_id": str(args.run_id),
        "run_number": args.run_number,
        "run_attempt": args.run_attempt,
        "source": "github-actions",
    }


def provenance_key(value: dict[str, Any]) -> tuple[int, int, tuple[int, Any]]:
    try:
        number = int(value.get("run_number", -1))
        attempt = int(value.get("run_attempt", -1))
    except (TypeError, ValueError) as exc:
        raise PublishError("existing coverage has invalid run provenance") from exc
    run_id = str(value.get("run_id", ""))
    if number < 0 or attempt < 0:
        return (-1, -1, (0, -1))
    if run_id.isdigit():
        return number, attempt, (0, int(run_id))
    return number, attempt, (1, run_id)


def canonical_coverage(
    class_a: int,
    fragments: list[dict[str, Any]],
    provenance: dict[str, Any],
    existing: dict[str, Any] | None = None,
    existing_rows: dict[tuple[int, int], int] | None = None,
    policy: tuple[str, str, str] | None = None,
) -> dict[str, Any]:
    """Merge one bounded block into a complete canonical Class-A document.

    A publisher run never invents a successful state for a Class B it did not
    receive.  With no previous canonical document, every other Class B is U;
    a legacy raw row is retained but remains U until its complete block is
    scanned again.
    """
    if not fragments:
        raise PublishError(f"Class A {class_a} has no incoming fragments")
    first = fragments[0]["document"]
    if policy is None:
        policy = (first["policy_name"], first["policy_version"], first["policy_digest"])
    policy_name, policy_version, policy_digest = policy
    rows = existing_rows or {}
    existing_maps = {}
    if existing is not None:
        existing_maps = {item["class_b"]: item for item in existing["class_b"]}

    incoming_by_b = {fragment["class_b"]: fragment for fragment in fragments}
    maps: list[dict[str, Any]] = []
    fragment_records: list[dict[str, Any]] = []
    for class_b in range(256):
        fragment = incoming_by_b.get(class_b)
        if fragment is not None:
            document = fragment["document"]
            maps.append(
                {
                    "class_b": class_b,
                    "states": fragment["states"],
                    "policy_name": policy_name,
                    "policy_version": policy_version,
                    "policy_digest": policy_digest,
                    "provenance": document["provenance"],
                }
            )
            fragment_records.append(
                {
                    "artifact": fragment["artifact"],
                    "class_b": class_b,
                    "document": document,
                }
            )
            continue

        previous = existing_maps.get(class_b)
        if previous is None:
            states = "U" * 256
            map_provenance = None
        else:
            states = previous["states"]
            map_provenance = previous.get("provenance")
        maps.append(
            {
                "class_b": class_b,
                "states": states,
                "policy_name": policy_name,
                "policy_version": policy_version,
                "policy_digest": policy_digest,
                "provenance": map_provenance,
            }
        )

    document = {
        "schema": "harvest-moon.coverage",
        "schema_version": 1,
        "class_a": class_a,
        "policy": {
            "name": policy_name,
            "version": policy_version,
            "digest": policy_digest,
        },
        "provenance": provenance,
        "class_b": maps,
        "fragments": fragment_records,
    }
    try:
        validate_canonical_coverage(document, class_a, f"Class A {class_a} canonical coverage")
    except ContractError as exc:
        raise PublishError(str(exc)) from exc
    return document


def validate_stale(
    worktree: Path,
    class_a: int,
    incoming: dict[str, Any],
    policy: tuple[str, str, str],
) -> dict[str, Any] | None:
    path = worktree / "coverage" / f"{class_a}.json"
    if not path.exists():
        return None
    try:
        document = load_json_bytes(path.read_bytes(), str(path))
        validate_canonical_coverage(document, class_a, str(path))
    except (OSError, ContractError) as exc:
        raise PublishError(f"existing coverage cannot be trusted: {exc}") from exc
    existing_policy = (
        document["policy"]["name"],
        document["policy"]["version"],
        document["policy"]["digest"],
    )
    if existing_policy != policy:
        raise PublishError(
            f"policy digest mismatch for Class A {class_a}; refusing a partial merge of incompatible coverage"
        )
    existing_key = provenance_key(document["provenance"])
    incoming_key = provenance_key(incoming["provenance"])
    if existing_key > incoming_key:
        raise PublishError(
            f"stale run rejected for Class A {class_a}: existing {existing_key} is newer than incoming {incoming_key}"
        )
    return document


def existing_rows(worktree: Path, class_a: int) -> dict[tuple[int, int], int]:
    """Read legacy/current sparse rows without assigning them verification."""
    path = worktree / "results" / f"{class_a}.txt"
    if not path.exists():
        return {}
    regular_path(path, "existing result")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublishError(f"existing result is not UTF-8: {path}") from exc
    rows: dict[tuple[int, int], int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        match = ROW_RE.fullmatch(line)
        if not match:
            raise PublishError(f"{path}:{number}: malformed existing sparse result row")
        row_a, class_b, class_c, count = (int(value) for value in match.groups())
        if row_a != class_a or class_b > 255 or class_c > 255 or not 1 <= count <= 256:
            raise PublishError(f"{path}:{number}: existing sparse result row is outside Class A {class_a}")
        key = (class_b, class_c)
        if key in rows:
            raise PublishError(f"{path}:{number}: duplicate existing sparse result row")
        rows[key] = count
    return rows


def validate_existing_agreement(
    coverage: dict[str, Any] | None,
    rows: dict[tuple[int, int], int],
    class_a: int,
) -> None:
    """Check verified historical maps before preserving them in a merge."""
    if coverage is None:
        return
    for item in coverage["class_b"]:
        class_b = item["class_b"]
        states = item["states"]
        for class_c, state in enumerate(states):
            has_row = (class_b, class_c) in rows
            if state == "S" and not has_row:
                raise PublishError(f"existing coverage S state has no raw row for {class_a}.{class_b}.{class_c}.0")
            if state in "ZE" and has_row:
                raise PublishError(f"existing coverage {state} state has a raw row for {class_a}.{class_b}.{class_c}.0")


def validate_existing_policy_set(worktree: Path, policy: tuple[str, str, str]) -> None:
    """Reject mixed-policy result branches before a partial merge begins."""
    coverage_dir = worktree / "coverage"
    if not coverage_dir.exists():
        return
    if coverage_dir.is_symlink() or not coverage_dir.is_dir():
        raise PublishError("existing coverage path is not a directory")
    for path in sorted(coverage_dir.iterdir()):
        if path.is_dir() or path.is_symlink() or not re.fullmatch(r"[0-9]+\.json", path.name):
            raise PublishError(f"unexpected existing coverage file: {path.name}")
        try:
            class_a = int(path.stem)
            document = load_json_bytes(path.read_bytes(), str(path))
            validate_canonical_coverage(document, class_a, str(path))
        except (OSError, ValueError, ContractError) as exc:
            raise PublishError(f"existing coverage cannot be trusted: {exc}") from exc
        existing_policy = (
            document["policy"]["name"],
            document["policy"]["version"],
            document["policy"]["digest"],
        )
        if existing_policy != policy:
            raise PublishError(
                "existing result contains an incompatible policy digest; refusing a partial merge"
            )


def write_bytes_if_changed(path: Path, content: bytes) -> None:
    if path.exists() and path.read_bytes() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def write_class_a(
    worktree: Path,
    class_a: int,
    fragments: list[dict[str, Any]],
    provenance: dict[str, Any],
    policy: tuple[str, str, str],
) -> None:
    rows = existing_rows(worktree, class_a)
    existing_coverage_document = validate_stale(
        worktree,
        class_a,
        {"provenance": provenance},
        policy,
    )
    validate_existing_agreement(existing_coverage_document, rows, class_a)
    incoming_bs = {fragment["class_b"] for fragment in fragments}
    for key in [key for key in rows if key[0] in incoming_bs]:
        del rows[key]
    for fragment in fragments:
        rows.update({(fragment["class_b"], class_c): count for class_c, count in fragment["rows"].items()})

    all_rows = [(class_b, class_c, count) for (class_b, class_c), count in rows.items()]
    all_rows.sort()
    raw = "".join(f"{class_a}.{class_b}.{class_c}.0,{count}\n" for class_b, class_c, count in all_rows).encode("ascii")
    write_bytes_if_changed(worktree / "results" / f"{class_a}.txt", raw)
    coverage = canonical_coverage(
        class_a,
        fragments,
        provenance,
        existing=existing_coverage_document,
        existing_rows=rows,
        policy=policy,
    )
    write_bytes_if_changed(worktree / "coverage" / f"{class_a}.json", canonical_json_bytes(coverage) + b"\n")


def remove_numeric_bins(worktree: Path) -> None:
    for path in worktree.iterdir():
        if path.is_file() and re.fullmatch(r"[0-9]+\.bin", path.name):
            path.unlink()


def owned_stage_paths(worktree: Path) -> list[str]:
    tracked = git(["ls-files", "-z"], worktree).stdout
    tracked_paths = [value for value in tracked.split("\0") if value]
    if any(not safe_member_name(value) for value in tracked_paths):
        raise PublishError("hostile path in result worktree index")
    paths: set[str] = {"results", "coverage", "manifest.json", "policy", "downloaded"}
    paths.update(value for value in tracked_paths if re.fullmatch(r"[0-9]+\.bin", value))
    return sorted(path for path in paths if (worktree / path).exists() or path in tracked_paths or any(value.startswith(path + "/") for value in tracked_paths))


def stage_owned(worktree: Path) -> bool:
    paths = owned_stage_paths(worktree)
    if paths:
        git(["add", "-A", "--", *paths], worktree)
    result = git(["diff", "--cached", "--quiet"], worktree, check=False)
    if result.returncode not in (0, 1):
        raise PublishError(f"git diff --cached failed ({result.returncode}): {result.stderr.strip()}")
    return result.returncode == 1


def validate_worktree_tree(worktree: Path) -> None:
    """Reject symlinks, special files, and unsafe names before any write."""
    if worktree.is_symlink():
        raise PublishError("result worktree is a symbolic link")
    stack = [worktree]
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise PublishError(f"cannot inspect result worktree {directory}: {exc}") from exc
        for entry in entries:
            if entry.name == ".git" and directory == worktree:
                continue
            if not safe_member_name(entry.name):
                raise PublishError(f"hostile path in result worktree: {entry.name}")
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise PublishError(f"cannot inspect result worktree entry {entry.path}: {exc}") from exc
            if stat.S_ISLNK(mode):
                raise PublishError(f"symbolic link in result worktree: {entry.path}")
            if stat.S_ISDIR(mode):
                stack.append(Path(entry.path))
            elif not stat.S_ISREG(mode):
                raise PublishError(f"special file in result worktree: {entry.path}")


def cleanup_worktree(repo: Path, worktree: Path, branch: str | None = None) -> None:
    if worktree.exists():
        git(["worktree", "remove", "--force", str(worktree)], repo)
    if branch:
        git(["branch", "-D", branch], repo, check=False)


def fetch_result(repo: Path, remote: str) -> ResultRef:
    check = git(["ls-remote", "--exit-code", remote, "refs/heads/result"], repo, check=False)
    if check.returncode == 0:
        lines = [line.split() for line in check.stdout.splitlines() if line.strip()]
        if len(lines) != 1 or len(lines[0]) != 2 or lines[0][1] != "refs/heads/result" or not SHA_RE.fullmatch(lines[0][0]):
            raise PublishError("remote result ref advertisement is malformed")
        remote_ref = f"refs/remotes/{remote}/result"
        git(["fetch", remote, f"+refs/heads/result:{remote_ref}"], repo)
        fetched = git(["rev-parse", remote_ref], repo).stdout.strip()
        if not SHA_RE.fullmatch(fetched):
            raise PublishError("fetched result ref is malformed")
        # The advertised value may race with a concurrent publisher.  The
        # fetched SHA is the lease we use; a subsequent remote change then
        # causes an intentional lease rejection and a rebuild from a fresh tip.
        return ResultRef(True, fetched)
    if check.returncode == 2 and not check.stdout.strip():
        git(["update-ref", "-d", f"refs/remotes/{remote}/result"], repo, check=False)
        return ResultRef(False, None)
    detail = (check.stderr or check.stdout).strip()
    raise PublishError(f"could not inspect result branch: {detail}")


def build_attempt(
    repo: Path,
    artifact_root: Path,
    args: argparse.Namespace,
    fragments: dict[int, list[dict[str, Any]]],
    policy_path: Path,
    policy_document: dict[str, Any],
    policy_digest: str,
    bootstrap: bool,
    bootstrap_branch: str,
    result_sha: str | None,
) -> tuple[Path, bool, str | None]:
    worktree = Path(tempfile.mkdtemp(prefix="harvest-moon-result-", dir=args.temp_dir))
    worktree.rmdir()
    try:
        if bootstrap:
            git(["worktree", "add", "--orphan", "-b", bootstrap_branch, str(worktree)], repo)
            for child in worktree.iterdir():
                if child.name != ".git":
                    if child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
        else:
            if result_sha is None or not SHA_RE.fullmatch(result_sha):
                raise PublishError("immutable result SHA is missing or malformed")
            # The fetched SHA is the immutable input to this attempt.  Never
            # attach a worktree to the mutable remote-tracking ref.
            git(["worktree", "add", "--detach", str(worktree), result_sha], repo)
        validate_worktree_tree(worktree)
        provenance = run_provenance(args)
        policy_tuple = (policy_document["policy_name"], policy_document["policy_version"], policy_digest)
        validate_existing_policy_set(worktree, policy_tuple)
        for class_a, class_fragments in fragments.items():
            write_class_a(worktree, class_a, class_fragments, provenance, policy_tuple)
        policy_hex = policy_digest.removeprefix("sha256:")
        write_bytes_if_changed(
            worktree / "policy" / f"sha256-{policy_hex}.json",
            policy_path.read_bytes(),
        )
        downloaded = worktree / "downloaded"
        if downloaded.exists():
            if downloaded.is_dir() and not downloaded.is_symlink():
                shutil.rmtree(downloaded)
            else:
                downloaded.unlink()
        remove_numeric_bins(worktree)
        converter = Path(__file__).with_name("csv2bin.py")
        subprocess.run(
            [sys.executable, str(converter), "results", "--coverage-dir", "coverage", "--out", "."],
            cwd=worktree,
            text=True,
            check=True,
        )
        changed = stage_owned(worktree)
        return worktree, changed, bootstrap_branch if bootstrap else None
    except Exception:
        cleanup_worktree(repo, worktree, bootstrap_branch if bootstrap else None)
        raise


def push_attempt(repo: Path, remote: str, worktree: Path, ref: ResultRef) -> bool:
    expected = ref.sha if ref.exists else ""
    lease = f"--force-with-lease=refs/heads/result:{expected}"
    result = git(["push", lease, remote, "HEAD:refs/heads/result"], worktree, check=False)
    if result.returncode == 0:
        return True
    detail = (result.stderr or result.stdout).strip()
    print(f"publisher: push rejected: {detail}", file=sys.stderr)
    return False


def captured_ref_is_current(repo: Path, remote: str, captured: ResultRef) -> bool:
    """Verify a no-op against a fresh remote advertisement before returning."""
    current = fetch_result(repo, remote)
    return current.exists == captured.exists and current.sha == captured.sha


def publish(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    artifact_root = Path(args.artifacts).absolute()
    policy_path = Path(args.policy).absolute()
    policy_document, policy_digest, policy_networks = json_policy(policy_path)
    policy_tuple = (policy_document["policy_name"], policy_document["policy_version"], policy_digest)
    fragments = validate_archives(artifact_root, args, policy_tuple, policy_networks)
    # Validate all inputs before fetching or creating a worktree.
    args.temp_dir = str(Path(args.temp_dir).resolve())
    Path(args.temp_dir).mkdir(parents=True, exist_ok=True)
    result_ref = fetch_result(repo, args.remote)
    observed_existing_branch = result_ref.exists
    if not result_ref.exists and not args.bootstrap_orphan:
        raise PublishError("origin/result is missing; pass --bootstrap-orphan for an explicit orphan bootstrap")

    for attempt in range(1, args.retries + 1):
        if attempt > 1:
            result_ref = fetch_result(repo, args.remote)
            if result_ref.exists:
                observed_existing_branch = True
            if not result_ref.exists and observed_existing_branch:
                raise PublishError("result branch disappeared while retrying")
        worktree, changed, bootstrap_branch = build_attempt(
            repo,
            artifact_root,
            args,
            fragments,
            policy_path,
            policy_document,
            policy_digest,
            bootstrap=not result_ref.exists,
            bootstrap_branch=f"publisher-result-{os.getpid()}-{attempt}",
            result_sha=result_ref.sha,
        )
        if not changed:
            cleanup_worktree(repo, worktree, bootstrap_branch)
            if captured_ref_is_current(repo, args.remote, result_ref):
                print("publisher: result snapshot already current; no commit or push")
                return 0
            print("publisher: result ref changed during no-op validation; rebuilding", file=sys.stderr)
            if attempt < args.retries:
                time.sleep(min(args.backoff_seconds * (2 ** (attempt - 1)), MAX_BACKOFF_SECONDS))
                continue
            raise PublishError("result ref changed or was deleted during no-op validation")
        try:
            git(["config", "user.email", "actions@github.com"], worktree)
            git(["config", "user.name", "github-actions"], worktree)
            git(["commit", "-m", args.commit_message], worktree)
            pushed = push_attempt(repo, args.remote, worktree, result_ref)
        finally:
            if worktree.exists():
                cleanup_worktree(repo, worktree, bootstrap_branch)
        if pushed:
            print("publisher: committed and pushed one result snapshot")
            return 0
        if attempt < args.retries:
            time.sleep(min(args.backoff_seconds * (2 ** (attempt - 1)), MAX_BACKOFF_SECONDS))
    raise PublishError(f"push failed after {args.retries} attempts")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repo", default=".", help="source checkout containing the configured remote")
    result.add_argument("--remote", default="origin")
    result.add_argument("--artifacts", required=True)
    result.add_argument("--policy", default="config/exclusions.json")
    result.add_argument("--class-a-start", type=int, required=True)
    result.add_argument("--class-a-end", type=int, required=True)
    result.add_argument("--class-b-block-start", type=int)
    result.add_argument("--class-b-starts")
    result.add_argument("--count", type=int, default=1)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-number", type=int, required=True)
    result.add_argument("--run-attempt", type=int, required=True)
    result.add_argument("--retries", type=int, default=5)
    result.add_argument("--backoff-seconds", type=float, default=1.0)
    result.add_argument("--temp-dir", default=None)
    result.add_argument("--commit-message", default="publish validated scan snapshot")
    result.add_argument("--bootstrap-orphan", "--allow-orphan", action="store_true", dest="bootstrap_orphan")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if (
            args.count != 1
            or args.retries < 1
            or args.retries > MAX_PUBLISH_RETRIES
            or args.backoff_seconds < 0
            or args.backoff_seconds > MAX_BACKOFF_SECONDS
        ):
            raise PublishError("count, retries, or backoff is outside its safe range")
        if args.temp_dir is None:
            args.temp_dir = tempfile.gettempdir()
        if args.class_b_block_start is not None and args.class_b_starts is not None:
            raise PublishError("use either --class-b-block-start or --class-b-starts, not both")
        if args.class_b_block_start is None and args.class_b_starts is None:
            raise PublishError("a 64-Class-B block selector is required")
        if args.class_b_starts is not None:
            try:
                args.class_b_starts = [int(value) for value in args.class_b_starts.split(",") if value != ""]
            except ValueError as exc:
                raise PublishError("Class-B starts must be decimal integers") from exc
        return publish(args)
    except (OSError, PublishError, ContractError, subprocess.CalledProcessError) as exc:
        print(f"publish-result: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
