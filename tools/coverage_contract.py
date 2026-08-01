#!/usr/bin/env python3
"""Shared strict validation and deterministic helpers for coverage documents."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any


class ContractError(ValueError):
    """Raised when an input does not satisfy the publication contract."""


POLICY_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UINT_RE = re.compile(r"^(0|[1-9][0-9]*)$")

# These values are part of the reviewed Phase-3 scan envelope.  The workflow
# repeats them explicitly and the publisher checks that every fragment really
# came from that bounded configuration.
REVIEWED_SCAN_CONFIG = {
    "nmap_max_rate": 25,
    "nmap_timeout_seconds": 120,
    "retry_delay_seconds": 1,
    "scan_attempts": 2,
    "scan_workers": 4,
}

REQUIRED_FRAGMENT_PROVENANCE = frozenset(
    {
        "executor",
        "nmap_bin",
        "nmap_options",
        "nmap_max_rate",
        "nmap_timeout_seconds",
        "retry_delay_seconds",
        "scan_attempts",
        "scan_workers",
        "source_run_id",
        "source_job_id",
    }
)
OPTIONAL_FRAGMENT_PROVENANCE = frozenset({"nmap_version"})
REQUIRED_FRAGMENT_FIELDS = frozenset(
    {
        "artifact_only",
        "class_a",
        "class_b",
        "policy_digest",
        "policy_name",
        "policy_version",
        "provenance",
        "schema",
        "schema_version",
        "states",
    }
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{label} is not UTF-8") from exc

    def pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise ContractError(f"non-standard JSON constant {value}")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (json.JSONDecodeError, ContractError) as exc:
        raise ContractError(f"{label} is malformed JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{label} must contain a JSON object")
    return value


def _uint(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ContractError(f"{label} must be an integer in 0..{maximum}")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def validate_policy_fields(document: dict[str, Any], label: str = "coverage") -> tuple[str, str, str]:
    name = _text(document.get("policy_name"), f"{label}.policy_name")
    version = _text(document.get("policy_version"), f"{label}.policy_version")
    digest = _text(document.get("policy_digest"), f"{label}.policy_digest")
    if not POLICY_DIGEST_RE.fullmatch(digest):
        raise ContractError(f"{label}.policy_digest is not a sha256 digest")
    return name, version, digest


def expected_nmap_options(rate: int) -> list[str]:
    return [
        "-sn",
        "-n",
        "-T5",
        "--max-rate",
        str(rate),
        "--max-rtt-timeout",
        "200ms",
        "--max-retries",
        "1",
        "--host-timeout",
        "300ms",
        "--min-hostgroup",
        "256",
        "-oX",
        "-",
    ]


def validate_provenance(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    keys = set(value)
    missing = REQUIRED_FRAGMENT_PROVENANCE - keys
    unknown = keys - REQUIRED_FRAGMENT_PROVENANCE - OPTIONAL_FRAGMENT_PROVENANCE
    if missing:
        raise ContractError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise ContractError(f"{label} contains unknown fields: {sorted(unknown)}")
    if value.get("executor") != "scan-classb.sh":
        raise ContractError(f"{label}.executor is not scan-classb.sh")
    for key in ("nmap_bin", "source_run_id", "source_job_id"):
        if not isinstance(value[key], str) or not value[key]:
            raise ContractError(f"{label}.{key} must be a non-empty string")
    if "nmap_version" in value and value["nmap_version"] is not None and (
        not isinstance(value["nmap_version"], str) or not value["nmap_version"]
    ):
        raise ContractError(f"{label}.nmap_version must be a non-empty string when present")
    if not isinstance(value["nmap_options"], list) or not all(
        isinstance(item, str) for item in value["nmap_options"]
    ):
        raise ContractError(f"{label}.nmap_options must be an array of strings")
    for key in REVIEWED_SCAN_CONFIG:
        item = value[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ContractError(f"{label}.{key} must be a non-negative integer")
        if item != REVIEWED_SCAN_CONFIG[key]:
            raise ContractError(f"{label}.{key} is outside the reviewed scan configuration")
    if value["nmap_options"] != expected_nmap_options(value["nmap_max_rate"]):
        raise ContractError(f"{label}.nmap_options does not match nmap_max_rate")
    return value


def validate_fragment(document: dict[str, Any], class_a: int, class_b: int, label: str) -> dict[str, Any]:
    missing = REQUIRED_FRAGMENT_FIELDS - set(document)
    unknown = set(document) - REQUIRED_FRAGMENT_FIELDS
    if missing:
        raise ContractError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise ContractError(f"{label} contains unknown fields: {sorted(unknown)}")
    if document.get("schema") != "harvest-moon.coverage-fragment" or document.get("schema_version") != 2:
        raise ContractError(f"{label} has an unsupported coverage-fragment schema")
    if document.get("artifact_only") is not True:
        raise ContractError(f"{label} is not marked artifact_only")
    if _uint(document.get("class_a"), f"{label}.class_a", 255) != class_a:
        raise ContractError(f"{label} has the wrong Class A")
    if _uint(document.get("class_b"), f"{label}.class_b", 255) != class_b:
        raise ContractError(f"{label} has the wrong Class B")
    states = document.get("states")
    if not isinstance(states, str) or len(states) != 256 or any(state not in "SZE" for state in states):
        raise ContractError(f"{label}.states must contain exactly 256 S/Z/E characters")
    validate_policy_fields(document, label)
    validate_provenance(document.get("provenance"), f"{label}.provenance")
    return document


def validate_canonical_provenance(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    required = {"run_id", "run_number", "run_attempt", "source"}
    missing = required - set(value)
    unknown = set(value) - required
    if missing:
        raise ContractError(f"{label} is missing required fields: {sorted(missing)}")
    if unknown:
        raise ContractError(f"{label} contains unknown fields: {sorted(unknown)}")
    if not isinstance(value["run_id"], str) or not value["run_id"]:
        raise ContractError(f"{label}.run_id must be a non-empty string")
    if isinstance(value["run_number"], bool) or not isinstance(value["run_number"], int) or value["run_number"] < 0:
        raise ContractError(f"{label}.run_number must be a non-negative integer")
    if isinstance(value["run_attempt"], bool) or not isinstance(value["run_attempt"], int) or value["run_attempt"] < 1:
        raise ContractError(f"{label}.run_attempt must be a positive integer")
    if value["source"] != "github-actions":
        raise ContractError(f"{label}.source is not github-actions")
    return value


def validate_canonical_coverage(document: dict[str, Any], class_a: int, label: str) -> dict[str, Any]:
    if document.get("schema") != "harvest-moon.coverage" or document.get("schema_version") != 1:
        raise ContractError(f"{label} has an unsupported canonical coverage schema")
    if _uint(document.get("class_a"), f"{label}.class_a", 255) != class_a:
        raise ContractError(f"{label} has the wrong Class A")
    policy = document.get("policy")
    if not isinstance(policy, dict):
        raise ContractError(f"{label}.policy must be an object")
    policy_name = _text(policy.get("name"), f"{label}.policy.name")
    policy_version = _text(policy.get("version"), f"{label}.policy.version")
    policy_digest = _text(policy.get("digest"), f"{label}.policy.digest")
    if not POLICY_DIGEST_RE.fullmatch(policy_digest):
        raise ContractError(f"{label}.policy.digest is not a sha256 digest")
    maps = document.get("class_b")
    if not isinstance(maps, list) or len(maps) != 256:
        raise ContractError(f"{label}.class_b must contain 256 maps")
    for expected_b, item in enumerate(maps):
        if not isinstance(item, dict):
            raise ContractError(f"{label}.class_b[{expected_b}] must be an object")
        if _uint(item.get("class_b"), f"{label}.class_b[{expected_b}].class_b", 255) != expected_b:
            raise ContractError(f"{label}.class_b is not ordered")
        states = item.get("states")
        if not isinstance(states, str) or len(states) != 256 or any(state not in "SZEU" for state in states):
            raise ContractError(f"{label}.class_b[{expected_b}].states is invalid")
        if item.get("policy_digest") != policy_digest or item.get("policy_name") != policy_name or item.get("policy_version") != policy_version:
            raise ContractError(f"{label}.class_b[{expected_b}] has inconsistent policy data")
        if "provenance" not in item:
            raise ContractError(f"{label}.class_b[{expected_b}] is missing provenance")
        # U is deliberately migration-only: it may have no scan provenance at
        # all (for example, a legacy raw file without a coverage document).
        # Verified states must always retain the strict executor provenance.
        if set(states) == {"U"} and item.get("provenance") is None:
            continue
        validate_provenance(item.get("provenance"), f"{label}.class_b[{expected_b}].provenance")
    validate_canonical_provenance(document.get("provenance"), f"{label}.provenance")
    return document


def source_digest(parts: list[tuple[str, bytes]]) -> str:
    """Hash named source files with explicit domain/path separators."""
    digest = hashlib.sha256()
    digest.update(b"harvest-moon.source.v1\0")
    for path, content in sorted(parts, key=lambda item: item[0]):
        encoded_path = path.encode("utf-8")
        digest.update(b"path\0")
        digest.update(str(len(encoded_path)).encode("ascii"))
        digest.update(b"\0")
        digest.update(encoded_path)
        digest.update(b"\0data\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0end\0")
    return "sha256:" + digest.hexdigest()


def coverage_summary(maps: list[str]) -> dict[str, int]:
    counts = {state: 0 for state in "SZEU"}
    for states in maps:
        for state in states:
            counts[state] += 1
    counts["F"] = 0
    return counts


def ipv4_is_canonical(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4 or any(not UINT_RE.fullmatch(part) for part in parts):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts) and str(ipaddress.ip_address(value)) == value
    except ValueError:
        return False
