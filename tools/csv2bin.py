#!/usr/bin/env python3
"""Strict, deterministic conversion of sparse Class-A results to binaries.

The legacy ``results/<A>.txt`` format remains the input and each ``<A>.bin``
is still 65,536 bytes at offset ``B * 256 + C``.  Coverage is optional for
old result branches: when it is absent the asset is explicitly marked ``U``
(unverified), never silently promoted to complete data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, NoReturn

try:
    from coverage_contract import (
        ContractError,
        canonical_json_bytes,
        coverage_summary,
        load_json_bytes,
        source_digest,
        validate_canonical_coverage,
    )
except ModuleNotFoundError:  # Importable as tools.csv2bin in tests.
    from tools.coverage_contract import (
        ContractError,
        canonical_json_bytes,
        coverage_summary,
        load_json_bytes,
        source_digest,
        validate_canonical_coverage,
    )


RESULT_NAME = re.compile(r"^(0|[1-9][0-9]*)\.txt$")


def fail(message: str) -> "NoReturn":
    raise ContractError(message)


def parse_results(path: Path, expected_class_a: int) -> tuple[bytearray, dict[tuple[int, int], int], bytes]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{path} is not UTF-8")
        raise AssertionError from exc
    values: dict[tuple[int, int], int] = {}
    buffer = bytearray(65536)
    for number, original in enumerate(text.splitlines(), 1):
        if not original:
            continue
        if original != original.strip():
            fail(f"{path}:{number}: surrounding whitespace is not allowed")
        fields = original.split(",")
        if len(fields) != 2:
            fail(f"{path}:{number}: expected A.B.C.0,COUNT")
        address, count_text = fields
        address_fields = address.split(".")
        if len(address_fields) != 4 or address_fields[3] != "0":
            fail(f"{path}:{number}: invalid fourth octet")
        if any(not re.fullmatch(r"(0|[1-9][0-9]*)", field) for field in address_fields[:3]):
            fail(f"{path}:{number}: non-canonical address")
        if not re.fullmatch(r"(0|[1-9][0-9]*)", count_text):
            fail(f"{path}:{number}: invalid count")
        a, b, c = (int(field) for field in address_fields[:3])
        count = int(count_text)
        if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255):
            fail(f"{path}:{number}: address is outside IPv4 range")
        if a != expected_class_a:
            fail(f"{path}:{number}: row belongs to Class A {a}, not {expected_class_a}")
        if not 1 <= count <= 256:
            fail(f"{path}:{number}: count must be in 1..256")
        key = (b, c)
        if key in values:
            fail(f"{path}:{number}: duplicate/conflicting row for {a}.{b}.{c}.0")
        values[key] = count
        buffer[b * 256 + c] = min(count, 255)
    return buffer, values, raw


def load_coverage(path: Path, class_a: int) -> tuple[dict[str, Any] | None, bytes | None]:
    if not path.exists():
        return None, None
    raw = path.read_bytes()
    document = load_json_bytes(raw, str(path))
    validate_canonical_coverage(document, class_a, str(path))
    return document, raw


def validate_coverage_agreement(
    coverage: dict[str, Any], values: dict[tuple[int, int], int], path: Path
) -> tuple[str, dict[str, int]]:
    maps = coverage["class_b"]
    for class_b_entry in maps:
        b = class_b_entry["class_b"]
        states = class_b_entry["states"]
        for c, state in enumerate(states):
            has_row = (b, c) in values
            if state == "S" and not has_row:
                fail(f"{path}: S state has no raw row for {coverage['class_a']}.{b}.{c}.0")
            if state in "ZE" and has_row:
                fail(f"{path}: {state} state has a raw row for {coverage['class_a']}.{b}.{c}.0")
    maps_text = [entry["states"] for entry in maps]
    summary = coverage_summary(maps_text)
    return ("U" if summary["U"] else "V"), summary


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def discover_inputs(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if not input_path.is_dir():
        fail(f"input does not exist: {input_path}")
    paths = sorted(input_path.iterdir())
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            continue
        if path.suffix == ".txt" and not RESULT_NAME.fullmatch(path.name):
            fail(f"unexpected result filename: {path.name}")
        if path.suffix == ".txt":
            result.append(path)
    return result


def coverage_directory(input_path: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    if input_path.is_file() and input_path.parent.name == "results":
        return input_path.parent.parent / "coverage"
    return input_path.parent / "coverage"


def build(input_path: Path, out_dir: Path, explicit_coverage: Path | None) -> tuple[dict[str, Any], dict[int, bytes]]:
    paths = discover_inputs(input_path)
    coverage_dir = coverage_directory(input_path, explicit_coverage)
    assets: dict[int, bytes] = {}
    asset_metadata: list[dict[str, Any]] = []
    classas: list[int] = []

    for path in paths:
        match = RESULT_NAME.fullmatch(path.name)
        if not match:
            fail(f"unexpected result filename: {path.name}")
        assert match is not None
        class_a = int(match.group(1))
        if class_a > 255:
            fail(f"{path}: Class A outside 0..255")
        if class_a in assets:
            fail(f"duplicate result file for Class A {class_a}")
        binary, values, raw = parse_results(path, class_a)
        coverage_path = coverage_dir / f"{class_a}.json"
        coverage, coverage_raw = load_coverage(coverage_path, class_a)
        if coverage is None:
            coverage_status = "U"
            coverage_path_value = None
            coverage_digest = None
            summary = {state: 0 for state in "SZEU"}
            summary.update({"F": 0, "U": 65536})
            source_parts = [(f"results/{class_a}.txt", raw)]
        else:
            assert coverage_raw is not None
            coverage_status, summary = validate_coverage_agreement(coverage, values, coverage_path)
            coverage_path_value = f"coverage/{class_a}.json"
            coverage_digest = sha256_hex(canonical_json_bytes(coverage) + b"\n")
            source_parts = [(f"results/{class_a}.txt", raw), (coverage_path_value, canonical_json_bytes(coverage) + b"\n")]
        source = source_digest(source_parts)
        assets[class_a] = bytes(binary)
        classas.append(class_a)
        coverage_metadata = {
            "status": coverage_status,
            "path": coverage_path_value,
            "digest": coverage_digest,
            "summary": summary,
        }
        asset_metadata.append(
            {
                "classa": class_a,
                "path": f"{class_a}.bin",
                "byte_length": 65536,
                "sha256": sha256_hex(bytes(binary)),
                "source_digest": source,
                "coverage_status": coverage_status,
                "coverage_path": coverage_path_value,
                "coverage_digest": coverage_digest,
                "coverage_summary": summary,
                "coverage": coverage_metadata,
            }
        )

    classas.sort()
    asset_metadata.sort(key=lambda item: item["classa"])
    manifest: dict[str, Any] = {
        "schema": "harvest-moon.manifest",
        "schema_version": 2,
        "classas": classas,
        "assets": asset_metadata,
    }
    return manifest, assets


def write_outputs(manifest: dict[str, Any], assets: dict[int, bytes], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for path in out_dir.iterdir():
        if path.is_file() and re.fullmatch(r"[0-9]+\.bin", path.name):
            path.unlink()
    for class_a, binary in sorted(assets.items()):
        (out_dir / f"{class_a}.bin").write_bytes(binary)
    (out_dir / "manifest.json").write_bytes(canonical_json_bytes(manifest) + b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="result .txt file or directory")
    parser.add_argument("--out", default="results", help="directory for root assets and manifest")
    parser.add_argument("--coverage-dir", help="canonical coverage directory (default: sibling of input)")
    args = parser.parse_args(argv)
    try:
        input_path = Path(args.input)
        coverage_path = Path(args.coverage_dir) if args.coverage_dir else None
        manifest, assets = build(input_path, Path(args.out), coverage_path)
        write_outputs(manifest, assets, Path(args.out))
    except (OSError, ContractError) as exc:
        print(f"csv2bin: {exc}", file=sys.stderr)
        return 1
    populated = sum(sum(1 for value in binary if value) for binary in assets.values())
    print(f"wrote {len(assets)} class-A files, {populated} populated /24 entries", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
