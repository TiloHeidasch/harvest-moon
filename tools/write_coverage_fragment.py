#!/usr/bin/env python3
"""Write one deterministic, artifact-only Class-B coverage fragment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("class_a", type=int)
    parser.add_argument("class_b", type=int)
    parser.add_argument("states")
    parser.add_argument("policy_digest")
    parser.add_argument("policy_name")
    parser.add_argument("policy_version")
    parser.add_argument("nmap_max_rate", type=int)
    parser.add_argument("nmap_timeout_seconds", type=int)
    parser.add_argument("scan_attempts", type=int)
    parser.add_argument("scan_workers", type=int)
    parser.add_argument("retry_delay_seconds", type=int)
    parser.add_argument("nmap_bin")
    parser.add_argument("nmap_version")
    parser.add_argument("source_run_id")
    parser.add_argument("source_job_id")
    args = parser.parse_args()
    if len(args.states) != 256 or any(state not in "SZE" for state in args.states):
        print("coverage states must contain exactly 256 S/Z/E characters", file=sys.stderr)
        return 1
    if any(value < 0 or value > 255 for value in (args.class_a, args.class_b)):
        print("coverage class address is outside 0..255", file=sys.stderr)
        return 1

    provenance = {
        "executor": "scan-classb.sh",
        "nmap_bin": args.nmap_bin,
        "nmap_options": [
            "-sn",
            "-n",
            "-T5",
            "--max-rate",
            str(args.nmap_max_rate),
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
        ],
        "nmap_max_rate": args.nmap_max_rate,
        "nmap_timeout_seconds": args.nmap_timeout_seconds,
        "retry_delay_seconds": args.retry_delay_seconds,
        "scan_attempts": args.scan_attempts,
        "scan_workers": args.scan_workers,
        "nmap_version": args.nmap_version or None,
        "source_run_id": args.source_run_id or None,
        "source_job_id": args.source_job_id or None,
    }
    document = {
        "artifact_only": True,
        "class_a": args.class_a,
        "class_b": args.class_b,
        "policy_digest": args.policy_digest,
        "policy_name": args.policy_name,
        "policy_version": args.policy_version,
        "provenance": provenance,
        "schema": "harvest-moon.coverage-fragment",
        "schema_version": 2,
        "states": args.states,
    }
    args.output.write_text(
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
