#!/usr/bin/env python3
"""Convert sparse harvest text results to per-Class-A binary files.

Input: one or more text files containing lines of the form
    A.B.C.0,COUNT
(e.g. the per-Class-A result files produced by the scan pipeline).
Lines with count 0 are ignored (no entry is created).

Output (into --out directory):
    <classa>.bin     65536 bytes, one byte per /24, offset = B*256 + C
    manifest.json    JSON list of Class-A numbers that actually have data
"""
import argparse
import datetime
import json
import os
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="result .txt file or directory of .txt files")
    ap.add_argument("--out", default="results", help="output directory")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # classa -> bytearray(65536)
    data = {}

    paths = []
    if os.path.isdir(args.input):
        for name in sorted(os.listdir(args.input)):
            if name.endswith(".txt"):
                paths.append(os.path.join(args.input, name))
    else:
        paths.append(args.input)

    for path in paths:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ip, count = line.split(",")
                    parts = ip.split(".")
                    a = int(parts[0])
                    b = int(parts[1])
                    c = int(parts[2])
                    v = int(count)
                except ValueError:
                    continue
                if v <= 0:
                    continue
                if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255):
                    continue
                buf = data.setdefault(a, bytearray(65536))
                buf[b * 256 + c] = min(v, 255)

    manifest = []
    entries = 0
    for a in sorted(data.keys()):
        manifest.append(a)
        entries += sum(1 for x in data[a] if x)
        with open(os.path.join(args.out, f"{a}.bin"), "wb") as f:
            f.write(data[a])

    # Objekt mit Zeitstempel; die Webseite liest sowohl dieses Format
    # (manifest["classas"] + manifest["generated"]) als auch das alte
    # reine Array-Format. So bleiben bereits gepushte Daten kompatibel.
    manifest_obj = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "classas": manifest,
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest_obj, f)

    print(
        f"wrote {len(manifest)} class-A files, {entries} populated /24 entries",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
