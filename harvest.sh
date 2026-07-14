#!/bin/bash
set -euo pipefail

classa=$1
# optional: if classb is given, scan only that /16 subnet
classb_only="${2:-}"

outdir="results"
mkdir -p "$outdir"
outfile="$outdir/$classa.txt"
> "$outfile"

re='^[0-9]+$'

for classb in {0..255}; do
    # if a specific classb was requested, skip others
    if [[ -n "$classb_only" ]]; then
        [[ "$classb" != "$classb_only" ]] && continue
    fi

    # skip RFC 1918
    [[ $classa -eq 10 ]] && continue
    [[ $classa -eq 172 && $classb -ge 16 && $classb -le 31 ]] && continue
    [[ $classa -eq 192 && $classb -eq 168 ]] && continue

    # skip loopback
    [[ $classa -eq 127 ]] && continue

    # skip multicast / reserved
    [[ $classa -ge 224 ]] && continue

    # scan /16 by running 256 parallel /24 sub-scans
    seq 0 255 | xargs -P 32 -I{} bash -c \
        "fping -g $classa.$classb.{}.0/24 -a -r 0 -t 100 2>/dev/null || true" \
        2>/dev/null | awk '{print $1",true"}' >> "$outfile"
done
