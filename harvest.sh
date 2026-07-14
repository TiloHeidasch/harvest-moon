#!/bin/bash
set -euo pipefail

classa=$1
classb_only="${2:-}"
classc_only="${3:-}"

outdir="results"
mkdir -p "$outdir"
outfile="$outdir/$classa.txt"
> "$outfile"

for classb in {0..255}; do
    # optional /16 restriction
    [[ -n "$classb_only" && "$classb" != "$classb_only" ]] && continue

    # skip RFC 1918
    [[ $classa -eq 10 ]] && continue
    [[ $classa -eq 172 && $classb -ge 16 && $classb -le 31 ]] && continue
    [[ $classa -eq 192 && $classb -eq 168 ]] && continue

    # skip loopback
    [[ $classa -eq 127 ]] && continue

    # skip multicast / reserved
    [[ $classa -ge 224 ]] && continue

    if [[ -n "$classc_only" ]]; then
        # single /24 subnet
        nmap -sn -n -T5 --max-rtt-timeout 200ms \
            -oG - "$classa.$classb.$classc_only.0/24" \
            2>/dev/null | grep '/Host$' | awk '{print $2",true"}' >> "$outfile"
    else
        # whole /16 subnet
        nmap -sn -n -T5 --max-rtt-timeout 200ms \
            --min-hostgroup 65536 \
            -oG - "$classa.$classb.0.0/16" \
            2>/dev/null | grep '/Host$' | awk '{print $2",true"}' >> "$outfile"
    fi
done
