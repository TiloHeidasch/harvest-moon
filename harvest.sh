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
        # single /24 subnet → report count for that /24
        nmap -sn -n -T5 --max-rtt-timeout 200ms \
            -oG - "$classa.$classb.$classc_only.0/24" \
            2>/dev/null | awk '/Status: Up/{c++} END{print "'"$classa.$classb.$classc_only.0"'"","c}' >> "$outfile" || true
    else
        # whole /16 subnet → group by /24, report count per /24
        nmap -sn -n -T5 --max-rtt-timeout 200ms \
            --min-hostgroup 65536 \
            -oG - "$classa.$classb.0.0/16" \
            2>/dev/null | awk '/Status: Up/{split($2,a,"."); k=a[1]"."a[2]"."a[3]".0"; c[k]++} END{for(k in c) print k","c[k]}' >> "$outfile" || true
    fi
done
