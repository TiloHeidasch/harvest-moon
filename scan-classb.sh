#!/bin/bash
set -euo pipefail

classa=$1
classb_start=$2
classb_end=$((classb_start + 1))

outdir="results"
mkdir -p "$outdir"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "scanning $classa.$classb_start.0.0/16 – $classa.$classb_end.0.0/16 (32 parallel /20)"

for classb in $(seq $classb_start $classb_end); do
    [[ $classa -eq 10 ]] && continue
    [[ $classa -eq 172 && $classb -ge 16 && $classb -le 31 ]] && continue
    [[ $classa -eq 192 && $classb -eq 168 ]] && continue
    [[ $classa -eq 127 ]] && continue
    [[ $classa -ge 224 ]] && continue

    for classc in 0 16 32 48 64 80 96 112 128 144 160 176 192 208 224 240; do
        (
            nmap -sn -n -T5 --max-rtt-timeout 200ms \
                --max-retries 1 --host-timeout 300ms \
                --min-hostgroup 65536 \
                -oG - "$classa.$classb.$classc.0/20" \
                2>/dev/null | awk '/Status: Up/{split($2,a,"."); k=a[1]"."a[2]"."a[3]".0"; c[k]++} END{for(k in c) print k","c[k]}' > "$tmpdir/$classb.$classc.txt"
        ) &
    done
done
wait

for classb in $(seq $classb_start $classb_end); do
    cat "$tmpdir"/$classb.*.txt > "$outdir/$classa.$classb.txt" 2>/dev/null || true
done