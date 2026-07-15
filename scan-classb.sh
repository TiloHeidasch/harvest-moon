#!/bin/bash
set -euo pipefail

classa=$1
classb_start=$2
classb_count=${3:-8}
classb_end=$((classb_start + classb_count - 1))

outdir="results"
mkdir -p "$outdir"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "scanning $classa.$classb_start.0.0/16 – $classa.$classb_end.0.0/16 ($((classb_count * 256)) parallel /24)"

for classb in $(seq $classb_start $classb_end); do
    [[ $classa -eq 10 ]] && continue
    [[ $classa -eq 172 && $classb -ge 16 && $classb -le 31 ]] && continue
    [[ $classa -eq 192 && $classb -eq 168 ]] && continue
    [[ $classa -eq 127 ]] && continue
    [[ $classa -ge 224 ]] && continue

    for classc in $(seq 0 1 255); do
        (
            nmap -sn -n -T5 --max-rtt-timeout 200ms \
                --max-retries 1 --host-timeout 300ms \
                --min-hostgroup 256 \
                -oG - "$classa.$classb.$classc.0/24" \
                2>/dev/null | awk '/Status: Up/{split($2,a,"."); k=a[1]"."a[2]"."a[3]".0"; c[k]++} END{for(k in c) print k","c[k]}' > "$tmpdir/$classb.$classc.txt"
        ) &
    done
done
wait

for classb in $(seq $classb_start $classb_end); do
    cat "$tmpdir"/$classb.*.txt > "$outdir/$classa.$classb.txt" 2>/dev/null || true
done