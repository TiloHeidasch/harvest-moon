#!/bin/bash
set -euo pipefail

classa=$1
classb=$2

# skip reserved ranges
[[ $classa -eq 10 ]] && exit 0
[[ $classa -eq 172 && $classb -ge 16 && $classb -le 31 ]] && exit 0
[[ $classa -eq 192 && $classb -eq 168 ]] && exit 0
[[ $classa -eq 127 ]] && exit 0
[[ $classa -ge 224 ]] && exit 0

outdir="results"
mkdir -p "$outdir"
outfile="$outdir/$classa.$classb.txt"
> "$outfile"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "scanning $classa.$classb.0.0/16 (16 parallel /20)"

for classc in 0 16 32 48 64 80 96 112 128 144 160 176 192 208 224 240; do
    (
        nmap -sn -n -T5 --max-rtt-timeout 200ms \
            --max-retries 1 --host-timeout 300ms \
            --min-hostgroup 65536 \
            -oG - "$classa.$classb.$classc.0/20" \
            2>/dev/null | awk '/Status: Up/{split($2,a,"."); k=a[1]"."a[2]"."a[3]".0"; c[k]++} END{for(k in c) print k","c[k]}' > "$tmpdir/$classc.txt"
    ) &
done
wait

cat "$tmpdir"/*.txt > "$outfile"