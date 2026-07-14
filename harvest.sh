#!/bin/bash
set -euo pipefail

classa=$1
block=$2

classb_start=$((block * 16))
classb_end=$((classb_start + 15))

outdir="results"
mkdir -p "$outdir"
outfile="$outdir/$classa.$block.txt"
pngfile="$outdir/$classa.$block.png"
> "$outfile"

for ((classb=classb_start; classb<=classb_end; classb++)); do
    # skip RFC 1918
    [[ $classa -eq 10 ]] && continue
    [[ $classa -eq 172 && $classb -ge 16 && $classb -le 31 ]] && continue
    [[ $classa -eq 192 && $classb -eq 168 ]] && continue

    # skip loopback
    [[ $classa -eq 127 ]] && continue

    # skip multicast / reserved
    [[ $classa -ge 224 ]] && continue

    # scan /16 subnet → group by /24, count per /24
    nmap -sn -n -T5 --max-rtt-timeout 200ms \
        --min-hostgroup 65536 \
        -oG - "$classa.$classb.0.0/16" \
        2>/dev/null | awk '/Status: Up/{split($2,a,"."); k=a[1]"."a[2]"."a[3]".0"; c[k]++} END{for(k in c) print k","c[k]}' >> "$outfile" || true
done

# generate 16x256 PNG (16 classb × 256 classc)
if [[ -s "$outfile" ]] && command -v convert &>/dev/null; then
    awk -F'[.,]' -v a="$classa" -v start="$classb_start" '
        $1==a && $2>=start && $2<start+16 {
            cb = $2 - start
            cc = $3
            pixel[cc * 16 + cb] = $5
        }
        END { for(i=0;i<4096;i++) printf "%c", (pixel[i]+0) }
    ' "$outfile" | convert -depth 8 -size 16x256 gray:- "$pngfile"
fi
