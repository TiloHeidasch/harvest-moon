#!/bin/bash
set -euo pipefail

classa=$1
classb_spec="${2:-}"
shift 2
classc_list=("$@")

# parse classb spec: "N" (single), "N-M" (range), or empty (all)
if [[ "$classb_spec" == *-* ]]; then
    classb_start="${classb_spec%-*}"
    classb_end="${classb_spec#*-}"
elif [[ -n "$classb_spec" ]]; then
    classb_start="$classb_spec"
    classb_end="$classb_spec"
else
    classb_start=0
    classb_end=255
fi

outdir="results"
mkdir -p "$outdir"
outfile="$outdir/$classa.txt"
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

    if [[ ${#classc_list[@]} -gt 0 ]]; then
        # one or more /24 subnets → report count per /24
        for classc_val in "${classc_list[@]}"; do
            nmap -sn -n -T5 --max-rtt-timeout 200ms \
                -oG - "$classa.$classb.$classc_val.0/24" \
                2>/dev/null | awk '/Status: Up/{c++} END{print "'"$classa.$classb.$classc_val.0"'"","c}' >> "$outfile" || true
        done
    else
        # whole /16 subnet → group by /24, report count per /24
        nmap -sn -n -T5 --max-rtt-timeout 200ms \
            --min-hostgroup 65536 \
            -oG - "$classa.$classb.0.0/16" \
            2>/dev/null | awk '/Status: Up/{split($2,a,"."); k=a[1]"."a[2]"."a[3]".0"; c[k]++} END{for(k in c) print k","c[k]}' >> "$outfile" || true
    fi
done

# generate 256x256 PNG from the collected /24 counts
if [[ -s "$outfile" ]] && command -v convert &>/dev/null; then
    awk -F'[.,]' -v a="$classa" '
        $1==a { pixel[$2*256+$3] = $5 }
        END   { for(i=0;i<65536;i++) printf "%c", (pixel[i]+0) }
    ' "$outfile" | convert -depth 8 -size 256x256 gray:- "$outdir/$classa.png"
fi
