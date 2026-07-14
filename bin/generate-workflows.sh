#!/bin/bash
set -euo pipefail

outdir=".github/workflows"
mkdir -p "$outdir"

classb_list=$(seq -s, 0 4 252)
classb_list="${classb_list%,}"

for a in $(seq 0 255); do
    cat > "$outdir/$a.yml" <<EOF
name: Scan Class A $a

on:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        classb: [$classb_list]
    steps:
      - uses: actions/checkout@v7
      - run: sudo apt-get update -qq && sudo apt-get install -y -qq nmap
      - run: ./scan-classb.sh $a \${{ matrix.classb }}
      - uses: actions/upload-artifact@v7
        with:
          name: scan-$a-\${{ matrix.classb }}
          path: results/
EOF
done

echo "generated 256 workflow files in $outdir/"