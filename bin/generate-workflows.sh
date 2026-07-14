#!/bin/bash
set -euo pipefail

outdir=".github/workflows"
mkdir -p "$outdir"

classb_list=$(seq -s, 0 8 248)
classb_list="${classb_list%,}"

for a in $(seq 0 255); do
    cat > "$outdir/$a.yml" <<EOF
name: Scan Class A $a

on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'

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

  aggregate:
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/download-artifact@v7
        with:
          pattern: scan-$a-*
          merge-multiple: true
          path: downloaded/
      - run: |
          mkdir -p results
          find downloaded -name '*.txt' -exec cat {} + | sort -t. -k2,2n -k3,3n > results/$a.txt
      - uses: actions/upload-artifact@v7
        with:
          name: classa-$a
          path: results/$a.txt
      - name: commit to result branch
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          git config user.email "actions@github.com"
          git config user.name "github-actions"
          git fetch origin result || true
          git checkout -B result origin/result 2>/dev/null || git checkout -b result
          git add results/$a.txt
          git commit -m "aggregate class A $a" || echo "nothing new"
          for i in \$(seq 1 12); do
            git pull --rebase origin result 2>/dev/null
            git push origin "HEAD:refs/heads/result" && break
            sleep 3
          done
EOF
done

echo "generated 256 workflow files in $outdir/"