#!/bin/bash
set -euo pipefail

outdir=".github/workflows"
mkdir -p "$outdir"

classb_list=$(seq -s, 0 16 240)
classb_list="${classb_list%,}"

for g in $(seq 0 15); do
    a_start=$((g * 16))
    a_end=$((g * 16 + 15))
    classa_list=$(seq -s, "$a_start" 1 "$a_end")
    classa_list="${classa_list%,}"

    cat > "$outdir/$g.yml" <<EOF
name: Scan Class A $a_start-$a_end

on:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        classa: [$classa_list]
        classb: [$classb_list]
    steps:
      - uses: actions/checkout@v7
      - run: sudo apt-get update -qq && sudo apt-get install -y -qq nmap
      - run: ./scan-classb.sh \${{ matrix.classa }} \${{ matrix.classb }} 16
      - uses: actions/upload-artifact@v7
        with:
          name: scan-\${{ matrix.classa }}-\${{ matrix.classb }}
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
          pattern: scan-*
          merge-multiple: true
          path: downloaded/
      - name: stage render tool
        run: |
          mkdir -p /tmp/render-tool
          cp tools/csv2bin.py /tmp/render-tool/
      - name: build results/<A>.txt
        run: |
          mkdir -p results
          for ca in $(seq -s ' ' "$a_start" 1 "$a_end"); do
            find downloaded -maxdepth 1 -name "\${ca}.*.txt" -exec cat {} + | sort -t. -k2,2n -k3,3n > "results/\${ca}.txt"
          done
      - uses: actions/upload-artifact@v7
        with:
          name: classa-$g
          path: results/*.txt
      - name: commit scan result to result branch
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          git config user.email "actions@github.com"
          git config user.name "github-actions"
          git fetch origin result || true
          git checkout -B result origin/result 2>/dev/null || git checkout -b result
          git add results/*.txt
          git commit -m "aggregate class A $a_start-$a_end" || echo "nothing new"
          for i in \$(seq 1 12); do
            git pull --rebase origin result 2>/dev/null || true
            git push origin "HEAD:refs/heads/result" && break
            sleep 3
          done
      - name: render bin + manifest
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          rm -rf /tmp/scan-data /tmp/render-out
          mkdir -p /tmp/scan-data /tmp/render-out
          git fetch origin result || true
          git archive origin/result | tar -x -C /tmp/scan-data
          python3 /tmp/render-tool/csv2bin.py /tmp/scan-data/results --out /tmp/render-out
          git checkout -B result origin/result 2>/dev/null || git checkout -b result
          cp /tmp/render-out/* .
          git add .
          git commit -m "render bin + manifest" || echo "nothing new"
          for i in \$(seq 1 12); do
            git pull --rebase origin result 2>/dev/null || true
            git push origin "HEAD:refs/heads/result" && break
            sleep 3
          done
EOF
done

echo "generated 16 workflow files in $outdir/"
