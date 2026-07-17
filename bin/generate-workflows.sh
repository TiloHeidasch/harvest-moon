#!/bin/bash
set -euo pipefail

outdir=".github/workflows"
mkdir -p "$outdir"

classb_list=$(seq -s, 0 64 192)
classb_list="${classb_list%,}"

for g in $(seq 0 15); do
    a_start=$((g * 16))
    a_end=$((g * 16 + 15))
    classa_list=$(seq -s, "$a_start" 1 "$a_end")
    classa_list="${classa_list%,}"

    # stagger by 30 min, starting 21:00 UTC (= 22:00 CET) for g=0,
    # finishing 05:00 UTC (= 06:00 CET) for g=15
    start_min=$(( (19 * 60) + g * 30 ))
    cron_min=$(( start_min % 60 ))
    cron_hr=$(( (start_min / 60) % 24 ))

    cat > "$outdir/$g.yml" <<EOF
name: Scan Class A $a_start-$a_end

on:
  workflow_dispatch:
  schedule:
    - cron: "$cron_min $cron_hr * * *"

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
      - run: ./scan-classb.sh \${{ matrix.classa }} \${{ matrix.classb }} 64
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
      - name: commit scan result to result branch
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          git config user.email "actions@github.com"
          git config user.name "github-actions"
          for i in \$(seq 1 20); do
            git fetch origin result || true
            git rebase --abort 2>/dev/null || true
            git merge --abort 2>/dev/null || true
            mv downloaded /tmp/downloaded-scans
            if git rev-parse --verify origin/result >/dev/null 2>&1; then
              git checkout -B result origin/result
              git reset --hard origin/result
            else
              git checkout -B result
            fi
            rm -rf downloaded
            mv /tmp/downloaded-scans downloaded
            mkdir -p results
            for ca in $(seq -s ' ' "$a_start" 1 "$a_end"); do
              find downloaded -maxdepth 1 -name "\${ca}.*.txt" -exec cat {} + | sort -t. -k2,2n -k3,3n > "results/\${ca}.txt"
            done
            git add results/*.txt
            git commit -m "aggregate class A $a_start-$a_end" || echo "nothing new"
            git push origin "HEAD:refs/heads/result" && break
            sleep 3
          done
      - uses: actions/upload-artifact@v7
        with:
          name: classa-$g
          path: results/*.txt
      - name: render bin + manifest
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          git config user.email "actions@github.com"
          git config user.name "github-actions"
          for i in \$(seq 1 20); do
            git fetch origin result || true
            git rebase --abort 2>/dev/null || true
            git merge --abort 2>/dev/null || true
            rm -rf results
            if git rev-parse --verify origin/result >/dev/null 2>&1; then
              git checkout -B result origin/result
              git reset --hard origin/result
              git clean -fd
            else
              git checkout -B result
            fi
            python3 /tmp/render-tool/csv2bin.py ./results --out .
            git add '*.bin' manifest.json
            git commit -m "render bin + manifest" || echo "nothing new"
            git push origin "HEAD:refs/heads/result" && break
            sleep 3
          done
EOF
done

echo "generated 16 workflow files in $outdir/"
