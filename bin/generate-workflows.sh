#!/usr/bin/env bash
set -euo pipefail

# WORKFLOW_OUTPUT_DIR is intentionally useful to drift tests only.  The
# production default remains the checked-in workflow directory.
outdir="${WORKFLOW_OUTPUT_DIR:-.github/workflows}"
mkdir -p "$outdir"

classb_offset_list=$(seq -s, 0 1 3)
classb_offset_list="${classb_offset_list%,}"

for g in $(seq 0 15); do
    a_start=$((g * 16))
    a_end=$((g * 16 + 15))

    {
        cat <<EOF
name: Scan Class A $a_start-$a_end

on:
  workflow_dispatch:
    inputs:
      authorization_acknowledgement:
        description: 'Type the exact confirmation for this selected Class-A scope.'
        required: true
        type: string
      class_a:
        description: 'Select exactly one Class A owned by this workflow.'
        required: true
        type: choice
        options:
EOF
        for class_a in $(seq "$a_start" 1 "$a_end"); do
            printf "          - '%s'\n" "$class_a"
        done
        cat <<EOF
      class_b_block_start:
        description: 'Select one contiguous 64-Class-B block for this run.'
        required: true
        type: choice
        options:
          - '0'
          - '64'
          - '128'
          - '192'
        default: '0'
      matrix_max_parallel:
        description: 'Maximum concurrent scan jobs (provider-approved choice).'
        required: true
        type: choice
        options:
          - '1'
          - '2'
        default: '1'

permissions:
  contents: read

concurrency:
  group: authorized-internet-scan
  queue: max
  cancel-in-progress: false

jobs:
EOF
        for wave in $(seq 0 15); do
            wave_offset=$((wave * 4))
            printf '  scan_wave_%s:\n' "$wave"
            if (( wave > 0 )); then
                printf '    needs: scan_wave_%s\n' "$((wave - 1))"
            fi
            cat <<EOF
    if: \${{ inputs.authorization_acknowledgement == 'I_HAVE_WRITTEN_AUTHORIZATION' && github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}
    name: Scan wave $wave
    runs-on: ubuntu-latest
    environment: internet-scan
    permissions:
      contents: read
    timeout-minutes: 360
    strategy:
      max-parallel: \${{ fromJSON(inputs.matrix_max_parallel) }}
      matrix:
        classa: ['\${{ inputs.class_a }}']
        classb_offset: [$classb_offset_list]
    steps:
      - uses: actions/checkout@v7
      - run: sudo apt-get update -qq && sudo apt-get install -y -qq nmap
      - id: scan
        env:
          BLOCK_START: \${{ inputs.class_b_block_start }}
          WAVE_OFFSET_BASE: $wave_offset
          CLASS_B_OFFSET: \${{ matrix.classb_offset }}
          CLASS_A: \${{ matrix.classa }}
          JOB_ID: \${{ github.job }}
          SCAN_WORKERS: 4
          NMAP_MAX_RATE: 25
          NMAP_TIMEOUT_SECONDS: 120
          SCAN_ATTEMPTS: 2
          SCAN_RETRY_DELAY: 1
          SCAN_RUN_ID: \${{ github.run_id }}
        run: |
          set -euo pipefail
          case "\$BLOCK_START" in
            0|64|128|192) ;;
            *) printf 'invalid BLOCK_START: %s\n' "\$BLOCK_START" >&2; exit 1 ;;
          esac
          case "\$WAVE_OFFSET_BASE" in
            0|[1-9]|[1-5][0-9]|60) ;;
            *) printf 'invalid WAVE_OFFSET_BASE: %s\n' "\$WAVE_OFFSET_BASE" >&2; exit 1 ;;
          esac
          case "\$CLASS_B_OFFSET" in
            0|[1-9]) ;;
            *) printf 'invalid CLASS_B_OFFSET: %s\n' "\$CLASS_B_OFFSET" >&2; exit 1 ;;
          esac
          classb=\$((10#\$BLOCK_START + 10#\$WAVE_OFFSET_BASE + 10#\$CLASS_B_OFFSET))
          if (( classb < 0 || classb > 255 )); then
            printf 'computed classb out of range: %s\n' "\$classb" >&2
            exit 1
          fi
          export SCAN_JOB_ID="\${JOB_ID}-\${CLASS_A}-\${classb}"
          ./scan-classb.sh "\$CLASS_A" "\$classb" 1
          printf 'classb=%s\n' "\$classb" >> "\$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v7
        with:
          name: scan-\${{ matrix.classa }}-\${{ steps.scan.outputs.classb }}-1
          path: artifacts/scan-\${{ matrix.classa }}-\${{ steps.scan.outputs.classb }}-1.tar
          if-no-files-found: error

EOF
        done
        cat <<EOF
  aggregate:
    needs:
EOF
        for wave in $(seq 0 15); do
            printf '      - scan_wave_%s\n' "$wave"
        done
        cat <<EOF
    runs-on: ubuntu-latest
    concurrency:
      group: result-publisher
      queue: max
      cancel-in-progress: false
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/download-artifact@v7
        with:
          pattern: scan-*
          merge-multiple: false
          path: incoming-artifacts/
      - name: publish validated result snapshot
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: >-
          ./bin/publish-result.sh
          --artifacts incoming-artifacts
          --class-a-start \${{ inputs.class_a }}
          --class-a-end \${{ inputs.class_a }}
          --class-b-block-start \${{ inputs.class_b_block_start }}
          --count 1
          --run-id \${{ github.run_id }}
          --run-number \${{ github.run_number }}
          --run-attempt \${{ github.run_attempt }}
          --policy config/exclusions.json
          --retries 5
EOF
    } > "$outdir/$g.yml"
done

echo "generated 16 workflow files in $outdir/"
