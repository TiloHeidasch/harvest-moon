#!/usr/bin/env bash
# Scan one contiguous set of Class-B networks with a bounded, fail-closed
# worker pool. Scanner output is structured XML and is never exposed live.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=config/exclusions.sh
. "$SCRIPT_DIR/config/exclusions.sh"

DEFAULT_CLASSB_COUNT=8
DEFAULT_SCAN_WORKERS=2
DEFAULT_NMAP_MAX_RATE=25
DEFAULT_NMAP_TIMEOUT_SECONDS=120
DEFAULT_SCAN_ATTEMPTS=2
DEFAULT_SCAN_RETRY_DELAY=1

# These are deliberately fixed in the executor. Raising them requires a
# code/documentation review rather than an environment-variable change.
HARD_MAX_SCAN_WORKERS=4
HARD_MAX_NMAP_MAX_RATE=50
HARD_MAX_NMAP_TIMEOUT_SECONDS=180
HARD_MAX_SCAN_ATTEMPTS=3
HARD_MAX_SCAN_RETRY_DELAY=10

PARSER="$SCRIPT_DIR/tools/parse_nmap_xml.py"
RUNNER="$SCRIPT_DIR/tools/run_nmap.py"
COVERAGE_WRITER="$SCRIPT_DIR/tools/write_coverage_fragment.py"

die() {
    printf 'scan-classb: %s\n' "$*" >&2
    exit 2
}

is_canonical_uint() {
    [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

# Compare only after a canonical decimal string has been established. This
# avoids shell arithmetic overflow on hostile input.
uint_at_most() {
    local value=$1
    local maximum=$2
    local value_len=${#value}
    local maximum_len=${#maximum}

    (( value_len < maximum_len )) && return 0
    (( value_len > maximum_len )) && return 1
    [[ "$value" < "$maximum" || "$value" == "$maximum" ]]
}

validate_cli_uint() {
    local name=$1
    local value=$2
    local maximum=$3

    is_canonical_uint "$value" || die "$name must be a canonical non-negative decimal integer"
    uint_at_most "$value" "$maximum" || die "$name is outside 0..$maximum"
}

validate_env_uint() {
    local name=$1
    local value=$2
    local minimum=$3
    local maximum=$4

    is_canonical_uint "$value" || die "$name must be a canonical non-negative decimal integer"
    uint_at_most "$value" "$maximum" || die "$name exceeds hard maximum $maximum"
    uint_at_most "$minimum" "$value" || die "$name must be at least $minimum"
}

resolve_executable() {
    local name=$1
    local value=$2

    [[ -n "$value" ]] || die "$name must not be empty"
    if [[ "$value" == */* ]]; then
        [[ -x "$value" ]] || die "$name is not executable: $value"
    else
        command -v "$value" >/dev/null 2>&1 || die "$name was not found on PATH: $value"
    fi
}

if (( $# != 2 && $# != 3 )); then
    die 'usage: ./scan-classb.sh A B_START [COUNT]'
fi

classa=$1
classb_start=$2
classb_count=${3:-$DEFAULT_CLASSB_COUNT}

validate_cli_uint 'class A' "$classa" 255
validate_cli_uint 'class-B start' "$classb_start" 255
validate_cli_uint 'class-B count' "$classb_count" 256
(( classb_count >= 1 )) || die 'class-B count must be at least 1'

# These additions are safe because all operands were bounded above first.
classb_end=$((classb_start + classb_count - 1))
(( classb_end <= 255 )) || die 'class-B start plus count must not exceed 256'

SCAN_WORKERS=${SCAN_WORKERS:-$DEFAULT_SCAN_WORKERS}
NMAP_MAX_RATE=${NMAP_MAX_RATE:-$DEFAULT_NMAP_MAX_RATE}
NMAP_TIMEOUT_SECONDS=${NMAP_TIMEOUT_SECONDS:-$DEFAULT_NMAP_TIMEOUT_SECONDS}
SCAN_ATTEMPTS=${SCAN_ATTEMPTS:-$DEFAULT_SCAN_ATTEMPTS}
SCAN_RETRY_DELAY=${SCAN_RETRY_DELAY:-$DEFAULT_SCAN_RETRY_DELAY}
NMAP_BIN=${NMAP_BIN:-nmap}
PYTHON_BIN=${PYTHON_BIN:-python3}
SCAN_ARTIFACT_DIR=${SCAN_ARTIFACT_DIR:-artifacts}

validate_env_uint SCAN_WORKERS "$SCAN_WORKERS" 1 "$HARD_MAX_SCAN_WORKERS"
validate_env_uint NMAP_MAX_RATE "$NMAP_MAX_RATE" 1 "$HARD_MAX_NMAP_MAX_RATE"
validate_env_uint NMAP_TIMEOUT_SECONDS "$NMAP_TIMEOUT_SECONDS" 1 "$HARD_MAX_NMAP_TIMEOUT_SECONDS"
validate_env_uint SCAN_ATTEMPTS "$SCAN_ATTEMPTS" 1 "$HARD_MAX_SCAN_ATTEMPTS"
validate_env_uint SCAN_RETRY_DELAY "$SCAN_RETRY_DELAY" 0 "$HARD_MAX_SCAN_RETRY_DELAY"
resolve_executable NMAP_BIN "$NMAP_BIN"
resolve_executable PYTHON_BIN "$PYTHON_BIN"

tmpdir=''
runner_registry=''
envelope_tmp=''
publish_pid=''
declare -a child_pids=()
declare -a child_keys=()
overall_failed=0
cleanup_running=0

read_registry_pids() {
    local registry_file pid
    [[ -n "$runner_registry" && -d "$runner_registry" ]] || return 0
    for registry_file in "$runner_registry"/*.pid; do
        [[ -f "$registry_file" ]] || continue
        pid=$(<"$registry_file")
        [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
        printf '%s\n' "$pid"
    done
}

signal_registered() {
    local signal_name=$1
    local pid
    while IFS= read -r pid; do
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
            # child.pid is a process-group leader created with
            # start_new_session; runner.pid is the Python supervisor itself.
            kill -"$signal_name" "$pid" 2>/dev/null || true
            kill -"$signal_name" "-$pid" 2>/dev/null || true
        fi
    done < <(read_registry_pids)
}

terminate_children() {
    local pid alive tick
    (( cleanup_running == 0 )) || return 0
    cleanup_running=1
    set +e

    # Signal scanner process groups first, then their shell supervisors.
    signal_registered TERM
    if [[ -n "$publish_pid" ]]; then
        kill -TERM "$publish_pid" 2>/dev/null || true
    fi
    for pid in "${child_pids[@]:-}"; do
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
    done

    # Give TERM handlers a bounded opportunity to reap. This also makes an
    # external TERM/INT bounded rather than an indefinite wait.
    for (( tick = 0; tick < 20; tick++ )); do
        alive=0
        for pid in "${child_pids[@]:-}"; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                alive=1
                break
            fi
        done
        (( alive == 0 )) && break
        sleep 0.1
    done

    signal_registered KILL
    if [[ -n "$publish_pid" ]]; then
        kill -KILL "$publish_pid" 2>/dev/null || true
    fi
    for pid in "${child_pids[@]:-}"; do
        [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
    done
    for pid in "${child_pids[@]:-}"; do
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
    done
    if [[ -n "$publish_pid" ]]; then
        wait "$publish_pid" 2>/dev/null || true
    fi
    child_pids=()
    child_keys=()
    publish_pid=''
    set -e
}

on_signal() {
    local signal_name=$1
    terminate_children
    trap - EXIT
    [[ -z "$envelope_tmp" ]] || rm -f "$envelope_tmp"
    rm -rf "$tmpdir" 2>/dev/null || true
    if [[ "$signal_name" == TERM ]]; then
        exit 143
    fi
    exit 130
}

on_exit() {
    local rc=$?
    trap - EXIT
    terminate_children
    [[ -z "$envelope_tmp" ]] || rm -f "$envelope_tmp"
    [[ -z "$tmpdir" ]] || rm -rf "$tmpdir"
    exit "$rc"
}

trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap on_exit EXIT

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/scan-classb.XXXXXX")
status_dir=$tmpdir/status
state_dir=$tmpdir/state
raw_dir=$tmpdir/raw
runner_registry=$tmpdir/runners
publish_dir=$tmpdir/publish
mkdir -p "$status_dir" "$state_dir" "$raw_dir" "$runner_registry" "$publish_dir/results" "$publish_dir/coverage"

mkdir -p "$SCAN_ARTIFACT_DIR"
envelope_name="scan-${classa}-${classb_start}-${classb_count}.tar"
envelope_path="$SCAN_ARTIFACT_DIR/$envelope_name"
envelope_tmp="$SCAN_ARTIFACT_DIR/.${envelope_name}.tmp.$$"

printf 'scanning %s.%s.0.0/16 – %s.%s.0.0/16 (max %s concurrent /24 workers)\n' \
    "$classa" "$classb_start" "$classa" "$classb_end" "$SCAN_WORKERS"

parse_nmap_output() {
    local raw_file=$1
    local count_file=$2
    local diagnostic_file=$3
    local expected_a=$4
    local expected_b=$5
    local expected_c=$6
    local count

    if ! count=$("$PYTHON_BIN" "$PARSER" "$raw_file" "$expected_a" "$expected_b" "$expected_c" 2>>"$diagnostic_file"); then
        return 1
    fi
    is_canonical_uint "$count" || return 1
    uint_at_most "$count" 256 || return 1
    printf '%s\n' "$count" > "$count_file"
}

write_status() {
    local status_file=$1
    local count=$2
    local temporary="${status_file}.tmp.$$"
    printf 'OK\n%s\n' "$count" > "$temporary"
    mv "$temporary" "$status_file"
}

scan_one_shard() {
    local shard_a=$1
    local shard_b=$2
    local shard_c=$3
    local shard_key="$shard_b.$shard_c"
    local status_file="$status_dir/$shard_key.status"
    local count_file="$status_dir/$shard_key.count"
    local diagnostic_file="$status_dir/$shard_key.diagnostic"
    local attempt raw_file nmap_rc count
    local runner_pid=''
    local runner_file=''

    cleanup_shard_runner() {
        local tick
        if [[ -n "$runner_pid" ]]; then
            kill -TERM "$runner_pid" 2>/dev/null || true
            for (( tick = 0; tick < 10; tick++ )); do
                kill -0 "$runner_pid" 2>/dev/null || break
                sleep 0.1
            done
            kill -KILL "$runner_pid" 2>/dev/null || true
            wait "$runner_pid" 2>/dev/null || true
        fi
    }
    trap 'cleanup_shard_runner; exit 143' INT TERM

    rm -f "$status_file" "$count_file" "$diagnostic_file"
    for (( attempt = 1; attempt <= SCAN_ATTEMPTS; attempt++ )); do
        raw_file="$raw_dir/$shard_key.attempt-$attempt.xml"
        : > "$diagnostic_file"

        # run_nmap.py creates a new session/process group for nmap. The
        # runner pid is registered before wait, while the runner itself
        # registers the process-group leader before emitting output.
        set +e
        "$PYTHON_BIN" "$RUNNER" --timeout "$NMAP_TIMEOUT_SECONDS" \
            --registry "$runner_registry" -- "$NMAP_BIN" \
            -sn -n -T5 --max-rate "$NMAP_MAX_RATE" \
            --max-rtt-timeout 200ms --max-retries 1 --host-timeout 300ms \
            --min-hostgroup 256 -oX - \
            "$shard_a.$shard_b.$shard_c.0/24" > "$raw_file" 2>>"$diagnostic_file" &
        runner_pid=$!
        runner_file="$runner_registry/$runner_pid.runner.pid"
        printf '%s\n' "$runner_pid" > "$runner_file"
        wait "$runner_pid"
        nmap_rc=$?
        rm -f "$runner_file"
        runner_pid=''
        runner_file=''
        set -e

        if (( nmap_rc == 0 )) && parse_nmap_output "$raw_file" "$count_file" "$diagnostic_file" \
            "$shard_a" "$shard_b" "$shard_c"; then
            count=$(<"$count_file")
            write_status "$status_file" "$count"
            return 0
        fi

        rm -f "$count_file" "$status_file"
        if (( attempt < SCAN_ATTEMPTS && SCAN_RETRY_DELAY > 0 )); then
            sleep "$SCAN_RETRY_DELAY"
        fi
    done

    # Diagnostic-only. The parent will never copy this to an artifact.
    printf 'FAILED\n' > "$status_file"
    return 1
}

launch_shard() {
    local shard_b=$1
    local shard_c=$2
    ( scan_one_shard "$classa" "$shard_b" "$shard_c" ) >/dev/null 2>&1 &
    child_pids[${#child_pids[@]}]=$!
    child_keys[${#child_keys[@]}]="$shard_b.$shard_c"
}

read_valid_status() {
    local key=$1
    local status_file="$status_dir/$key.status"
    local count

    [[ -f "$status_file" ]] || return 1
    if ! count=$(awk 'NR == 1 { good = ($0 == "OK") } NR == 2 { value = $0 } NR > 2 { extra = 1 } END { if (!good || extra || value == "") exit 1; print value }' "$status_file"); then
        return 1
    fi
    is_canonical_uint "$count" || return 1
    uint_at_most "$count" 256 || return 1
    [[ "$(wc -l < "$status_file")" -eq 2 ]] || return 1
    printf '%s' "$count"
}

reap_batch() {
    local i pid key rc count
    for (( i = 0; i < ${#child_pids[@]}; i++ )); do
        pid=${child_pids[$i]}
        key=${child_keys[$i]}
        set +e
        wait "$pid"
        rc=$?
        set -e
        if (( rc != 0 )); then
            printf 'scan-classb: shard %s failed (exit %s)\n' "$key" "$rc" >&2
            printf 'F' > "$state_dir/$key"
            overall_failed=1
            continue
        fi
        if ! count=$(read_valid_status "$key"); then
            printf 'scan-classb: shard %s has missing or invalid status\n' "$key" >&2
            printf 'F' > "$state_dir/$key"
            overall_failed=1
            continue
        fi
        if (( count > 0 )); then
            printf 'S' > "$state_dir/$key"
        else
            printf 'Z' > "$state_dir/$key"
        fi
    done
    child_pids=()
    child_keys=()
}

active=0
stop_scheduling=0
for (( classb = classb_start; classb <= classb_end; classb++ )); do
    for (( classc = 0; classc <= 255; classc++ )); do
        rule=$(exclusion_rule_for "$classa" "$classb" "$classc")
        if [[ -n "$rule" ]]; then
            printf 'E' > "$state_dir/$classb.$classc"
            continue
        fi

        launch_shard "$classb" "$classc"
        active=${#child_pids[@]}
        if (( active >= SCAN_WORKERS )); then
            reap_batch
            active=0
            if (( overall_failed != 0 )); then
                stop_scheduling=1
                break
            fi
        fi
    done
    (( stop_scheduling == 0 )) || break
done

if (( ${#child_pids[@]} > 0 )); then
    reap_batch
fi

if (( overall_failed != 0 )); then
    die 'one or more /24 shards failed; no publishable output was created'
fi

write_classb_outputs() {
    local shard_b=$1
    local states=''
    local classc state count rule
    local result_file="$publish_dir/results/$classa.$shard_b.txt"
    local coverage_file="$publish_dir/coverage/$classa.$shard_b.json"

    : > "$result_file"
    for (( classc = 0; classc <= 255; classc++ )); do
        rule=$(exclusion_rule_for "$classa" "$shard_b" "$classc")
        if [[ -n "$rule" ]]; then
            state=E
            [[ ! -f "$status_dir/$shard_b.$classc.status" ]] || die "excluded shard unexpectedly has scanner status"
        else
            count=$(read_valid_status "$shard_b.$classc") || die "required status missing for $classa.$shard_b.$classc"
            if (( count > 0 )); then
                state=S
                printf '%s.%s.%s.0,%s\n' "$classa" "$shard_b" "$classc" "$count" >> "$result_file"
            else
                state=Z
            fi
        fi
        states="${states}${state}"
    done

    [[ ${#states} -eq 256 ]] || die "coverage map for $classa.$shard_b is not 256 characters"
    "$PYTHON_BIN" "$COVERAGE_WRITER" "$coverage_file" "$classa" "$shard_b" "$states" \
        "$EXCLUSION_POLICY_DIGEST" "$EXCLUSION_POLICY_NAME" "$EXCLUSION_POLICY_VERSION" \
        "$NMAP_MAX_RATE" "$NMAP_TIMEOUT_SECONDS" "$SCAN_ATTEMPTS" "$SCAN_WORKERS" \
        "$SCAN_RETRY_DELAY" "$NMAP_BIN" "${NMAP_VERSION:-}" "${SCAN_RUN_ID:-}" \
        "${SCAN_JOB_ID:-}"
}

for (( classb = classb_start; classb <= classb_end; classb++ )); do
    write_classb_outputs "$classb"
done

# The only public write is a complete tar envelope. It is built beside the
# final path and renamed in one filesystem operation, so an old complete
# envelope remains consumable if scan, tar, interruption, or mv fails.
set +e
tar -cf "$envelope_tmp" -C "$publish_dir" results coverage &
publish_pid=$!
wait "$publish_pid"
tar_rc=$?
publish_pid=''
set -e
(( tar_rc == 0 )) || die 'could not create complete artifact envelope'
mv -f "$envelope_tmp" "$envelope_path"
envelope_tmp=''

printf 'scan-classb: published %s Class-B result/coverage pairs at %s\n' "$classb_count" "$envelope_path"
