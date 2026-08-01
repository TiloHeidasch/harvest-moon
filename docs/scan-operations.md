# Scan operations

## Scope and ownership

The scan executor (`scan-classb.sh`), central exclusion descriptor/generator
under `config/`, generated workflows, publisher, converter, and their focused
tests are maintained together. The executor keeps the existing interface:

```text
./scan-classb.sh A B_START [COUNT]
```

The default count is 8. Inputs are canonical decimal integers; `A` is 0--255,
`B_START` is 0--255, `COUNT` is 1--256, and the requested range must end at
Class B 255. A failed or incomplete shard is never represented as zero.

The responsible contact is the repository maintainer team, through the
project's normal issue/security contact. Before a run, the operator must give
the affected address owner or provider a notice containing the scope, time
window, source addresses, packet budget, retry policy, and an abort contact.
The provider's written approval must be retained with the run record.

## Authorization and exclusion policy

There is no automatic authorization in this repository and no automatic full
IPv4 schedule is authorized. A scan is an explicit, manually approved
operation only. Not dispatching a run is the opt-out. A provider or address
owner may opt out by contacting the responsible maintainers; the maintainers
must add the request to `config/exclusions.json` before another run. Operators
may not bypass policy exclusions with an environment variable or a different
command line.

`config/exclusions.json` is the policy source of truth. Its scope is every
IANA IPv4 Special-Purpose Address Registry entry whose `Global` field is
`False`, applied conservatively at whole-/24 granularity. The descriptor also
records the explicit safe/routable exceptions `192.31.196.0/24`,
`192.52.193.0/24`, and `192.175.48.0/24`: IANA marks these special-purpose
service ranges globally reachable and routable, so they remain eligible for an
authorized scan. `192.88.99.0/24` is excluded as deprecated, non-global
6to4-relay-anycast space. The complete ordered rule list and its sources are
only in the JSON descriptor; `config/exclusions.sh` is generated code.

To maintain policy, review the current IANA registry and relevant RFC updates,
edit only `config/exclusions.json`, then regenerate and verify the executable
policy:

```sh
python3 tools/check_exclusions.py --write
python3 tools/check_exclusions.py --check
bash -n config/exclusions.sh
```

The checker defines the exact digest input: UTF-8 JSON with `policy_digest`
removed, recursively sorted keys, and compact separators (`,`, `:`). The
stored value is `sha256:<hex digest>`. A policy change requires a new ordered
rule/rationale, source-date/version review, boundary test, and second
maintainer review. The first matching generated rule is authoritative.

## Executor budgets and scanner contract

The executor uses a bounded pool. Every scanner is run by
`tools/run_nmap.py` in a new session/process group. Its timeout sends TERM to
the complete group, waits one bounded grace interval, then sends KILL and
reaps the direct child. Executor TERM/INT traps also terminate registered
groups and use bounded waits. The ordinary-success path also checks the
original process group after reaping the scanner and applies the same bounded
TERM-to-KILL cleanup, so a fork-and-exit descendant cannot escape the
worker/rate bound. No shell timeout implementation is assumed, so the same
behavior works in the macOS development shell and Ubuntu Actions.

The default and fixed hard maximums are:

| Variable | Default | Hard maximum | Meaning |
| --- | ---: | ---: | --- |
| `SCAN_WORKERS` | 2 | 4 | concurrent `/24` child scans |
| `NMAP_MAX_RATE` | 25 | 50 | nmap packets/second per child |
| `NMAP_TIMEOUT_SECONDS` | 120 | 180 | external timeout per nmap invocation |
| `SCAN_ATTEMPTS` | 2 | 3 | total attempts per shard |
| `SCAN_RETRY_DELAY` | 1 | 10 | seconds between attempts |
| `NMAP_BIN` | `nmap` | n/a | executable scanner, injectable for tests |

The default aggregate send budget is `2 workers × 25 packets/second = 50
packets/second` across the executor. For one `/24` attempt, the conservative
planning calculation allows four normal privileged Nmap discovery probe types
for each of 256 hosts and one retry: `256 × 4 × (1 + 1) = 2,048` probe
transmissions. At the per-child default rate this takes at most `2,048 / 25
= 81.92 seconds` of packet-send time. The 120-second external timeout leaves
38.08 seconds for process startup, scheduling, responses, and XML output; it
is intentionally not a three-second wall-clock shortcut. `--host-timeout
300ms` and `--max-rtt-timeout 200ms` limit individual probe/host waits but do
not replace this aggregate external budget. Two bounded attempts may consume
at most 4,096 planned transmissions for a shard, with the one-second retry
delay also bounded. The hard caps remain finite at four workers, 50 packets/s
per child (200 packets/s aggregate), and 180 seconds per attempt; changing
them requires a code and documentation review.

The workflow intentionally uses the reviewed maximum of four workers and two
matrix jobs. The repository-wide workflow envelope is
`2 × 4 × 25 = 200 packets/second`. A Class-B job's two attempts are planned at
about 257 minutes in the worst case, below the six-hour hosted-job limit.
Every bare workflow click derives `slot=(run_number-1)%64`,
`class_a=workflow_a_start+slot/4`, and
`class_b_block_start=(slot%4)*64`; it therefore scans exactly one Class A ×
one 64-Class-B tile. In each four-cell wave, the last cell starts after
`3 × 257 = 771 minutes` (12.85 hours) and the wave completes after
`4 × 257 = 1,028 minutes` (17.1 hours). Sixteen dependency-gated waves take
about 5.7 days at the fixed parallelism 2 (11.4 days at 1), below GitHub's
35-day workflow limit and without a cell waiting behind `max-parallel` for 24
hours. Four runs cover one Class A; 64 runs cover the workflow's 16 × 4 tiles.

The exact fixed scanner arguments are:

```text
nmap -sn -n -T5 --max-rate RATE --max-rtt-timeout 200ms \
  --max-retries 1 --host-timeout 300ms --min-hostgroup 256 -oX - A.B.C.0/24
```

Nmap XML is required. The validator rejects empty/comment-only, malformed,
truncated, non-successful, or structurally incomplete documents; requires
`runstats/finished`, `hosts total="256"`, canonical counts, and matching
`up`; and requires every observed IPv4 host to be unique, canonical, in the
requested /24, and `up` or `down`. A rejected document cannot create `Z`.

## Atomic output envelope

Successful runs expose exactly one complete artifact envelope, not sequential
live result or coverage directories. The path is:

```text
artifacts/scan-A-B_START-COUNT.tar
```

`SCAN_ARTIFACT_DIR` may select a temporary output parent for tests or an
operator-managed destination. The tar envelope contains:

```text
results/A.B.txt       # sparse A.B.C.0,COUNT rows, positive hosts only
coverage/A.B.json     # one Class-B artifact-only coverage fragment
```

All requested Class-B pairs are staged privately first. The completed tar is
renamed over the final path in one filesystem operation. A scan/parser/tar,
interruption, or rename failure leaves an existing complete envelope intact;
there is no publishable `F` state. Phase 3 uploads this envelope as one input.

Coverage fragments are not canonical aggregate coverage documents. Their
schema is `harvest-moon.coverage-fragment`, `artifact_only` is true, and their
256-character map uses only `S` (scanned with hosts), `Z` (scanned zero), and
`E` (policy-excluded). Phase 3 must validate exactly 64 Class-B fragments for
the selected block and merge them into canonical `coverage/A.json`. Successful
Phase-2 output never contains `F`. Each publishable workflow fragment records the fixed nmap options,
reviewed rate/timeout, attempts, retry delay, worker bound, policy digest,
executor name, the source run ID, and a nonempty source job ID. Scanner version
is the only optional provenance field.

## Phase 3 artifact and publication contract

Numbered workflows are input-free and dispatch-only; they contain no `schedule`
or cron trigger. A dispatch must come from the repository default branch and run
in the protected `internet-scan` environment. Provider permission for the
deterministically selected scope and environment approvals are operational
prerequisites, not values that CI can simulate or bypass. Scan permissions are
read-only; only aggregation has `contents: write`.

The 64 selected Class-B cells run in 16 dependency-gated waves of four cells.
Each wave waits for the preceding wave, so at parallelism 1 the final cell of a
wave begins after `3 × 257 = 771` minutes (12.85 hours) and the wave completes
after `4 × 257 = 1,028` minutes (17.1 hours). All waves take about 11.4 days at
parallelism 1 or 5.7 days at 2, below the 35-day workflow limit and without a
cell waiting behind `max-parallel` for 24 hours.

Every scan job uploads exactly:

```text
artifacts/scan-<classa>-<classb>-1.tar
```

The artifact contains one `results/<A>.<B>.txt` and one
`coverage/<A>.<B>.json` pair. A selected Class A and block therefore produces
exactly 64 one-Class-B envelopes. Aggregation downloads each artifact into its
own directory and calls `bin/publish-result.sh` once. The publisher validates
the complete expected block and safe tar members before touching a temporary
worktree based on the exact fetched result SHA. A missing `result` branch is an
error unless the operator explicitly supplies `--bootstrap-orphan`.

The publisher writes sparse `results/<A>.txt`, canonical
`coverage/<A>.json`, digest-addressed `policy/sha256-<digest>.json`, root
`<A>.bin`, and `manifest.json` together. It removes stale numeric binaries and
legacy `downloaded/` content, makes at most one commit, and retries rejected
pushes with bounded exponential backoff by rebuilding from the newest result
tip. Fetch, validation, commit, and exhausted push errors are fatal. Incoming
run number/attempt/id provenance prevents an older run from replacing newer
Class-A data.

Each rebuild captures the fetched `origin/result` SHA and pushes with the exact
`--force-with-lease=refs/heads/result:<sha>` value. A no-op re-fetches the
remote before returning; a changed or deleted ref is rebuilt or fails after
retry, never reported as an unvalidated no-op. Explicit orphan bootstrap
uses the absent-ref lease `--force-with-lease=refs/heads/result:`; a later ref
deletion is rejected rather than silently recreating an old tip. Temporary
orphan branches are deleted after every attempt.

## Partial coverage and policy migrations

Canonical `coverage/<A>.json` always contains 256 ordered Class-B maps. The
incoming 64 maps replace only their matching Class-B ranges. Missing historical
or unscanned ranges are `U` (migration/incomplete); they are never fabricated
as `S`, `Z`, `E`, or `F`. Existing sparse rows are retained, but rows in a `U`
map remain unverified until that complete Class-B block is scanned again. A
Class A is verified only when all 256 maps contain `S`, `Z`, or `E`. The
converter reports manifest coverage status `U` whenever any map is `U`.

Incoming `E` states are checked against the JSON exclusion policy using
`IPv4Network.overlaps()`, so a future sub-/24 opt-out conservatively excludes
the complete affected /24. A policy name/version/digest mismatch in existing
canonical coverage rejects a partial merge; no unsafe mixed-policy result is
published. There is no publishable `F` state.

## Requirements before any schedule is re-enabled

Before an automated schedule or broad dispatch is considered, all of the
following must be recorded and approved:

1. Written provider and address-owner permission for the exact scope.
2. A named responsible operator, notice recipient, abort contact, and support
   coverage for the complete window.
3. A reviewed packet-rate and concurrency budget below provider limits, with a
   staged canary plan and an explicit stop threshold.
4. Confirmation that the JSON policy and its digest are current in the run
   record.
5. Successful local mocked tests, shell syntax checks, policy checks, and an
   independent review of failure/retry, cleanup, and atomic publication.
6. A documented rollback/disable procedure and evidence that no stale or
   partial result can be consumed as a successful scan.

Until those approvals exist, no cron, recurring workflow, or automatic full
IPv4 schedule is authorized. The numbered workflows intentionally have no
automated schedule at all; adding one requires a new review of this contract.

## Local verification

The focused tests never invoke the network. They inject portable temporary
mock scanner executables and exercise XML parsing, arguments, retries,
timeouts, signals, process cleanup, atomic envelopes, and policy boundaries:

```sh
python3 -m unittest tests.test_scan_classb -v
bash -n scan-classb.sh config/exclusions.sh
python3 tools/check_exclusions.py --check
```

For a result snapshot, conversion is strict and deterministic:

```sh
python3 tools/csv2bin.py results --coverage-dir coverage --out .
```

It preserves the 65,536-byte `<A>.bin` layout, removes numeric binaries whose
raw source disappeared, and records `sha256`, source, and coverage metadata in
the versioned manifest. A raw file without canonical coverage is retained as
legacy `U`/unverified data.

The mocks use Python's portable process/session APIs and standard shell tools;
no GNU-only `timeout` is required on macOS. Ubuntu Actions retains the same
Python/session behavior. A POSIX shell, Python 3, `tar`, and `mktemp` are
required; no real network scan is part of verification.
