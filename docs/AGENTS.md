# Documentation guidance

The numbered scan workflows are manual, default-branch-only operations. A bare
click selects no inputs: `github.run_number` deterministically selects one Class
A and one of the four contiguous 64-Class-B tiles (`slot=(run_number-1)%64`).
It creates exactly 64 one-Class-B jobs in 16 dependency-gated waves of four
cells. Each wave waits for the previous wave, so no cell waits behind
`max-parallel` for 24 hours. The reviewed workflow bounds are four
`/24` workers at 25 Nmap packets/second each, so two matrix jobs are at most
200 packets/second repository-wide. One Class-B job is planned at about 257
minutes worst case; the last cell of a wave begins after about 12.85 hours and
the wave completes in about 17.1 hours at parallelism 1. All 16 waves take
about 5.7 days at the fixed parallelism 2 (11.4 days at 1), within the 35-day
limit. Four consecutive runs cover one Class A; 64 runs cover the workflow's
16 × 4 tiles. This does not restore a broad legacy scope.

The protected `internet-scan` environment must be configured in GitHub to allow
deployments only from the default branch. Provider permission for the
deterministically selected scope and environment approval remain manual prerequisites;
documentation must not imply that CI can manufacture those approvals. There is
no cron or automatic full-IPv4 scan.

Keep artifact, policy, publisher, and result-branch descriptions aligned with
`docs/scan-operations.md` and the workflow generator. Document only the
bounded one-Class-B envelope and serialized publication contract. A publisher
merges only the selected block into persistent Class-A results; every
unscanned Class-B map is `U` until that block is verified. Legacy raw rows are
preserved as `U`, never presented as verified coverage. A policy digest change
rejects a partial merge unless a separately reviewed full migration exists.
