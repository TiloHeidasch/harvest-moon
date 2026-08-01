# Documentation guidance

The numbered scan workflows are manual, default-branch-only operations. A run
selects one Class A and one of the four contiguous 64-Class-B blocks
(`0`, `64`, `128`, or `192`), creating exactly 64 one-Class-B jobs. Matrix
concurrency is 1 or 2 (default 1), in 16 dependency-gated waves of four cells.
Each wave waits for the previous wave, so no cell waits behind `max-parallel`
for 24 hours. The reviewed workflow bounds are four
`/24` workers at 25 Nmap packets/second each, so two matrix jobs are at most
200 packets/second repository-wide. One Class-B job is planned at about 257
minutes worst case; the last cell of a wave begins after about 12.85 hours and
the wave completes in about 17.1 hours at parallelism 1. All 16 waves take
about 11.4 days at parallelism 1 or 5.7 days at 2, within the 35-day limit.

The protected `internet-scan` environment must be configured in GitHub to allow
deployments only from the default branch. Exact written authorization, provider
permission for the scope, and environment approval remain manual prerequisites;
documentation must not imply that CI can manufacture those approvals. There is
no cron or automatic full-IPv4 scan.

Keep artifact, policy, publisher, and result-branch descriptions aligned with
`docs/scan-operations.md` and the workflow generator. Document only the
bounded one-Class-B envelope and serialized publication contract. A publisher
merges only the selected block into persistent Class-A results; every
unscanned Class-B map is `U` until that block is verified. Legacy raw rows are
preserved as `U`, never presented as verified coverage. A policy digest change
rejects a partial merge unless a separately reviewed full migration exists.
