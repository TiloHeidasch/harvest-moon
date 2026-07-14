# harvest-moon

## What this is

IP range ping sweeper. `harvest.sh` takes two octets (`$1.$2`) and pings every IP
in `$1.$2.0.0`–`$1.$2.255.255`, skipping RFC 1918, loopback, and multicast/reserved
ranges. Results are written to `$1.$2.txt` as CSV (`ip,true`|`ip,false`).

## Usage

```bash
./harvest.sh 10 0    # sweeps 10.0.0.0–10.0.255.255 → writes 10.0.txt
```

## CI

`.github/workflows/harvest.yml` defines a matrix over `classa`/`classb` in 0–63.
The `echo helloworld` step is a placeholder — not yet wired to run `harvest.sh`.
