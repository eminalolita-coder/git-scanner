# Running the scan on a datacenter box

A residential uplink cannot carry thousands of requests per second, and a
rotating datacenter proxy is not a substitute. Measured on a Flashproxy
endpoint (`dc.flashproxy.io:777`, country-US session):

| concurrent connections | useful throughput | failures | latency |
|---|---|---|---|
| 50  | 6.3 req/s  | 18 % | 6.5 s |
| 100 | 11 req/s   | 27 % | 6.6 s |
| 200 | 22 req/s   | 28 % | 6.7 s |

Throughput scales linearly with concurrency, so 4 000 req/s would need
~26 000 permanently open connections to that single endpoint, with a quarter
of the requests failing. Proxies are therefore kept for low-volume,
high-value traffic (re-verification, targeted clones), not for the sweep.

The scan itself belongs on a VPS: the local line then only carries SSH and
the target list.

## Deploy

```bash
# cross-compile a static linux binary, upload it, start under nohup
VPS=user@1.2.3.4 ./scripts/vps.sh deploy ~/fresh200k.txt

# follow progress (throughput, findings, checkpoint, load)
VPS=user@1.2.3.4 ./scripts/vps.sh status

# pull findings + checkpoint + log back to the Windows machine
VPS=user@1.2.3.4 ./scripts/vps.sh fetch
```

`deploy` detects `amd64`/`arm64` on the remote host, uploads
`bin/git-scanner`, `scripts/mass-resilient.sh`, `scripts/tune-linux.sh` and
the target list, then starts the supervised scan. The remote box needs **no
Go toolchain** (`SKIP_BUILD=1`).

## Knobs

| variable | default | meaning |
|---|---|---|
| `VPS` | – | `user@host`, required |
| `PORT` | 22 | ssh port |
| `DIR` | `gs` | remote directory |
| `CONCURRENCY` | 4000 | simultaneous requests |
| `RATE` | 3000 | hard requests/second cap |
| `TIMEOUT` | 6 | per-request timeout (seconds) |
| `ARCH` | auto | `linux/amd64` or `linux/arm64` |
| `SSH_OPTS` | – | extra ssh options (key, jump host) |

```bash
VPS=user@host CONCURRENCY=8000 RATE=4000 TIMEOUT=5 \
  ./scripts/vps.sh deploy ~/fresh200k.txt
```

## Operations

```bash
VPS=user@host ./scripts/vps.sh stop          # stop the supervisor and the scan
VPS=user@host ./scripts/vps.sh start         # restart with the uploaded list
VPS=user@host ./scripts/vps.sh tune          # raise ulimits / netdev budget
```

Progress is checkpointed (`lists/<targets>.ckpt`), so an interruption resumes
where it stopped; the supervisor also exits on a stall (`--stall-exit 90`)
and relaunches with a gentler concurrency and rate.

To start over, delete the checkpoint:

```bash
ssh user@host 'rm ~/gs/lists/*.ckpt'
```

## When to use the proxy instead

The scanner accepts a proxy globally:

```bash
./git-scanner check --from findings.jsonl --only gcp-api-key \
  --proxy 'dc.flashproxy.io:777:user-country-US:pass'
```

A pool is configured in the JSON config (`-c config.json`):

```json
{
  "proxy": {
    "enabled": true,
    "file": "/home/user/proxies.txt",
    "protocol": "http"
  }
}
```

`proxies.txt` takes one `host:port` or `host:port:user:pass` per line, rotated
round-robin for HTTP, checkers and git clones.
