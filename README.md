# git-scanner

A fast, self-contained secret scanner for git repositories, live URLs, local
files and archives. It finds leaked credentials in the working tree, in commit
history, inside minified JavaScript, in `.env` files and in `.zip`/`.tar.gz`
archives — and can verify each hit against the provider's API.

`git-scanner` is a clean-room reimplementation in Go, inspired by the
`LightWeightGitDumper` binary: same idea, tidier architecture, fully open source
(MIT).

## Features

- **Many inputs, one engine** — repo URLs (`https://` / `git@`), web URLs,
  files, directories, or a `.txt` list of targets.
- **History-aware git scanning** — clones a repository and walks the worktree
  *and* commit history, extracting blobs with author/date provenance.
- **~60 built-in rules** — AWS, GitHub/GitLab/Bitbucket, Stripe, Square,
  Shopify, SendGrid, Mailgun, Mailchimp, Slack, Discord, Twilio, Telegram,
  OpenAI/Anthropic/xAI, DigitalOcean, GCP, Vercel, New Relic, Grafana, private
  keys, JWTs and DB/AMQP connection strings.
- **Exposure rules** — exposed `.git/HEAD`, `.git/config` remotes,
  `~/.git-credentials`, S3 bucket hostnames, S3 presigned URLs.
- **Verification** — live checks against provider APIs (GitHub, GitLab, Slack,
  Stripe, SendGrid, OpenAI, Anthropic, Google API keys, Firebase,
  DigitalOcean, Telegram, Discord, Vercel, Mailgun, New Relic, SMTP); keys that
  exist but are restricted (HTTP 403) are reported as verified+restricted.
- **Obfuscation handling** — base64, hex and percent-decoding, binary string
  extraction, archive walking.
- **Verification** — live checks against provider APIs (GitHub, GitLab, Slack,
  Stripe, SendGrid, OpenAI, Anthropic, DigitalOcean, Telegram, Discord, Vercel,
  Mailgun, New Relic, SMTP) to separate real secrets from noise.
- **Custom rules** — supply extra regex patterns as a JSON file.
- **Outputs** — `jsonl`, `csv` or `txt`, with a built-in de-duplicator.
- **Notifications** — verified findings are pushed to Telegram and/or Discord.
- **Config parity** — reads the same `config.json` shape as the original tool.

## Install

```sh
go install github.com/jesuis/git-scanner/cmd/git-scanner@latest
# or
git clone https://github.com/jesuis/git-scanner && cd git-scanner && make build
```

## Usage

```sh
# scan a directory / single file
git-scanner scan ./my-project
git-scanner scan .env

# scan live hosts from a list
git-scanner scan hosts.txt

# scan a repository (worktree + history)
git-scanner scan https://github.com/org/repo

# verify findings against provider APIs
git-scanner scan ./src --verify

# write CSV to a custom directory
git-scanner scan ./src -o findings --format csv

# identify / verify a single secret
git-scanner check ghp_012345678901234567890123456789012345
```

### Recon commands

| command | purpose |
|---------|---------|
| `mass hosts.txt` | high-throughput scan (`--crawl-js` follows bundles, `--check-buckets` triages and scans public S3 buckets) |
| `discover hosts.txt` | find exposed `.git` directories (git-clone with `--scan`) |
| `cve hosts.txt` | probe common misconfigurations / metadata leaks |
| `envcrack hosts.txt` | fetch `.env`/config files and scan them |
| `js https://site` | analyse JS bundles: endpoints, secrets, source maps, subdomains |
| `dump github.com -T <token>` | enumerate repos a forge token can reach (`--scan` to scan) |
| `aws AKIA… --secret-key …` | verify creds, `--deep` to enumerate, `--chain` for role chains |
| `s3 bucket…` | triage buckets for public access, `--scan` to scan their objects |

```sh
git-scanner mass hosts.txt --paths "/,.git/HEAD,.git/config" --decode
git-scanner mass hosts.txt --crawl-js --check-buckets --bucket-objects 5
git-scanner discover hosts.txt --scan
git-scanner js https://app.example.com
git-scanner dump dev.azure.com --org myorg -T <pat> --scan
git-scanner dump gerrit.ex.com -u me -T me:httppass
git-scanner aws AKIAIOSFODNN7EXAMPLE --secret-key wJalr… --deep --json
git-scanner aws AKIA… --secret-key … --chain --depth 3
git-scanner aws AKIA… --secret-key … --env          # Lambda / ECS env vars
git-scanner s3 my-bucket other-bucket --scan
git-scanner s3 --account --access-key AKIA… --secret-key … --scan
```

### Global flags

| flag | description |
|------|-------------|
| `-c, --config` | path to a config file |
| `-v, --verbose` | debug logging |
| `-q, --quiet` | warnings and errors only |
| `--no-color` | disable ANSI colors |
| `-t, --threads` | concurrency override |
| `--timeout` | per-request timeout (seconds) |

## Performance — reaching thousands of hosts per second

Throughput is `concurrency / latency`; everything else is tuning. Measured on a
16-core box against a mixed host list (average response ≈ 2.9 s including
timeouts):

| concurrency | hosts/s |
|-------------|---------|
| 500 | ~180 |
| 4 000 | ~1 370 |
| 12 000 | ~4 385 |

```sh
ulimit -n 200000        # raise the fd limit first (default is often 10240)
GOGC=400 git-scanner mass hosts.txt \
  --concurrency 12000 --timeout 2 --progress 5 -o hits
```

What makes it fast:

- **Pooled DNS + dial by IP** while preserving TLS SNI and the Host header.
  Input may already be `domain ip` (pre-resolved with massdns/dnsx) to skip DNS
  entirely; use `--resolve-only` to emit such a file.
- **Fixed worker pool** (no goroutine per host) fed by a buffered channel.
- **Tuned transport**: keep-alives off for single-path scans, HTTP/2 off,
  dial timeout aligned with the request timeout.
- **Frozen pattern engine** read without locks, `--matches-per-pattern 1`.
- **Sharded de-dup + asynchronous buffered writer** (1 MiB buffers) so disk
  writes never block workers.
- `--rate` caps requests/second; `--paths` fetches several paths per host over a
  single connection.

For IP lists that mostly answer over plain HTTP, add `--scheme http` to avoid a
wasted TLS attempt per host.

### Datacenter profile (e.g. 52 vCPU / 160 GB / 10 Gb/s)

Tune the kernel first, then size concurrency from the **NIC**, not the CPU:

```sh
sudo ./scripts/tune-linux.sh     # sysctl + limits: somaxconn, ports, tw_reuse, bbr
ulimit -n 1048576
GOGC=400 git-scanner mass hosts.txt --profile vps --concurrency 20000 \
  --timeout 3 --scheme http --max-body 256 -o hits
```

Or use the wrapper (handles limits, optional tuning, build and scan):

```sh
TARGETS=hosts.txt OUT=hits TUNE=1 ./scripts/mass-scan.sh
```

`--profile auto|small|vps|max` derives concurrency from the CPU count
(×150 / ×50 / ×250 / ×500) and sets GOGC (0/0/400/800); explicit flags win.

Bandwidth ceiling on 10 Gb/s (≈ 1.25 GB/s of payload) as a function of body size:

| average body | max hosts/s (bandwidth-bound) |
|--------------|-------------------------------|
| 10 KB | ~125 000 |
| 25 KB | ~50 000 |
| 100 KB | ~12 000 |
| 500 KB | ~2 500 |

Conclusions for that box:

- keep `--max-body` at **128–256 KB**, and use `--method head` when you only
  need the status line — then the limit is concurrency, not bandwidth;
- 52 vCPU sustains >100k TLS handshakes/s, so **CPU is not the constraint** and
  a single process is enough;
- ephemeral ports are rarely the issue for a mass scan because the 4-tuple
  varies with the destination IP — the sysctl script still raises the limits;
- watch `dropped:` in the summary: it only appears if the writer buffer
  overflows (raise `--concurrency` then).

## Configuration

```sh
git-scanner config init config.json   # write defaults
git-scanner config show               # print effective config
```

The full schema lives in `config.example.json`. Every section — `performance`,
`scan_limits`, `git_scanner`, `checkers`, `webhooks`, `proxy`, `aws_enum`,
`cve_scan`, `envcrack` — is optional; missing values fall back to sane
defaults.

## Custom rules

```sh
git-scanner scan ./src --patterns rules.json
```

`rules.json` is a JSON array:

```json
[
  {
    "id": "acme-token",
    "description": "Acme API token",
    "regex": "\\b(acme_[A-Za-z0-9]{32})\\b",
    "secret_group": 1,
    "entropy": 3.5,
    "keywords": ["acme_"],
    "tags": ["acme"],
    "allowlist": ["^acme_example$"]
  }
]
```

## Architecture

```
cmd/git-scanner      entry point
internal/cli         commands (scan, check, discover, cve, envcrack, dump, aws, js, config, version)
internal/config      typed config, load/validate/watch
internal/scanner     pipeline orchestrator (proxy-aware)
internal/fetch       high-throughput fetch: pooled DNS, dial-by-IP, tuned client
internal/gitdump     clone + worktree/history extraction
internal/source      target classification (file/dir/url/repo)
internal/patterns    regex engine + built-in rules
internal/analyzer    base64/hex/url decoding, binary strings
internal/checkers    provider verification (incl. AWS SigV4)
internal/aws         SigV4, STS (assume-role), deep enumeration, S3 public triage, Lambda/ECS env
internal/dumper      multi-forge repository enumeration (incl. Gerrit, Azure DevOps)
internal/proxy       rotating proxy pool (http/https/socks5) for scan, checkers and clone
internal/output      jsonl/csv/txt writers + dedup + stream
internal/webhook     telegram/discord
internal/scanners    .env cracking + recovered path wordlists
internal/jscracker   JS crawl, source-map and subdomain discovery
internal/rce         RCE primitives (Laravel/Ignition)
internal/cve         CVE / metadata probing
```

## Status / roadmap

Core and recon features are implemented and tested:

- [x] CLI, config, git + URL + file + archive scanning, pattern engine
- [x] De-obfuscation, output formats, de-dup, verification, webhooks
- [x] AWS SigV4 verification and account enumeration
- [x] Multi-forge token dump (GitHub / GitLab / Gitea / Gogs / Bitbucket / Gerrit / Azure DevOps)
- [x] Proxy pool for scanning, checkers and cloning
- [x] JS crawl with source-map and subdomain discovery
- [x] Rule/wordlist data recovered from the reference binary
- [x] STS assume-role chain walking (privilege escalation routes)
- [x] Public S3 bucket detection and object scanning
- [x] Deep multi-service `aws` enumeration (Secrets, SSM, Lambda, CFN, ECR, RDS, EC2, SQS/SNS, DynamoDB, KMS)
- [x] SOCKS proxy rotation for git cloning
- [x] Lambda / ECS environment variable extraction
- [x] High-throughput `mass` mode (pooled DNS, dial-by-IP, worker pool, async writer)
- [x] JS crawl from a mass scan (bundles followed, base64/hex decoding, endpoints)
- [x] Bucket → content chain (discovered S3 buckets triaged then their objects scanned)

## Development

```sh
make build     # build ./git-scanner
make test      # go test -race ./...
make vet       # go vet ./...
make fmt       # gofmt -s -w .
```

## License

MIT — see [LICENSE](LICENSE).

## Credits

Inspired by the closed-source `LightWeightGitDumper` tool; rule set informed by
the broader secret-scanning ecosystem (gitleaks, trufflehog).
