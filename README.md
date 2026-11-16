# ecsproxy

A reverse HTTP proxy for ECS Fargate services, built on [Pingora](https://github.com/cloudflare/pingora).
It discovers containers from an ECS cluster, routes by hostname using docker labels, and gets its own
Let's Encrypt certificates.

## Features

- HTTPS with SNI and ALPN, HTTP/1.1 and HTTP/2; plain HTTP on port 80, optionally redirected to HTTPS.
- Polls the ECS cluster every 5 seconds and groups containers into target groups by docker label.
- Skips containers that fail their ECS health check or the optional `proxy-healthcheck` probe.
- New backends wait out a warmup period before they receive traffic.
- Least-connections routing (in-flight plus queued requests), with per-container connection limits and queueing.
- Retries failed requests up to 10 times on the other backends, round-robin, backing off from 100ms
  (26 seconds in total): connection failures for any request, and timeouts and 500/502/503/504
  responses for idempotent methods (GET, HEAD, PUT, DELETE, OPTIONS) only.
- Let's Encrypt certificates, one per target group covering all of its hostnames: HTTP-01, or DNS-01
  through Route53 for wildcards. The hosted zone is found automatically, including for sub-subdomains.
- The ACME account and certificates are kept in S3 and reloaded on startup. Instances coordinate through
  an S3 lock (conditional writes), so several can run side by side and only one orders each certificate.

## Usage

```
ecsproxy --cluster my-cluster --s3-bucket my-bucket --http-redirect
```

| Option | Default | |
| --- | --- | --- |
| `--cluster` | `$ECS_CLUSTER` | ECS cluster to discover containers in |
| `--s3-bucket` | | Bucket for the ACME account, certificates and locks |
| `--s3-path` | `ecsproxy` | Key prefix inside the bucket |
| `--proxy-constraint` | | Only route to containers whose `proxy-constraint` label equals this |
| `--http-redirect` | off | Redirect HTTP to HTTPS (307, path intact) instead of proxying it |
| `--warmup` | `10` | Seconds a newly healthy backend waits before receiving traffic |
| `--request-timeout` | `60` | Seconds a request may spend queueing, retrying and waiting on a backend |
| `--acme-email` | | Contact email for the Let's Encrypt account |
| `--acme-directory` | Let's Encrypt | ACME directory URL, e.g. the Let's Encrypt staging one |
| `--http-listen` | `0.0.0.0:80` | Plain HTTP listen address |
| `--https-listen` | `0.0.0.0:443` | HTTPS listen address |
| `--threads` | CPU count | Worker threads |

The region comes from `AWS_REGION`. Credentials come from the ECS task role or EC2 instance role, falling
back to the standard AWS chain (access keys in the environment, profiles). Set `RUST_LOG=debug` for more logs.

The role needs `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:DescribeTaskDefinition`; `s3:GetObject`,
`s3:PutObject`, `s3:DeleteObject` on the bucket path; and, for wildcard hostnames,
`route53:ListHostedZones`, `route53:ChangeResourceRecordSets`, `route53:GetChange`.

## Docker labels

Set these on the container definition. Only `proxy-hostname` is required.

| Label | Default | |
| --- | --- | --- |
| `proxy-hostname` | | Hostnames to route and get certificates for, comma separated; `*.example.com` allowed |
| `proxy-group` | task family | Target group ID; containers sharing it are load balanced together |
| `proxy-port` | `8080` | Container port to proxy to |
| `proxy-healthcheck` | | Path that must answer `GET` with 2xx for the container to receive traffic |
| `proxy-maxconns` | unlimited | Maximum in-flight requests to the container; the rest queue |
| `proxy-constraint` | | Must equal `--proxy-constraint` when that option is set |

## Building

Needs a Rust toolchain and `cmake`. `cargo build --release` produces `target/release/ecsproxy`.
Every push to `main` builds linux/arm64 and linux/amd64 binaries and publishes them as release `v1`, `v2`, ...

## Layout

| File | |
| --- | --- |
| `src/main.rs` | CLI options and server wiring |
| `src/discovery.rs` | ECS polling, label parsing, health checks |
| `src/backend.rs` | Backends, target groups, routing table, connection counting |
| `src/proxy.rs` | Request routing, retries, redirects |
| `src/acme.rs` | Certificate issuing and renewal |
| `src/dns.rs` | Route53 records for DNS-01 |
| `src/store.rs` | S3 storage and locking |
| `src/tls.rs` | SNI certificate selection |
