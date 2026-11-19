# Cloud Sentinel

A small Go probe that tells a **destination failure** apart from a **relay failure**. Uptime checks only see "down". This tool runs the same target twice — direct, then through an HTTP CONNECT proxy you own — and names a cause only when the evidence supports it.

It does not call an LLM. `llm_calls` is always 0.

## What it does

Stages, in order: DNS, TCP, optional HTTP CONNECT, TLS 1.2+, HTTP GET.

| Outcome | Meaning |
|---|---|
| `healthy` | TLS and HTTP both completed |
| `dns_failure` | Local resolver failed and there is no proxy |
| `tcp_failure` | Could not open TCP to the target or the proxy |
| `connect_failure` | Proxy did not return `200 Connection Established` |
| `tls_handshake_failure` | TCP (and CONNECT, if used) succeeded; TLS did not |
| `http_failure` | TLS succeeded; HTTP failed or returned 5xx |

`-compare` adds one extra field, `incident`:

| Incident | When |
|---|---|
| `relay_path_tls_failure` | Direct path is `healthy`, CONNECT is `pass`, relayed TLS fails, same target, reports within 30s |
| `unclassified` | Both paths fail, CONNECT itself fails, the direct path has a bad certificate, or the targets differ |

The rule refuses a cause it cannot prove. Stage JSON is kept either way.

## Quick start

Go 1.22+.

```bash
go test ./...
go run . -target example.com:443
```

Compare a direct path with a proxy you are allowed to use:

```bash
go run . -compare -target example.com:443 -proxy 127.0.0.1:8888
```

Issue #1 reproduction (local HTTPS fixture + a CONNECT relay that drops before TLS):

```bash
go test -tags=integration -run='^TestIssue1RelayTLSFailure$' -count=1 -v .
docker compose run --rm issue1-repro
```

Sample compare output (shape, not a captured run):

```json
{
  "target": "example.com:443",
  "incident": "relay_path_tls_failure",
  "llm_calls": 0,
  "direct": { "outcome": "healthy", "route": "direct" },
  "relay": { "outcome": "tls_handshake_failure", "route": "http_connect_relay" }
}
```

## Tests

- Unit: self-signed TLS is `tls_handshake_failure`; a closed port is `tcp_failure`.
- Correlation negatives: both-fail, CONNECT fail, direct certificate fail, different targets stay `unclassified`.
- Integration: the Issue #1 fixture must return `relay_path_tls_failure`.

## Scope

Authorized checks of a host you name. No credentials, no auto-remediation, no production changes. Do not publish private hostnames or unsanitized logs.

Inspired by Prometheus Blackbox Exporter and Shopify Toxiproxy. This repo does not copy their code.
