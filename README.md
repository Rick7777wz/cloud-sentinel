# Cloud Sentinel (early prototype)

A small, open-source starting point for **evidence-based network incident diagnosis**. This repository contains a real, runnable Go probe and tests. It is **not yet** an autonomous SRE platform; the integrations below are a roadmap.

## What works today

- A Go CLI that performs deterministic **DNS -> TCP -> optional HTTP CONNECT -> TLS -> HTTP** checks.
- JSON output with each stage's state, duration and error, plus a basic failure classification.
- A zero-LLM-call monitoring path (the CLI does not use AI or external model APIs).
- Unit tests for a TLS certificate failure and an unreachable TCP endpoint.

## Quick start

Requires Go 1.22+.

```bash
go test ./...
go run . -target example.com:443
```

Optional HTTP CONNECT relay check (use a proxy **you own or are authorized to test**):

```bash
go run . -target example.com:443 -proxy 127.0.0.1:8888
```

The command prints a JSON report like this (illustrative, not a captured run):

```json
{
  "timestamp": "2026-11-19T00:00:00Z",
  "target": "example.com:443",
  "route": "direct",
  "stages": {
    "dns": {"state": "pass", "latency_ms": 8},
    "tcp": {"state": "pass", "latency_ms": 12},
    "http_connect": {"state": "skipped"},
    "tls": {"state": "pass", "latency_ms": 32},
    "http": {"state": "pass", "latency_ms": 45}
  },
  "outcome": "healthy",
  "llm_calls": 0
}
```

## Architecture (current and proposed)

```text
[Go probes] ----JSON----> [FastAPI ingestion - planned]
    |                         |
    |                    [correlation rules - planned]
    |                         |
    |                [incident + repro evidence]
    |                         |
    +-- no AI in checks --> [Linear task - planned]
                              |
                         [Devin - planned]
                              |
                     [tested GitHub PR - planned]
                              |
                       [human approval]
```

### Next steps

1. Add reproducible fault injection with Docker Compose and Toxiproxy.
2. Add a probe comparison engine for direct-versus-relayed requests.
3. Publish labeled incident fixtures and accuracy/cost benchmarks.
4. Integrate alert deduplication and a human-reviewed Devin PR workflow.

## Scope and safety

This is a starter implementation for authorized testing, **not** a finished product. No credentials are needed. The probe only checks a host that the operator specifies; no automatic remediation or production deployment occurs. Avoid publishing private hosts, credentials, or unsanitized logs.

## Inspiration and attribution

Project concepts are informed by the ecosystem around Prometheus Blackbox Exporter and Shopify Toxiproxy. This repository does **not** claim ownership of those projects or copy their code.
