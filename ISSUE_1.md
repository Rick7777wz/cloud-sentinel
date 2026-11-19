# Issue #1: Correlate direct vs HTTP CONNECT relay failures

## Problem

The existing Go CLI (`main.go`) reports DNS, TCP, CONNECT, TLS and HTTP stages for *one* route at a time. If TLS fails on the relay route, it currently returns the generic `tls_handshake_failure` classification. That observation alone does **not** establish whether the destination or the relay is at fault. The missing feature is route-pair correlation.

## Reproducible RED test

```sh
docker compose run --rm issue1-repro
```

Equivalent local Go command:

```sh
go test -tags=integration -run='^TestIssue1RelayTLSFailure$' -count=1 -v .
```

`TestIssue1RelayTLSFailure` starts an isolated local HTTPS fixture and a minimal HTTP CONNECT relay that replies `200 Connection Established` but drops the connection before TLS completes. It checks:

- Direct path to the same local HTTPS fixture: `healthy`.
- Relay's TCP and HTTP CONNECT: `pass`.
- TLS via relay: `fail`.
- LLM calls from probes: `0`.
- Correlated outcome expected: `relay_path_tls_failure`.

The new `classifyIncident` function in `correlation.go` is an explicit TODO baseline returning `unclassified`, so the integration test is **intentionally red** until the correlation logic is implemented. The test failure should show:

```
Issue #1 RED: want relay_path_tls_failure after comparing both paths, got "unclassified"
```

The existing unit tests (`go test ./...`) should continue to pass without the `integration` build tag.

## Acceptance criteria

1. Implement `classifyIncident` so it identifies a relay-specific TLS failure **only** when the direct path is healthy, CONNECT succeeds and the relayed TLS stage fails for the same target within a bounded observation window.
2. Add negative controls: direct and relayed both fail; CONNECT itself fails; TLS certificate validation fails directly; and unrelated targets must not be correlated.
3. Preserve stage-level evidence and reject unsupported causal claims.
4. Keep normal probes deterministic with `llm_calls = 0`.
5. Make the Docker integration test green; run unit tests and CI before opening a human-reviewed PR.

## Follow-up work (not part of Issue #1)

- Add Toxiproxy-backed fault injection and more scenarios.
- Add an incident queue and Devin-assisted PR workflow.
- Add cost, accuracy, and false-positive benchmarks.
