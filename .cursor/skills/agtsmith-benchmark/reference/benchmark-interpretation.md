# Benchmark Interpretation

## make check

Runs template safety, query policy regression, environment profile tests, and TDIR unit tests. Fail here before live benchmarks.

## spl-hardening-benchmark

Exercises the live MCP path. Zero rows is not always failure — confirm HTTP 200 and structured MCP payloads.

## langgraph-topology-eval

Offline experiment runner. Does not change production topology unless you promote results manually.

## Release gate (fork)

1. `make check`
2. `make spl-hardening-benchmark` against local `127.0.0.1:8089`
3. `make screenshots` for doc refresh
4. `make splunk-app-package` with no secrets in tarball
