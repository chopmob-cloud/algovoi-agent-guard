# Benchmarks

Measured with `time.perf_counter` against the real code — no mocks, no stubs. Each
hot path is warmed up, then timed over N independent calls; the table reports
throughput and median / p95 latency. The benchmark script is `tools/bench.py`
(reproduce: `python tools/bench.py <repo> <outdir>`).

Two environments, same source tree:

| Host | OS | Python | cryptography |
|------|----|--------|--------------|
| workstation | win32 | 3.12.10 | 48.0.0 |
| vm2 (cleanroom) | linux | 3.12.3 | 50.0.2 |

## Hot paths (empty / small ledger)

| Operation | win32 ops/s | win32 median | linux ops/s | linux median |
|-----------|-------------|--------------|-------------|--------------|
| `evaluate()` pure (no commit) | 1,226 | 0.61 ms | 1,504 | 0.62 ms |
| `verify_decision()` offline | 787 | 0.94 ms | 1,085 | 0.88 ms |
| `decide()` ALLOW + atomic commit (n=200, growing ledger) | 45 | 19.6 ms | 498 | 1.94 ms |

`evaluate` and `verify_decision` are the read paths a third party runs to recompute a
receipt; both stay around a thousand per second on a single core. The commit path is
dominated by `fsync` + full-chain re-verification, not by the Ed25519 signature.

## Ledger scaling (the honest cost)

`Ledger.append` re-verifies the **whole** chain, rewrites the **full** history to a
temp file, `fsync`s, then `os.replace`s. That is O(n) per append and O(n²) to build n
entries — the price of tamper-evidence plus atomic, crash-safe commits. Single-append
latency therefore grows with ledger size:

| Ledger size | win32 median | win32 ops/s | linux median | linux ops/s |
|-------------|--------------|-------------|--------------|-------------|
| 0 (empty) | 10.3 ms | 94 | 2.68 ms | 372 |
| 100 | 20.5 ms | 45 | 11.0 ms | 88 |
| 300 | 37.7 ms | 23 | 26.2 ms | 35 |

`verify_chain` (offline tamper check) scales the same way:

| Ledger size | win32 median | linux median |
|-------------|--------------|--------------|
| 100 | 7.11 ms | 6.64 ms |
| 300 | 23.8 ms | 22.9 ms |
| 500 | 44.0 ms | 35.3 ms |

The empty-append gap (win32 vs linux) is `fsync` cost on the two filesystems, not a
code difference. Figures are from a run on the final gated tree (154 tests green on
both hosts).

## What these numbers are not

- This is a **single-writer reference ledger**, not a distributed settlement rail; do
  not read the commit throughput as a payment-network benchmark.
- For long-lived ledgers, rotate / shard the chain or move to an append-only store with
  periodic checkpoints — the full-rewrite design favours auditability over throughput.
- Numbers are one core, one process, warm cache; single measurements per configuration,
  so treat them as indicative rather than stable. p95 tails on win32 reflect filesystem
  and antivirus scheduling, shown rather than hidden.