# AgentShield Performance Report

## Test Environment

- OS: Darwin arm64
- Python: 3.13.5
- Workload: local synthetic payloads
- Direct mock tool: in-process function call
- Protected SDK: in-process AgentShield wrapper with audit disabled for wrapper-only comparison
- Audit test: 200 SQLite audit writes in a temporary database
- API test: 500 FastAPI `TestClient` evaluation requests
- Concurrency test: 200 policy evaluations with 8 workers

## Policy and SDK Latency

| Workload | Average | p50 | p95 | Maximum |
|---|---:|---:|---:|---:|
| Direct mock call | 0.000 ms | 0.000 ms | 0.000 ms | 0.000 ms |
| Policy evaluation | 0.021 ms | 0.021 ms | 0.023 ms | 0.103 ms |
| Protected SDK call | 0.035 ms | 0.032 ms | 0.041 ms | 0.381 ms |
| SQLite audit write | 0.494 ms | 0.461 ms | 0.767 ms | 1.118 ms |
| FastAPI evaluation API | 3.003 ms | 2.806 ms | 3.770 ms | 12.085 ms |

Direct and sub-millisecond results should be interpreted as local in-process measurements, not network or deployment benchmarks.

## SDK Overhead

Average protected SDK call overhead compared with the direct mock call: **0.034 ms**.

Protected calls remained consistently under 1 ms in this workload; p95 was 0.041 ms.

## API and Concurrency

- API successful evaluations: 500 / 500
- Concurrent policy evaluations: 200 / 200 successful
- Concurrent 200-request elapsed time: 6.409 ms
- Maximum observed API latency: 12.085 ms

## Identified Bottlenecks

No critical bottleneck was observed in the bounded synthetic workload.

Potential scaling costs are:

1. SQLite audit write latency.
2. Audit JSON serialization and database transaction overhead.
3. FastAPI request serialization and TestClient overhead.
4. Deep or near-limit payload normalization.

## Optimization Changes

No optimization was changed in this phase because the measured p95 latency is low and security enforcement is preserved. The existing bounded workload does not justify replacing SQLite or adding caching that could weaken audit correctness.

## Stability Limits

Stress testing was bounded to avoid destabilizing the local machine. The report does not claim production throughput or real-world prompt-injection detection accuracy.
