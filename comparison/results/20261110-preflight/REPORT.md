# Measured protocol comparison

Run: 2026-11-10T04:21:50.611839+00:00. CPU: INTEL(R) XEON(R) PLATINUM 8573C. Pinned CPU: 0. 9 samples, up to 100,000 messages and 64 MiB of input per sample.

Both parsers receive the same bytes and decode the supported LDAP operation completely. Differential tests compare every typed field and consumed frame length before measurement. The zldap output borrows input; ldap3_proto returns owned allocations. The timing binary uses the normal system allocator; allocation counters run in a separate build.

## Full protocol decode

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 42.3 | 340.7 | 8.06× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 48.4 | 402.1 | 8.31× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 39.5 | 361.4 | 9.16× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 252.1 | 684.6 | 2.72× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 897.2 | 2655.0 | 2.96× | 0.000 | 55.000 | 0 | 3775 |
| entry_many_attributes | 9193.9 | 29287.7 | 3.19× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 228.9 | 4480.3 | 19.57× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 40.7 | 321.5 | 7.89× | 0.000 | 5.000 | 0 | 394 |
| unbind | 30.9 | 169.5 | 5.48× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 37.7 | 319.9 | 8.49× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 722.2 | 1852.1 | 2.56× | 0.000 | 38.000 | 0 | 4460 |

## Decode and read every payload byte

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 154.2 | 454.6 | 2.95× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 129.7 | 506.0 | 3.90× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 121.4 | 428.8 | 3.53× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 444.7 | 967.7 | 2.18× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 2178.8 | 3357.6 | 1.54× | 0.000 | 55.000 | 0 | 3775 |
| entry_many_attributes | 28258.1 | 42565.6 | 1.51× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 204107.2 | 210070.0 | 1.03× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 127.2 | 399.9 | 3.14× | 0.000 | 5.000 | 0 | 394 |
| unbind | 54.0 | 223.1 | 4.13× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 142.4 | 444.7 | 3.12× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 2352.7 | 3167.2 | 1.35× | 0.000 | 38.000 | 0 | 4460 |

## BER validation and representation

This phase compares zldap's complete bounded BER validation plus a borrowed root view with ldap3_lber's recursively materialized BER tree. It performs no LDAP operation conversion. BER tree equivalence is tested separately; the allocation/representation difference is part of this API-level workload.

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_lber ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 33.7 | 139.7 | 4.15× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 42.9 | 175.1 | 4.08× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 33.6 | 127.5 | 3.80× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 67.6 | 377.7 | 5.59× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 256.1 | 1383.6 | 5.40× | 0.000 | 47.000 | 0 | 3397 |
| entry_many_attributes | 2427.4 | 21768.6 | 8.97× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 103.3 | 3728.4 | 36.09× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 35.9 | 121.1 | 3.37× | 0.000 | 5.000 | 0 | 394 |
| unbind | 22.3 | 56.4 | 2.52× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 33.9 | 132.5 | 3.91× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 203.4 | 1223.0 | 6.01× | 0.000 | 38.000 | 0 | 4460 |

## Repeated encoding from reusable structured inputs

ldap3_proto consumes its owned input, so this phase includes cloning that input on each repetition. zldap borrows its input and reuses a prevalidated BER Filter. Output buffers for both are allocated before timing. These numbers describe those native API contracts, not an isolated copy primitive.

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 77.6 | 532.1 | 6.85× | 0.000 | 13.000 | 0 | 430 |
| bind_sasl | 116.6 | 559.9 | 4.80× | 0.000 | 16.000 | 0 | 501 |
| bind_response | 80.8 | 529.3 | 6.55× | 0.000 | 11.000 | 0 | 421 |
| search_simple | 236.4 | 870.1 | 3.68× | 0.000 | 24.000 | 0 | 784 |
| search_complex | 249.3 | 4490.2 | 18.01× | 0.000 | 97.000 | 0 | 2929 |
| entry_many_attributes | 10978.6 | 61309.3 | 5.58× | 0.000 | 1303.000 | 0 | 30506 |
| entry_large_value | 3789.1 | 234118.5 | 61.79× | 0.000 | 26.000 | 0 | 262725 |
| search_done | 75.9 | 492.0 | 6.48× | 0.000 | 11.000 | 0 | 424 |
| unbind | 41.2 | 204.3 | 4.96× | 0.000 | 4.000 | 0 | 209 |

## Whole-process memory

RSS comes from `wait4` for the specific benchmark child. Compiler processes are excluded. It includes both libraries, all fixtures and caller buffers, so it must not be attributed to either parser. Per-operation heap peaks are reported separately above.

| Run | Peak RSS bytes | User CPU seconds | System CPU seconds |
| --- | ---: | ---: | ---: |
| allocations | 12,058,624 | 0.254 | 0.004 |
| errors | 12,058,624 | 0.000 | 0.003 |
| timing | 12,058,624 | 58.740 | 0.407 |

## Scope and limits

Rejection behavior is recorded in `errors.csv`; timing of malformed and oversized input is in the `rejection_policy` rows. Those rows intentionally include known acceptance-policy differences and are excluded from speedup claims. Unknown operation support and stricter integer/Filter validation differ between implementations.

`results.csv` also reports messages/second, ns/byte, and per-sample min/max latency. The minimum and maximum are variation across samples, not a confidence interval. `*-process.json` records child-specific harness peak RSS; GNU time is a fallback where `wait4` is unavailable. It includes corpora and is not a per-parser memory figure. A shared virtual machine can introduce noise. Results do not measure a Kanidm server, network handling, TLS, authentication, or an identity database.

## Claim and evidence checks

- Complete supported fields: equal field streams and independently encoded bytes in `tests/differential.rs`.
- Zero dynamic allocations: measured call counts in `allocations.csv`; input/output/workspace are supplied separately.
- Latency ratios: medians in `timing.csv`; no fixed multiplier is promised across hardware or workloads.
- Safety: benchmark equivalence does not prove memory safety; use the root crate's safe-Rust policy, Miri, and adversarial tests.
- Evaluation limits: one machine and a fixed synthetic corpus; full payload scans and rejection differences remain visible.
