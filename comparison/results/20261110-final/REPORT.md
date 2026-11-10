# Measured protocol comparison

Run: 2026-11-10T04:27:20.449125+00:00. CPU: INTEL(R) XEON(R) PLATINUM 8573C. Pinned CPU: 0. 9 samples, up to 100,000 messages and 64 MiB of input per sample.

Both parsers receive the same bytes and decode the supported LDAP operation completely. Differential tests compare every typed field and consumed frame length before measurement. The zldap output borrows input; ldap3_proto returns owned allocations. The timing binary uses the normal system allocator; allocation counters run in a separate build.

## Full protocol decode

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 53.8 | 354.0 | 6.58× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 59.6 | 420.1 | 7.04× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 53.3 | 393.1 | 7.37× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 263.5 | 731.5 | 2.78× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 917.8 | 2696.0 | 2.94× | 0.000 | 55.000 | 0 | 3775 |
| entry_many_attributes | 9681.7 | 30742.3 | 3.18× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 231.0 | 4079.9 | 17.66× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 51.5 | 363.7 | 7.07× | 0.000 | 5.000 | 0 | 394 |
| unbind | 50.7 | 202.9 | 4.01× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 49.3 | 337.1 | 6.84× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 752.0 | 1845.0 | 2.45× | 0.000 | 38.000 | 0 | 4460 |

## Decode and read every payload byte

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 159.2 | 481.6 | 3.02× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 143.6 | 528.5 | 3.68× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 124.3 | 465.2 | 3.74× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 422.9 | 894.0 | 2.11× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 2228.3 | 3311.5 | 1.49× | 0.000 | 55.000 | 0 | 3775 |
| entry_many_attributes | 29017.8 | 42727.6 | 1.47× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 209567.8 | 209006.0 | 1.00× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 123.1 | 432.6 | 3.51× | 0.000 | 5.000 | 0 | 394 |
| unbind | 63.3 | 263.2 | 4.16× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 164.5 | 476.2 | 2.89× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 2405.6 | 3129.7 | 1.30× | 0.000 | 38.000 | 0 | 4460 |

## BER validation and representation

This phase compares zldap's complete bounded BER validation plus a borrowed root view with ldap3_lber's recursively materialized BER tree. It performs no LDAP operation conversion. BER tree equivalence is tested separately; the allocation/representation difference is part of this API-level workload.

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_lber ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 35.2 | 137.6 | 3.91× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 42.8 | 181.6 | 4.24× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 33.3 | 121.7 | 3.65× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 57.6 | 385.2 | 6.69× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 222.8 | 1374.9 | 6.17× | 0.000 | 47.000 | 0 | 3397 |
| entry_many_attributes | 2103.8 | 21945.5 | 10.43× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 102.9 | 4433.2 | 43.08× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 33.2 | 124.5 | 3.75× | 0.000 | 5.000 | 0 | 394 |
| unbind | 20.4 | 63.3 | 3.10× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 33.3 | 139.9 | 4.20× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 190.5 | 1190.3 | 6.25× | 0.000 | 38.000 | 0 | 4460 |

## Repeated encoding from reusable structured inputs

ldap3_proto consumes its owned input, so this phase includes cloning that input on each repetition. zldap borrows its input and reuses a prevalidated BER Filter. Output buffers for both are allocated before timing. These numbers describe those native API contracts, not an isolated copy primitive.

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 74.9 | 513.5 | 6.86× | 0.000 | 13.000 | 0 | 430 |
| bind_sasl | 110.0 | 549.7 | 5.00× | 0.000 | 16.000 | 0 | 501 |
| bind_response | 88.7 | 506.2 | 5.71× | 0.000 | 11.000 | 0 | 421 |
| search_simple | 219.9 | 828.2 | 3.77× | 0.000 | 24.000 | 0 | 784 |
| search_complex | 237.4 | 4451.7 | 18.75× | 0.000 | 97.000 | 0 | 2929 |
| entry_many_attributes | 10823.2 | 63413.2 | 5.86× | 0.000 | 1303.000 | 0 | 30506 |
| entry_large_value | 4353.6 | 242425.5 | 55.68× | 0.000 | 26.000 | 0 | 262725 |
| search_done | 81.4 | 517.3 | 6.35× | 0.000 | 11.000 | 0 | 424 |
| unbind | 39.5 | 220.3 | 5.58× | 0.000 | 4.000 | 0 | 209 |

## Whole-process memory

RSS comes from `wait4` for the specific benchmark child. Compiler processes are excluded. It includes both libraries, all fixtures and caller buffers, so it must not be attributed to either parser. Per-operation heap peaks are reported separately above.

| Run | Peak RSS bytes | User CPU seconds | System CPU seconds |
| --- | ---: | ---: | ---: |
| allocations | 12,058,624 | 0.242 | 0.008 |
| errors | 12,058,624 | 0.003 | 0.000 |
| timing | 12,058,624 | 60.476 | 0.353 |

## Scope and limits

Rejection behavior is recorded in `errors.csv`; timing of malformed and oversized input is in the `rejection_policy` rows. Those rows intentionally include known acceptance-policy differences and are excluded from speedup claims. Unknown operation support and stricter integer/Filter validation differ between implementations.

`results.csv` also reports messages/second, ns/byte, and per-sample min/max latency. The minimum and maximum are variation across samples, not a confidence interval. `*-process.json` records child-specific harness peak RSS; GNU time is a fallback where `wait4` is unavailable. It includes corpora and is not a per-parser memory figure. A shared virtual machine can introduce noise. Results do not measure a Kanidm server, network handling, TLS, authentication, or an identity database.

## Claim and evidence checks

- Complete supported fields: equal field streams and independently encoded bytes in `tests/differential.rs`.
- Zero dynamic allocations: measured call counts in `allocations.csv`; input/output/workspace are supplied separately.
- Latency ratios: medians in `timing.csv`; no fixed multiplier is promised across hardware or workloads.
- Safety: benchmark equivalence does not prove memory safety; use the root crate's safe-Rust policy, Miri, and adversarial tests.
- Evaluation limits: one machine and a fixed synthetic corpus; full payload scans and rejection differences remain visible.
