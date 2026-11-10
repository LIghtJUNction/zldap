# Measured protocol comparison

Run: 2026-11-10T03:58:03.495349+00:00. CPU: INTEL(R) XEON(R) PLATINUM 8573C. Pinned CPU: 0. 7 samples, up to 30,000 messages and 64 MiB of input per sample.

Both parsers receive the same bytes and decode the supported LDAP operation completely. Differential tests compare every typed field and consumed frame length before measurement. The zldap output borrows input; ldap3_proto returns owned allocations. The timing binary uses the normal system allocator; allocation counters run in a separate build.

The production source for this baseline is preserved at commit `866d947de6f31cb69d5c02513fe3f4b38c9086e8`; its five `src/*.rs` hashes match `metadata.json`.

## Full protocol decode

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 269.2 | 322.0 | 1.20× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 370.9 | 386.7 | 1.04× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 237.1 | 349.4 | 1.47× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 739.7 | 737.7 | 1.00× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 1721.8 | 2731.4 | 1.59× | 0.000 | 55.000 | 0 | 3775 |
| entry_many_attributes | 12998.1 | 29183.4 | 2.25× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 276.6 | 4029.0 | 14.56× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 232.0 | 328.8 | 1.42× | 0.000 | 5.000 | 0 | 394 |
| unbind | 166.2 | 153.1 | 0.92× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 233.6 | 297.9 | 1.27× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 1001.5 | 1861.3 | 1.86× | 0.000 | 38.000 | 0 | 4460 |

## Decode and read every payload byte

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 375.1 | 481.7 | 1.28× | 0.000 | 6.000 | 0 | 428 |
| bind_sasl | 441.7 | 504.4 | 1.14× | 0.000 | 7.000 | 0 | 596 |
| bind_response | 305.3 | 425.6 | 1.39× | 0.000 | 5.000 | 0 | 391 |
| search_simple | 922.3 | 881.0 | 0.96× | 0.000 | 14.000 | 0 | 808 |
| search_complex | 3236.4 | 3254.5 | 1.01× | 0.000 | 55.000 | 0 | 3775 |
| entry_many_attributes | 30354.6 | 42266.8 | 1.39× | 0.000 | 522.000 | 0 | 61229 |
| entry_large_value | 204084.7 | 207888.9 | 1.02× | 0.000 | 9.000 | 0 | 132069 |
| search_done | 291.9 | 401.4 | 1.38× | 0.000 | 5.000 | 0 | 394 |
| unbind | 178.9 | 195.1 | 1.09× | 0.000 | 2.000 | 0 | 193 |
| batch_256_binds | 351.9 | 443.2 | 1.26× | 0.000 | 6.000 | 0 | 429 |
| batch_128_entries | 2546.8 | 3138.0 | 1.23× | 0.000 | 38.000 | 0 | 4460 |

## Repeated encoding from reusable structured inputs

ldap3_proto consumes its owned input, so this phase includes cloning that input on each repetition. zldap borrows its input and reuses a prevalidated BER Filter. Output buffers for both are allocated before timing. These numbers describe those native API contracts, not an isolated copy primitive.

Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.

| Scenario | zldap ns/msg | ldap3_proto ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| bind_small | 81.0 | 584.8 | 7.22× | 0.000 | 13.000 | 0 | 430 |
| bind_sasl | 113.2 | 578.9 | 5.11× | 0.000 | 16.000 | 0 | 501 |
| bind_response | 82.2 | 552.5 | 6.72× | 0.000 | 11.000 | 0 | 421 |
| search_simple | 228.5 | 887.0 | 3.88× | 0.000 | 24.000 | 0 | 784 |
| search_complex | 230.5 | 4511.1 | 19.57× | 0.000 | 97.000 | 0 | 2929 |
| entry_many_attributes | 10540.7 | 58183.5 | 5.52× | 0.000 | 1303.000 | 0 | 30506 |
| entry_large_value | 3640.5 | 234156.0 | 64.32× | 0.000 | 26.000 | 0 | 262725 |
| search_done | 76.4 | 486.2 | 6.37× | 0.000 | 11.000 | 0 | 424 |
| unbind | 41.7 | 215.0 | 5.15× | 0.000 | 4.000 | 0 | 209 |

## Scope and limits

Rejection behavior is recorded in `errors.csv`; timing of malformed and oversized input is in the `rejection_policy` rows. Those rows intentionally include known acceptance-policy differences and are excluded from speedup claims. Unknown operation support and stricter integer/Filter validation differ between implementations.

`results.csv` also reports messages/second, ns/byte, and per-sample min/max latency. The minimum and maximum are variation across samples, not a confidence interval. `*-process.txt` records total harness peak RSS when GNU time is available; it includes corpora and is not a per-parser memory figure. A shared virtual machine can introduce noise. Results do not measure a Kanidm server, network handling, TLS, authentication, or an identity database.

## Claim and evidence checks

- Complete supported fields: equal field streams and independently encoded bytes in `tests/differential.rs`.
- Zero dynamic allocations: measured call counts in `allocations.csv`; input/output/workspace are supplied separately.
- Latency ratios: medians in `timing.csv`; no fixed multiplier is promised across hardware or workloads.
- Safety: benchmark equivalence does not prove memory safety; use the root crate's safe-Rust policy, Miri, and adversarial tests.
- Evaluation limits: one machine and a fixed synthetic corpus; full payload scans and rejection differences remain visible.
