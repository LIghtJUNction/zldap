#!/usr/bin/env python3
"""Render measured values only; no inferred server-level performance claims."""
import csv
import json
from pathlib import Path
import sys

directory = Path(sys.argv[1])
rows = list(csv.DictReader((directory / "results.csv").open()))
metadata = json.loads((directory / "metadata.json").read_text())
paired = {}
for row in rows:
    paired.setdefault((row["case"], row["phase"]), {})[row["implementation"]] = row

lines = [
    "# Measured protocol comparison", "",
    f"Run: {metadata['utc']}. CPU: {metadata.get('cpu_model', metadata['platform'])}. "
    f"Pinned CPU: {metadata['pinned_cpu']}. {metadata['samples']} samples, "
    f"up to {metadata['iterations']:,} messages and 64 MiB of input per sample.", "",
    "Both parsers receive the same bytes and decode the supported LDAP operation completely. "
    "Differential tests compare every typed field and consumed frame length before measurement. "
    "The zldap output borrows input; ldap3_proto returns owned allocations. "
    "The timing binary uses the normal system allocator; allocation counters run in a separate build.", "",
]
for phase, title in [("decode", "Full protocol decode"), ("decode_and_scan", "Decode and read every payload byte"), ("ber_decode", "BER validation and representation"), ("encode_reuse", "Repeated encoding from reusable structured inputs")]:
    if not any(row_phase == phase for _, row_phase in paired):
        continue
    lines += [f"## {title}", ""]
    reference = "ldap3_lber" if phase == "ber_decode" else "ldap3_proto"
    if phase == "ber_decode":
        lines += ["This phase compares zldap's complete bounded BER validation plus a borrowed root view with ldap3_lber's recursively materialized BER tree. It performs no LDAP operation conversion. BER tree equivalence is tested separately; the allocation/representation difference is part of this API-level workload.", ""]
    if phase == "encode_reuse":
        lines += ["ldap3_proto consumes its owned input, so this phase includes cloning that input on each repetition. "
                  "zldap borrows its input and reuses a prevalidated BER Filter. Output buffers for both are allocated before timing. "
                  "These numbers describe those native API contracts, not an isolated copy primitive.", ""]
    lines += ["Median latency is per message; peak heap is maximum live parser/encoder heap during one operation, excluding caller input, output, and workspace.", "",
              f"| Scenario | zldap ns/msg | {reference} ns/msg | Ratio | zldap alloc/msg | oracle alloc/msg | zldap peak B | oracle peak B |",
              "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for (case, row_phase), implementations in paired.items():
        if row_phase != phase:
            continue
        z, k = implementations["zldap"], implementations[reference]
        ratio = float(k["median_ns_per_message"]) / float(z["median_ns_per_message"])
        lines.append(f"| {case} | {float(z['median_ns_per_message']):.1f} | {float(k['median_ns_per_message']):.1f} | {ratio:.2f}× | {z['allocations_per_message']} | {k['allocations_per_message']} | {z['peak_live_heap_bytes']} | {k['peak_live_heap_bytes']} |")
    lines.append("")
process_rows = []
for path in sorted(directory.glob("*-process.json")):
    process = json.loads(path.read_text())
    if process.get("peak_rss_bytes") is not None:
        process_rows.append(f"| {path.name.removesuffix('-process.json')} | {process['peak_rss_bytes']:,} | {process['user_cpu_seconds']:.3f} | {process['system_cpu_seconds']:.3f} |")
if process_rows:
    lines += ["## Whole-process memory", "",
              "RSS comes from `wait4` for the specific benchmark child. Compiler processes are excluded. It includes both libraries, all fixtures and caller buffers, so it must not be attributed to either parser. Per-operation heap peaks are reported separately above.", "",
              "| Run | Peak RSS bytes | User CPU seconds | System CPU seconds |",
              "| --- | ---: | ---: | ---: |", *process_rows, ""]
lines += [
    "## Scope and limits", "",
    "Rejection behavior is recorded in `errors.csv`; timing of malformed and oversized input is in the `rejection_policy` rows. "
    "Those rows intentionally include known acceptance-policy differences and are excluded from speedup claims. "
    "Unknown operation support and stricter integer/Filter validation differ between implementations.", "",
    "`results.csv` also reports messages/second, ns/byte, and per-sample min/max latency. "
    "The minimum and maximum are variation across samples, not a confidence interval. "
    "`*-process.json` records child-specific harness peak RSS; GNU time is a fallback where `wait4` is unavailable. It includes corpora and is not a per-parser memory figure. "
    "A shared virtual machine can introduce noise. Results do not measure a Kanidm server, network handling, TLS, authentication, or an identity database.", "",
    "## Claim and evidence checks", "",
    "- Complete supported fields: equal field streams and independently encoded bytes in `tests/differential.rs`.",
    "- Zero dynamic allocations: measured call counts in `allocations.csv`; input/output/workspace are supplied separately.",
    "- Latency ratios: medians in `timing.csv`; no fixed multiplier is promised across hardware or workloads.",
    "- Safety: benchmark equivalence does not prove memory safety; use the root crate's safe-Rust policy, Miri, and adversarial tests.",
    "- Evaluation limits: one machine and a fixed synthetic corpus; full payload scans and rejection differences remain visible.", "",
]
(directory / "REPORT.md").write_text("\n".join(lines))
