#!/usr/bin/env python3
"""Run timing and allocation experiments in separate binaries, then merge CSV."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=50_000)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--phase", choices=["all", "decode", "decode_and_scan", "ber_decode", "encode_reuse", "rejection_policy"], default="all")
    args = parser.parse_args()
    if args.iterations < 1 or args.samples < 1:
        parser.error("iterations and samples must be positive")
    directory = Path(__file__).resolve().parent
    root = directory.parent
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    if not cargo or not rustc:
        raise SystemExit("cargo and rustc must be on PATH")
    manifest = directory / "Cargo.toml"
    binary = directory / "target" / "release" / ("zldap-comparison.exe" if os.name == "nt" else "zldap-comparison")
    if os.environ.get("CARGO_TARGET_DIR"):
        raise SystemExit("unset CARGO_TARGET_DIR so the binary path is reproducible")
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    cpu = args.cpu if args.cpu is not None else (affinity[0] if affinity else None)
    if cpu is not None and affinity and cpu not in affinity:
        parser.error("selected CPU is outside process affinity")
    prefix = ["taskset", "-c", str(cpu)] if cpu is not None and shutil.which("taskset") else []
    gnu_time = Path("/usr/bin/time").exists() and "GNU" in subprocess.run(
        ["/usr/bin/time", "--version"], capture_output=True, text=True
    ).stdout
    source_paths = sorted([
        *root.glob("src/*.rs"), root / "Cargo.toml", root / "Cargo.lock",
        *directory.glob("src/*.rs"), *directory.glob("tests/*.rs"),
        *directory.glob("*.py"), manifest, directory / "Cargo.lock",
    ])
    hashes = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
    metadata = {
        "utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "rustc": subprocess.check_output([rustc, "-Vv"], text=True),
        "cargo": subprocess.check_output([cargo, "-V"], text=True).strip(),
        "git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True).stdout.strip(),
        "source_sha256": hashes,
        "cpu_affinity": affinity,
        "pinned_cpu": cpu if prefix else None,
        "iterations": args.iterations,
        "samples": args.samples,
        "phase": args.phase,
        "max_input_bytes_per_sample": 64 * 1024 * 1024,
        "oracle_crates": {"ldap3_proto": "0.9.0", "ldap3_lber": "0.9.0"},
        "oracle_source_commit": "f1ec51111756a6ea941a0685827283bb55bb94ac",
        "instrumentation": "timing=system allocator; memory=separate count-allocations feature build",
        "rustflags": os.environ.get("RUSTFLAGS", ""),
        "cargo_encoded_rustflags": os.environ.get("CARGO_ENCODED_RUSTFLAGS", ""),
        "process_measurement": "wait4-child-rusage" if hasattr(os, "wait4") else ("GNU-time" if gnu_time else "unavailable"),
    }
    if Path("/proc/cpuinfo").exists():
        lines = Path("/proc/cpuinfo").read_text().splitlines()
        metadata["cpu_model"] = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("model name")), "unknown")
    if hasattr(os, "getloadavg"):
        metadata["load_average_start"] = os.getloadavg()
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    patch = subprocess.check_output([
        "git", "diff", "--binary", "HEAD", "--", "src", "Cargo.toml", "Cargo.lock",
        "comparison/src", "comparison/tests", "comparison/Cargo.toml", "comparison/Cargo.lock",
        "comparison/run.py", "comparison/summarize.py",
    ], cwd=root)
    (out / "source_changes.patch").write_bytes(patch)

    def execute(name, command):
        with (out / f"{name}.csv").open("w") as stdout, (out / f"{name}.log").open("w") as stderr:
            if hasattr(os, "wait4"):
                started = time.monotonic()
                process = subprocess.Popen(command, cwd=root, stdout=stdout, stderr=stderr)
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                # Linux reports KiB; Darwin reports bytes. Keep raw platform
                # units visible, and never mix this child with compiler rusage.
                scale = 1 if sys.platform == "darwin" else 1024 if sys.platform.startswith("linux") else None
                details = {
                    "method": "wait4 for this benchmark child only",
                    "peak_rss_bytes": usage.ru_maxrss * scale if scale else None,
                    "raw_maxrss": usage.ru_maxrss,
                    "raw_maxrss_unit": "bytes" if scale == 1 else "KiB" if scale else "platform-native",
                    "user_cpu_seconds": usage.ru_utime,
                    "system_cpu_seconds": usage.ru_stime,
                    "wall_seconds": time.monotonic() - started,
                    "exit_code": process.returncode,
                    "scope": "whole benchmark process including both libraries, corpora and caller buffers; excludes compiler processes",
                }
                (out / f"{name}-process.json").write_text(json.dumps(details, indent=2) + "\n")
                if process.returncode:
                    raise subprocess.CalledProcessError(process.returncode, command)
                return
            if gnu_time:
                command = ["/usr/bin/time", "-v", "-o", str(out / f"{name}-process.txt"), *command]
            subprocess.run(command, cwd=root, check=True, stdout=stdout, stderr=stderr)

    subprocess.run([cargo, "test", "--manifest-path", str(manifest), "--locked"], cwd=root, check=True)
    subprocess.run([cargo, "build", "--release", "--manifest-path", str(manifest), "--locked", "--no-default-features"], cwd=root, check=True)
    metadata["type_sizes"] = json.loads(subprocess.check_output([str(binary), "--sizes"], text=True))
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    execute("timing", [*prefix, str(binary), "--iterations", str(args.iterations), "--samples", str(args.samples), "--only-phase", args.phase])
    execute("errors", [str(binary), "--report-errors"])
    subprocess.run([cargo, "build", "--release", "--manifest-path", str(manifest), "--locked", "--features", "count-allocations"], cwd=root, check=True)
    execute("allocations", [*prefix, str(binary), "--iterations", "1", "--samples", "1", "--only-phase", args.phase])
    final_hashes = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
    if final_hashes != hashes:
        raise SystemExit("source changed during benchmark; rerun before merging incompatible binaries")
    rows = list(csv.DictReader((out / "timing.csv").open()))
    measured = {(r["case"], r["phase"], r["implementation"]): r for r in csv.DictReader((out / "allocations.csv").open())}
    for row in rows:
        memory = measured[(row["case"], row["phase"], row["implementation"])]
        for column in ("allocations_per_message", "peak_live_heap_bytes"):
            row[column] = memory[column]
        if row["implementation"] == "zldap" and (float(row["allocations_per_message"]) != 0 or int(row["peak_live_heap_bytes"]) != 0):
            raise SystemExit("zldap unexpectedly allocated during a measured operation")
    if not any(r["implementation"] in ("ldap3_proto", "ldap3_lber") and float(r["allocations_per_message"]) > 0 for r in rows):
        raise SystemExit("allocation counter did not observe the owned reference parser")
    with (out / "results.csv").open("w") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    subprocess.run([sys.executable, str(directory / "summarize.py"), str(out)], check=True)
    print(out)


if __name__ == "__main__":
    main()
