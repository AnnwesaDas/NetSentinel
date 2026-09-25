#!/usr/bin/env python3
"""Phase 5 benchmark: CPU-only vs CPU+GPU on one reproducible capture.

Runs, in order:
  1. bench_entropy: the entropy stage alone, CPU vs GPU, across batch and
     payload sizes.
  2. netsentinel end to end on the benchmark capture, for each batch size,
     with entropy on the CPU and (in Metal builds, -g) on the GPU. The two
     are interleaved within each repetition so slow drift (thermal
     throttling on a fanless laptop, background load) hits both equally,
     and each reported number is a median.

High-entropy and signature alerts are decided per packet, so their counts
must be identical in every CPU and GPU run; the script checks that. Port
scan and SYN flood counts can shift slightly between runs (alert
debouncing depends on thread timing), so they are reported, not compared.

Everything is written under --out; the summary printed at the end is
markdown, ready to paste into docs/BENCHMARK.md.
"""
import argparse
import csv
import os
import platform
import re
import statistics
import subprocess
import sys

DONE_RE = re.compile(r"done — (\d+) packet\(s\) captured, (\d+) processed, (\d+) alert\(s\), "
                     r"([\d.]+)s, (\d+) packets/sec, avg batch ([\d.]+)")
FALLBACK_RE = re.compile(r"warning: (\d+) batch\(es\) fell back")
BY_TYPE_RE = re.compile(r"alerts by type: port_scan=(\d+) syn_flood=(\d+) "
                        r"high_entropy=(\d+) signature=(\d+)")


def machine_description():
    if platform.system() == "Darwin":
        try:
            chip = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                  capture_output=True, text=True).stdout.strip()
            mac = platform.mac_ver()[0]
            return f"{chip}, macOS {mac}, {os.cpu_count()} cores"
        except OSError:
            pass
    return f"{platform.system()} {platform.machine()}, {os.cpu_count()} cores"


def run_once(binary, pcap, batch, linger, workers, flags):
    cmd = [binary, "-r", pcap, "-s", "-b", str(batch), "-L", str(linger)] + flags
    if workers:
        cmd += ["-w", str(workers)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"failed: {' '.join(cmd)}\n{proc.stdout}{proc.stderr}")
    match = DONE_RE.search(proc.stdout)
    if not match:
        sys.exit(f"could not parse output of {' '.join(cmd)}:\n{proc.stdout}")
    fallback = FALLBACK_RE.search(proc.stdout)
    by_type = BY_TYPE_RE.search(proc.stdout)
    if not by_type:
        sys.exit(f"could not parse alert counts from {' '.join(cmd)}:\n{proc.stdout}")
    return {
        "processed": int(match.group(2)),
        "alerts": int(match.group(3)),
        "seconds": float(match.group(4)),
        "pps": int(match.group(5)),
        "avg_batch": float(match.group(6)),
        "fallbacks": int(fallback.group(1)) if fallback else 0,
        "port_scan": int(by_type.group(1)),
        "syn_flood": int(by_type.group(2)),
        "high_entropy": int(by_type.group(3)),
        "signature": int(by_type.group(4)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", default="build", help="CMake build directory")
    parser.add_argument("--pcap", default="benchmark.pcap")
    parser.add_argument("--packets", type=int, default=500_000,
                        help="size of the capture to generate if --pcap is missing")
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--batches", default="64,256,1024,4096")
    parser.add_argument("--linger", type=int, default=2000,
                        help="microseconds a worker waits to fill a batch (netsentinel -L)")
    parser.add_argument("--workers", default="",
                        help="comma-separated worker counts to compare (netsentinel -w); "
                             "default: netsentinel's own default")
    parser.add_argument("--out", default=None, help="results directory (default: BUILD/bench)")
    parser.add_argument("--skip-entropy", action="store_true",
                        help="skip the bench_entropy stage benchmark")
    args = parser.parse_args()

    netsentinel = os.path.join(args.build, "netsentinel")
    bench_entropy = os.path.join(args.build, "bench_entropy")
    out = args.out or os.path.join(args.build, "bench")
    os.makedirs(out, exist_ok=True)
    for binary in (netsentinel, bench_entropy):
        if not os.path.exists(binary):
            sys.exit(f"{binary} not found; build first (cmake --build {args.build})")

    if not os.path.exists(args.pcap):
        generator = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gen_benchmark_pcap.py")
        subprocess.run([sys.executable, generator, "-o", args.pcap, "-n", str(args.packets)],
                       check=True)
    with open(args.pcap, "rb") as f:  # pull the file into the page cache before timing
        while f.read(1 << 24):
            pass

    gpu_probe = subprocess.run([netsentinel, "-r", args.pcap, "-s", "-g", "-c", "1"],
                               capture_output=True, text=True)
    modes = [("cpu", [])]
    if gpu_probe.returncode == 0:
        modes.append(("gpu", ["-g"]))
    else:
        print("GPU mode unavailable in this build; running cpu only.\n")

    machine = machine_description()
    print(f"machine: {machine}")
    print(f"capture: {args.pcap}\n")

    if not args.skip_entropy:
        print("== entropy stage alone (bench_entropy) ==")
        subprocess.run([bench_entropy, "--csv", os.path.join(out, "entropy_stage.csv")], check=True)
        print()

    batches = [int(b) for b in args.batches.split(",")]
    # 0 stands for "netsentinel's default worker count".
    worker_counts = [int(w) for w in args.workers.split(",")] if args.workers else [0]
    runs = []
    print(f"== end to end: {len(modes)} modes x {len(batches)} batch sizes x "
          f"{len(worker_counts)} worker counts x {args.reps} reps ==")
    for batch in batches:
        for rep in range(args.reps):
            for workers in worker_counts:
                for mode, flags in modes:
                    result = run_once(netsentinel, args.pcap, batch, args.linger, workers, flags)
                    result.update(mode=mode, batch=batch, workers=workers or "default", rep=rep)
                    runs.append(result)
                    print(f"  batch {batch:>5}  workers {workers or 'default':>7}  "
                          f"rep {rep + 1}/{args.reps}  {mode:<8} {result['pps']:>9} pkt/s  "
                          f"avg batch {result['avg_batch']:.1f}", flush=True)

    raw_path = os.path.join(out, "end_to_end_runs.csv")
    with open(raw_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mode", "batch", "workers", "rep", "pps", "seconds",
                                               "avg_batch", "alerts", "processed", "fallbacks",
                                               "port_scan", "syn_flood", "high_entropy",
                                               "signature"])
        writer.writeheader()
        writer.writerows(runs)

    print(f"\n### End-to-end results\n\nMachine: {machine}. Capture: `{args.pcap}`, "
          f"linger {args.linger} us, median of {args.reps} runs.\n")
    print("| batch | workers | mode | packets/sec (median) | min–max | avg batch | vs cpu |")
    print("|---:|---:|---|---:|---:|---:|---:|")
    problems = []
    for batch in batches:
        for workers in worker_counts:
            label = workers or "default"
            same = [r for r in runs if r["batch"] == batch and r["workers"] == label]
            cpu_median = statistics.median(r["pps"] for r in same if r["mode"] == "cpu")
            for mode, _ in modes:
                mine = [r for r in same if r["mode"] == mode]
                pps = [r["pps"] for r in mine]
                median = statistics.median(pps)
                print(f"| {batch} | {label} | {mode} | {median:,.0f} | {min(pps):,}–{max(pps):,} | "
                      f"{statistics.median(r['avg_batch'] for r in mine):.1f} | "
                      f"{median / cpu_median:.2f}x |")
                if any(r["fallbacks"] for r in mine):
                    problems.append(f"{mode} at batch {batch}, {label} workers: "
                                    "GPU batches fell back to the CPU")

    # Per-packet decisions must not depend on the backend, batch size or run.
    for kind in ("high_entropy", "signature"):
        counts = sorted({r[kind] for r in runs})
        if len(counts) == 1:
            ran = " and ".join(mode for mode, _ in modes)
            print(f"\n{kind} alerts: {counts[0]:,} in every run ({ran}, all batch sizes and worker counts)", end="")
        else:
            problems.append(f"{kind} alert counts differ between runs: {counts}")
    flow = sorted({(r["port_scan"], r["syn_flood"]) for r in runs})
    print(f"\nport_scan / syn_flood alerts across runs: "
          f"{min(p for p, _ in flow)}–{max(p for p, _ in flow)} / "
          f"{min(q for _, q in flow)}–{max(q for _, q in flow)} (timing-dependent, see README)")

    print(f"\nRaw runs: {raw_path}")
    if not args.skip_entropy:
        print(f"Entropy stage: {os.path.join(out, 'entropy_stage.csv')}")
    for problem in problems:
        print(f"WARNING: {problem}; those GPU numbers include CPU work.")


if __name__ == "__main__":
    main()
