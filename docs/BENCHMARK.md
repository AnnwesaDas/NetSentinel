# Benchmark

Phase 5: packets/sec with entropy on the CPU vs on the GPU, measured on one
reproducible capture.

## Run it

From a Metal-enabled build (see METAL_SETUP.md):

```sh
cmake --build build
python3 scripts/run_benchmark.py
```

The first run generates `benchmark.pcap` (500,000 packets, ~335 MB, seed
42; regenerating gives an identical file). It takes a few minutes. Plug the
laptop in and close other apps first. It ends with a markdown summary;
raw CSVs go to `build/bench/`.

Options: `--reps N` (default 5), `--batches 64,256,1024,4096`,
`--pcap other.pcap`, `--skip-entropy`.

## What it measures

**1. The entropy stage alone** (`build/bench_entropy`). The CPU backend (one
core) and the GPU backend on identical batches, for payloads of 64, 512 and
1460 bytes and batches of 1 to 4096 packets. This is the part the GPU
replaces, with nothing else in the timing. Each row also reports the largest
difference from the CPU result, so a speed figure never comes from wrong
answers.

**2. The whole pipeline** (`netsentinel -r benchmark.pcap -s`), with and
without `-g`, at each batch size. This is the number the project reports:
capture, parsing, queueing, entropy, signatures and flow rules together.

## Methodology

- **Same input for both.** One capture file, read from the page cache (the
  script reads it once before timing), so disk speed doesn't vary between runs.
- **Alerts are counted, not printed** (`-s`). Encrypted traffic looks random,
  so the high-entropy rule fires on most packets; printing ~190k lines would
  time the terminal instead of the detector.
- **Interleaved, repeated, median.** CPU and GPU runs alternate within each
  repetition, and each figure is the median of 5. A fanless MacBook Air
  throttles under sustained load; interleaving spreads that across both modes
  instead of penalizing whichever ran last.
- **Correctness is checked in the same runs.** High-entropy and signature
  alerts are decided per packet, so their counts must be identical across
  every CPU and GPU run and every batch size; the script fails loudly if not.
  Port-scan and SYN-flood counts are reported but not compared, because alert
  debouncing depends on thread timing (see the README's known limitations).
- **The real batch size is reported.** `-b` is a maximum. The summary shows the
  average batch the workers actually processed, since that's what the GPU
  sees per dispatch.

## Traffic mix

`scripts/gen_benchmark_pcap.py`: 400 clients and 40 servers; ~40% bare ACKs,
~35% full 1460-byte segments (85% encrypted-looking), ~15% 100–1000-byte
payloads, ~10% DNS-sized UDP. A real capture works too
(`sudo tcpdump -i en0 -w real.pcap -c 500000`, then `--pcap real.pcap`),
but it contains your own traffic: keep it out of git (`*.pcap` is ignored).

## A bottleneck found while building this

The first measurements showed throughput *falling* as workers were added:
290k packets/sec with one worker, 46k with four. The average batch was 1.1
packets, even though the configured maximum was 64. Workers were faster than
the single capture thread, so each packet woke a worker that took just that
packet, and they spent their time contending for the queue lock. In GPU mode
that would have meant one dispatch per packet.

Fix: a worker that finds fewer packets than it wants waits up to 2 ms for a
full batch (`linger`), and the queue wakes a worker when packets start
arriving and when a full batch is ready, not on every packet. With four
workers: 46k → 372k packets/sec, average batch 1.1 → 63.8. The default
worker count is also now cores − 1, leaving a core for the capture thread.

## Results: Apple M5 (MacBook Air, 10 cores, macOS 26.6.2)

Raw data: [results/m5_entropy_stage.csv](results/m5_entropy_stage.csv),
[results/m5_end_to_end_runs.csv](results/m5_end_to_end_runs.csv).

**Headline: on this machine and workload, CPU-only is faster end to end.**
The GPU path is correct but reaches 0.84–0.96× the CPU's throughput.

### Whole pipeline (9 workers, 500k packets, median of 5)

| max batch | avg batch (actual) | CPU packets/sec | GPU packets/sec | GPU vs CPU |
|---:|---:|---:|---:|---:|
| 64 | 64 | 1,206,528 | 1,012,211 | 0.84× |
| 256 | ~250 | 1,427,031 | 1,284,701 | 0.90× |
| 1024 | ~495 | 1,444,982 | 1,380,088 | 0.96× |
| 4096 | ~650 | 1,465,475 | 1,401,589 | 0.96× |

Correctness held in every one of the 40 runs: exactly 188,341
high-entropy alerts each time, CPU and GPU alike.

### Entropy stage alone (one CPU core vs the GPU)

GPU throughput relative to one CPU core:

| batch | 64-byte payloads | 512-byte | 1460-byte |
|---:|---:|---:|---:|
| 1 | 0.00× | 0.00× | 0.00× |
| 64 | 0.13× | 0.21× | 0.25× |
| 256 | 0.49× | 0.80× | 1.16× |
| 1024 | 1.78× | 3.07× | 2.54× |
| 4096 | 4.31× | 4.88× | 3.38× |

The GPU matches CPU results to within 1.3e-6 bits/byte in every row.

### Why the GPU loses end to end

1. **Every dispatch has a fixed cost of about 0.22 ms.** At batch size 1
   the GPU completes ~4,600 dispatches/sec whatever the payload size, so
   that time is setup (four buffer allocations and copies, encoding, and
   waiting for completion), not computation. The GPU only overtakes one
   CPU core once a batch has a few hundred to a thousand packets to spread
   that cost over.
2. **The pipeline never produces batches that big.** Even with `-b 4096`,
   the average batch was ~650: at ~1.45M packets/sec across 9 workers, the
   2 ms linger fills each worker's batch only that far.
3. **Entropy isn't the bottleneck with 9 CPU workers.** Both modes flatten
   out near the same ~1.4–1.5M packets/sec as batches grow, which points
   to a shared limit outside the entropy step, most likely the single
   capture thread and the queue. Speeding up entropy can't move a
   pipeline that's waiting on something else. And where entropy does
   matter, one GPU at ~650-packet batches is worth roughly one to two
   CPU cores (between the 256 and 1024 rows above), while the pipeline
   already has nine.

### What would change the result

In rough order of likely effect:
- Remove the per-dispatch overhead: reuse buffers across dispatches instead
  of allocating four each time, and submit without blocking so the CPU
  keeps working while the GPU runs.
- Feed the GPU larger batches: one GPU-feeding stage that collects packets
  from all workers, rather than each worker dispatching its own ~650.
- Give the GPU more work per byte: whole-payload hashing and one histogram
  per packet are light, while rolling-window signature matching (Rabin-Karp)
  over every offset of every payload is heavy enough that the GPU's
  parallelism would matter.
- Raise the pipeline's ceiling first (e.g. more than one capture thread),
  or no analysis speedup will show up end to end.
