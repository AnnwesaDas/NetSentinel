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
`--workers 3,4,9` (compare worker counts; default: netsentinel's own),
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

**Headline (round 3, below): with batches of 256 or more, the GPU is
faster end to end.** The best GPU configuration reaches 4.48M packets/sec,
against 3.58M for the best CPU one (1.25×). With the default batch of 64,
the CPU is still faster.

Rounds 1 and 2 found the opposite (GPU at 0.84–0.98× the CPU). They are
kept below because the reason it changed is the most useful part: a
bottleneck elsewhere in the pipeline was hiding any gain from the GPU.

The first measurements (round 1): CPU-only was faster end to end, with
the GPU path correct but reaching 0.84–0.96× the CPU's throughput.

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
   that time isn't computation. (This originally said the cost was mostly
   buffer allocation; round 2 below shows it isn't: removing the
   allocations left it unchanged.) The GPU only overtakes one CPU core
   once a batch has a few hundred to a thousand packets to spread that
   cost over.
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

### Round 2: optimizations

Changes: GPU buffers are pooled and reused instead of allocated per
dispatch; payloads are copied once, straight into GPU-visible memory,
instead of twice; a worker runs the signature and flow rules while the GPU
computes, instead of waiting for it; and `-L` lets workers wait longer to
fill bigger batches. The M5 ran the full benchmark twice (numbers below
are run 1 / run 2). All 6 test suites passed first, including new GPU
tests for dispatches in flight, buffer reuse, and abandoned dispatches.
Correctness held in all 120 end-to-end runs: 188,341 high-entropy alerts
every time, and 0 port-scan alerts now that the rule counts only
connection attempts.

**The fixed cost per dispatch didn't move.** At batch size 1 the GPU still
completes ~4,600–4,700 dispatches/sec. So the ~0.22 ms isn't buffer
allocation. It's the round trip itself: handing a command buffer to the
GPU, having it scheduled and run, and being told it finished. Pooling
can't remove that; only bigger batches or overlapping it with other work
can hide it.

**Where it did help: the GPU's entropy speed on big batches roughly
doubled.** GPU throughput relative to one CPU core, round 1 → round 2:

| batch | 64-byte payloads | 512-byte | 1460-byte |
|---:|---:|---:|---:|
| 256 | 0.49× → 0.49× / 0.50× | 0.80× → 0.80× / 0.81× | 1.16× → 1.02× / 0.97× |
| 1024 | 1.78× → 1.76× / 1.85× | 3.07× → 2.87× / 2.95× | 2.54× → 3.83× / 3.86× |
| 4096 | 4.31× → 3.16× / 3.37× | 4.88× → 8.66× / 7.88× | 3.38× → 6.85× / 6.92× |

The gains are largest where the most bytes were being copied (big
payloads, big batches), which fits removing a copy. One row got worse:
64-byte payloads at batch 4096 dropped in both runs. That row is also the
shortest measurement (about 10 ms per pass), so it's the least reliable,
but the cause is unexplained.

**End to end, the gap narrowed but the GPU still doesn't win.** GPU vs
CPU throughput, median of 5, round 1 → round 2:

| max batch | linger | round 1 | round 2 (run 1 / run 2) |
|---:|---:|---:|---:|
| 64 | 2 ms | 0.84× | 0.91× / 0.90× |
| 256 | 2 ms | 0.90× | 0.93× / 0.93× |
| 1024 | 2 ms | 0.96× | 0.96× / 0.96× |
| 4096 | 2 ms | 0.96× | 0.98× / 0.97× |
| 1024 | 10 ms | — | 0.96× / 0.95× |
| 4096 | 10 ms | — | 0.98× / 0.95× |

Overlapping GPU work with the other rules helped most at small batches
(0.84× → 0.90×). Both modes still top out at about 1.5M packets/sec
(CPU medians 1.22M at batch 64, 1.35–1.51M at larger batches), and with
10 ms linger the GPU received ~2,000-packet batches, where its entropy is
roughly 4–7× a CPU core, without the total moving. That settles the
earlier suspicion: entropy is not what limits the pipeline. The limit is
elsewhere, most likely the single capture thread (reading, parsing,
copying each payload into its own heap allocation, and taking the queue
lock once per packet). Measuring it is the next step, before changing it.

### What would change the result

Items struck through are done (rounds 2 and 3):
- ~~Remove the per-dispatch overhead~~: buffers are pooled and the CPU no
  longer blocks on the GPU. The round-trip latency itself remains.
- ~~Feed the GPU larger batches~~: `-L` does this per worker; a single
  GPU-feeding stage shared by all workers would go further.
- Give the GPU more work per byte: whole-payload hashing and one histogram
  per packet are light, while rolling-window signature matching (Rabin-Karp)
  over every offset of every payload is heavy enough that the GPU's
  parallelism would matter.
- ~~Raise the pipeline's ceiling first~~: done in round 3, by removing a
  system call per packet from the capture loop rather than adding capture
  threads.

## Measuring the capture thread

`build/bench_capture benchmark.pcap` times the capture thread with no
analysis at all. Each line adds one step to the line above, so the
difference between two lines is what that step costs:

| line | what the thread does per packet |
|---|---|
| read | `pcap_next_ex` only |
| + decode | parse the Ethernet/IP/TCP/UDP headers |
| + copy (reused buffer) | copy the payload into one buffer that's reused |
| + allocate (heap per packet) | copy the payload into its own heap allocation, as the pipeline does |
| + queue (to workers) | push each packet into the queue; worker threads take batches and discard them |

A last line, "queue, payload not copied", pushes packets without their
payload. Comparing it with "+ queue" separates the queue's own cost
(locking, waking workers) from allocating memory on the capture thread and
freeing it on a worker thread. Options match netsentinel's: `-w`, `-b`,
`-L`, `-q`, plus `--reps`.

First numbers, from the 4-core Linux container used for development
(release build, 3 workers, batch 256, 500k packets):

| line | packets/sec | ns/packet |
|---|---:|---:|
| read | 3.9M | 253 |
| + decode | 3.6M | 274 |
| + copy (reused buffer) | 3.5M | 288 |
| + allocate (heap per packet) | 3.2M | 314 |
| + queue (to workers) | 0.62M | 1,606 |
| queue, payload not copied | 1.48M | 678 |

Reading, decoding and copying are cheap. Handing packets to the workers
costs more than everything else combined, and about two thirds of that
comes from freeing each payload on a different thread from the one that
allocated it; the rest is the queue lock. The full pipeline on the same
machine ran at ~0.50M packets/sec, close to the 0.62M ceiling this sets.
The M5 has a different memory allocator, so its numbers decide what to
change next.

On the M5 (9 workers, batch 256, 500k packets, median of 5):

| line | packets/sec | ns/packet |
|---|---:|---:|
| read | 8.3M | 120 |
| + decode | 8.1M | 124 |
| + copy (reused buffer) | 7.6M | 131 |
| + allocate (heap per packet) | 6.9M | 144 |
| + queue (to workers) | 4.2M | 236 |
| queue, payload not copied | 4.9M | 204 |

**On the M5 the capture thread is not the limit.** It can feed workers
4.2M packets/sec, almost three times the ~1.5M the full pipeline reaches.
macOS's allocator handles the cross-thread frees far better than Linux's
(about 30 ns instead of about 900 ns). The earlier guess about the
capture thread was wrong for this machine, and changing the capture code
would not have moved the M5 number. The limit is on the worker side.

## Measuring the worker side

`build/bench_analysis benchmark.pcap` loads every packet into memory, then
times the detection rules with no capture thread or queue. It measures
each rule on one thread, then on 1, 2, 4, ... threads at once. A rule
whose throughput stops growing as threads are added is held back by
something shared (a lock, memory bandwidth, or slower cores), not by its
own work.

First numbers, Linux container (release build, batch 256):

| rule | ns/packet, one thread | 1 thread | 2 | 3 | 4 |
|---|---:|---:|---:|---:|---:|
| entropy | 1,495 | 0.67M | 1.32M | 1.97M | 2.69M |
| signature | 768 | 1.30M | 2.56M | 3.79M | 5.04M |
| flow | 68 | 14.7M | 4.66M | 5.94M | 5.51M |
| all (a real worker) | 2,486 | 0.40M | 0.74M | 1.07M | 1.40M |

(packets/sec by thread count)

- **Entropy and signature scale almost perfectly.** They cost the most
  per packet, but each thread works alone. Signature matching costs
  half as much as entropy because it hashes every payload byte by byte.
- **The flow rules get slower as threads are added.** They're cheap on
  one thread, but two threads are 3× slower than one. The likely cause
  is threads waiting on the same shard locks (and passing the locked
  data between cores); that still needs confirming.
- One real worker handles ~0.40M packets/sec here, and four reach 1.40M.

On the M5 (batch 256, median of 5), packets/sec by thread count:

| rule | ns/packet, one thread | 1 | 2 | 4 | 8 | 9 | 10 |
|---|---:|---:|---:|---:|---:|---:|---:|
| entropy | 402 | 2.49M | 4.89M | 8.84M | 13.45M | 14.54M | 15.44M |
| signature | 579 | 1.73M | 3.60M | 7.14M | 11.96M | 13.17M | 14.28M |
| flow | 10 | 100M | 22.5M | 22.8M | 13.8M | 12.9M | 13.0M |
| all (a real worker) | 991 | 1.01M | 1.94M | 3.61M | 4.95M | 5.32M | 5.68M |

- Entropy and signature scale well up to 4 threads, then gain less per
  thread. The M5 has 4 fast cores and 6 slower ones, so threads 5 to 10
  are slower threads.
- The flow rules have the same lock problem as on Linux, but at ~13M
  packets/sec they're still far from the limit.
- With 9 threads, the workers alone manage 5.3M packets/sec.

**This leaves a puzzle.** The capture thread alone manages 4.2M
packets/sec, and the workers alone 5.3M, but the full pipeline reaches
only ~1.5M. Neither side explains that on its own, so the slowdown comes
from running them together. To find out which side is waiting on the
other, netsentinel now prints how much of the time the capture thread
spent blocked on a full queue, and how much the workers spent waiting for
packets:

```
waiting: capture thread blocked on a full queue 0% of its 1.151s, workers waiting for packets 46% of their time
```

That line is from the Linux container with 3 workers: the workers sat
idle almost half the time while the capture thread never waited, so there
the capture thread is the limit, as bench_capture showed.

### Found: one system call per packet

On the M5, the `waiting:` line settled it:

| run | packets/sec | capture thread blocked | workers waiting |
|---|---:|---:|---:|
| 9 workers, CPU | 1.13M | 0% | 84% |
| 3 workers, CPU | 1.17M | 0% | 52% |
| 9 workers, GPU | 1.07M | 0% | 70% |

The workers were idle most of the time and the capture thread never
waited, so the capture thread was the limit after all, yet it ran at
1.1M packets/sec in the program against 4.2M in bench_capture. The
difference was in `Capture::run`. To stop live capture from hanging on
Linux (see the comment there), it calls `poll()` before every packet. A
comment said libpcap gives no pollable handle for a file, but it does, so
replaying a file also paid for one `poll()` system call per packet
(`strace` counted 100,000 calls for 100,000 packets). bench_capture calls
libpcap directly and never had that cost, which is why the two numbers
disagreed.

Fix: poll only during live capture. After each poll, read every packet
that's ready before polling again, so live capture makes one system call
per burst instead of one per packet.

On the Linux container (3 workers, runs of the old and new build
alternated): **0.70M → 0.95M packets/sec**. The capture thread and
workers are now close to balanced there (capture blocked 1%, workers
waiting 8%). Live capture still stops on Ctrl-C with no traffic, and a
loopback test captured every packet sent.

On the M5, single runs after the fix (not yet a proper benchmark):

| run | before | after | capture thread blocked | workers waiting |
|---|---:|---:|---:|---:|
| 9 workers, CPU | 1.13M | 2.05M | 0% | 68% |
| 3 workers, CPU | 1.17M | 2.67M | 41% | 0% |
| 9 workers, GPU | 1.07M | 2.31M | 0% | 38% |

The M5 pipeline is now 1.8–2.3× faster. Two things in these runs needed
the full, repeated benchmark before they counted (answered in round 3):
- **3 workers beat 9.** With 3 workers the capture thread waits on them
  (41%), so it's fast enough. With 9, the capture thread is slower even
  though it never waits, possibly because 10 busy threads push it off the
  M5's 4 fast cores.
- **The GPU run beat the CPU run with 9 workers.** That would be the
  first time the GPU wins end to end.

`python3 scripts/run_benchmark.py --skip-entropy --workers 3,4,6,9`
settles both.

## Round 3: after the capture fix (M5)

`python3 scripts/run_benchmark.py --skip-entropy --workers 3,4,6,9`
(medians: [results/m5_round3_medians.csv](results/m5_round3_medians.csv)):
500k packets, linger 2 ms, median of 5, CPU and GPU runs alternated.
Correctness held in all 160 runs: 188,341 high-entropy alerts every time.

Packets/sec, median (GPU vs CPU in brackets):

| max batch | 3 workers | 4 workers | 6 workers | 9 workers (default) |
|---:|---|---|---|---|
| 64 | CPU 2.64M / GPU 1.32M (0.50×) | 3.02M / 2.04M (0.67×) | 2.60M / 2.63M (1.01×) | 2.55M / 2.33M (0.91×) |
| 256 | 2.66M / 2.49M (0.94×) | 3.05M / 3.40M (1.11×) | 3.06M / 3.56M (1.16×) | 3.03M / 3.50M (1.15×) |
| 1024 | 2.66M / 4.11M (1.55×) | 3.27M / 4.36M (1.33×) | 3.28M / 4.32M (1.32×) | 3.28M / 4.24M (1.29×) |
| 4096 | 2.65M / 4.18M (1.58×) | 3.29M / **4.48M** (1.36×) | 3.45M / 4.42M (1.28×) | **3.58M** / 4.41M (1.23×) |

Best of each: GPU 4.48M (batch 4096, 4 workers) against CPU 3.58M (batch
4096, 9 workers), so **the GPU is 1.25× faster end to end**. Against
round 2's best CPU result (~1.5M), both modes are now 2.4–3× faster.

What the numbers say:
- **Removing the capture bottleneck is what let the GPU win.** In rounds
  1–2 both modes hit the same ~1.5M ceiling, so a faster entropy step
  couldn't show. Now the CPU runs are limited by the workers' own work,
  and moving entropy (about 40% of a worker's time per packet, from
  bench_analysis: 402 of 991 ns) to the GPU frees them.
- **The GPU runs now top out near 4.2–4.5M,** about what bench_capture
  measured for the capture thread alone (4.2M). So the capture thread is
  once again the limit for GPU runs. The next speedup would have to come
  from there.
- **The GPU needs big batches.** At batch 64 it loses in most columns:
  each dispatch has a fixed ~0.22 ms round trip, and 64 packets aren't
  enough work to pay for it. From 256 up it wins in every column but one.
- **More CPU workers help less than expected.** On the CPU, 4 workers
  beat 3 by ~15–25%, but going from 4 to 9 adds at most ~9%. The M5 has
  4 fast cores and 6 slower ones, so workers beyond 4 run slower.
  netsentinel's default (cores − 1 = 9) is still close to the best CPU
  setting at large batches, and slightly worse than 4 at batch 64.
