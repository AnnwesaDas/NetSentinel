# Build plan

C++17, libpcap, `std::thread`/thread pool, Metal + metal-cpp (dev machine:
MacBook Air, M5, Apple Silicon integrated GPU, no CUDA), CMake.

## Phase 0 — Setup & scaffolding
CMake project structure, libpcap linked and building. Resolve the macOS
`/dev/bpf*` permission issue up front (see README) — don't let it block
later phases.

## Phase 1 — Packet capture + parsing
libpcap capture loop, manual Ethernet/IP/TCP header parsing (network byte
order, header length fields — no external parsing libs). No threading, no
analysis yet.
**Success**: raw packets printed/logged correctly for real traffic.

## Phase 2 — Thread pool + queue
One capture thread producing, thread-safe queue, worker thread pool
consuming in batches.

Finalized queue design:
- Mutex + condition variable, not lock-free. Lock-free is a stretch goal
  for after the Metal port, not before.
- Batched pop: `std::vector<Packet> pop_batch(size_t max_n, std::chrono::milliseconds timeout);`
  — block until at least one packet is available or the timeout fires, then
  drain up to `max_n`. A short timeout (~50-100ms) lets idle workers
  periodically check a shutdown flag.
- Bounded queue with backpressure: a full queue blocks `push`, it never
  silently drops. Capacity gets tuned against real throughput numbers in
  Phase 5, not guessed upfront.

**Success**: no dropped packets under moderate load, clean shutdown.

## Phase 3 — CPU-only anomaly detection — CHECKPOINT
Do not start GPU work until this phase is fully working and demoable on
its own.

- Shannon entropy over payload bytes
- Hash-based signature matching
- Rules: port scan (distinct dest ports/src IP in a window), high-entropy
  payload flag, SYN flood (SYN count/src IP without completed handshake
  in a window)
- Stateful rules need per-IP/per-flow tracking shared across worker
  threads: sharded map, or route all packets from a source IP to the same
  worker to avoid contention.
- Testing: nmap for port scans, scapy-crafted SYN floods (hping3 is flaky
  on macOS — avoid), a script pushing random high-entropy payloads.

**Success**: end-to-end on real traffic, correctly flags synthetic test
cases of each anomaly type.

## Phase 4 — Metal GPU kernel port
metal-cpp setup; build a throwaway "hello world" compute kernel (vector
add) first to validate device/queue/pipeline/buffer plumbing before
porting real logic. Port the hot loop (entropy/hash/pattern matching)
into Metal compute kernels. The entropy histogram is the trickiest part
to parallelize correctly — atomics or a per-threadgroup reduction.

**Success**: GPU path produces identical results to the CPU path on the
same input.

## Phase 5 — Benchmark
Reproducible PCAP replay (capture a representative sample once, replay
identically for both runs — not live traffic). Measure and log real
packets/sec, CPU-only vs CPU+GPU, on the same sample.

**Success**: a real, reproducible number, not an estimate.

## Phase 6 — Docs + demo
README with architecture diagram, benchmark results/chart, setup
instructions including the macOS `/dev/bpf*` note. Can be written
incrementally alongside earlier phases.

## Timeline target
- CPU-only checkpoint (end of Phase 3): Week 3-4
- Full build, minimum: ~12-14 working days at 7-12 hrs/day
- Full build, realistic with buffer: ~15-18 working days
- Biggest risk: Phase 4 (Metal) — first-time GPU compute work, budget real
  time for the learning curve even with metal-cpp cutting the
  Objective-C boilerplate.
