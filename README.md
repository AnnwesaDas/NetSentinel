# NetSentinel

GPU-accelerated network traffic anomaly detector. Captures live packets,
analyzes them for anomalies (port scans, high-entropy payloads, SYN floods)
on both a CPU path and a Metal GPU path, and benchmarks the two.

## Architecture

```
[Capture Thread] --libpcap--> [Thread-safe Queue]
                                     |
                      [Worker Thread Pool] --batches packets-->
                                     |
                    [Analysis: CPU path now, Metal GPU path later]
                    (entropy calc, hash-based signature match,
                     rule-based anomaly detection)
                                     |
                          [Alert/Anomaly Output]
```

- **Capture**: single producer thread reading raw packets via libpcap,
  manually parsing Ethernet/IP/TCP headers (no parsing libs).
- **Queue**: bounded, thread-safe, mutex + condition variable. Backpressure
  on a full queue (capture blocks on push) rather than dropping packets.
  Workers pop in batches, not one at a time.
- **Analysis**: Shannon entropy over payload bytes, hash-based signature
  matching, and rule-based detection (port scan, high-entropy payload,
  SYN flood). CPU-only baseline first; Metal compute kernels are a
  performance upgrade on top of the same logic, not a replacement for it.
- **Benchmark**: replays a fixed PCAP sample through both paths and reports
  measured packets/sec, CPU-only vs CPU+GPU.

## Detection rules (Phase 3)

Each worker runs `AnalysisEngine::analyze()` per packet:

- **Port scan** — flags a source IP once it has touched N distinct
  destination ports within a trailing window (default: 10 ports / 5s).
- **SYN flood** — flags a source IP once it has N SYN packets with no
  completing ACK yet, within a trailing window (default: 20 / 2s). A
  legitimate client's own later ACK on the same 4-tuple clears its pending
  entry, so normal fast-but-real connections don't trip this.
- **High-entropy payload** — flags a payload whose Shannon entropy is at or
  above a threshold (default: 7.0 bits/byte out of a max of 8.0), meant to
  catch encrypted/compressed C2 or exfil traffic. Note: Shannon entropy
  computed over a *small* sample undercounts true randomness (a 128-byte
  random payload averages ~6.5 bits/byte, a 256-byte one ~7.2) — this is an
  inherent property of the technique, not a bug, and the threshold/min
  payload length (`-e`, default min 32B) are tuning knobs to revisit
  against real traffic in Phase 5, same as queue capacity.
- **Signature match** — hashes the payload (FNV-1a) and compares against a
  small built-in set of known-bad hashes (seeded with the EICAR antivirus
  test string, a standard harmless string for exercising exactly this).

### Resistance to the traffic it detects

A detector whose own bookkeeping degrades under attack traffic is a
liability, so two properties are treated as requirements, not
optimizations, and are covered by tests:

- **Per-packet work is O(1) amortized.** Both stateful rules keep their
  sliding windows as a FIFO plus live counts, so nothing rescans the
  window per packet. The naive version was quadratic: a sustained scan
  from one source took 51s for 40k packets and never finished 200k. It now
  runs 200k in 1.3s (~155k packets/sec) and scales linearly — a ~200x
  improvement at 40k packets, widening as traffic grows.
- **Tracked state is bounded.** Per-IP records are evicted once idle and
  hard-capped per shard, because a spoofed-source flood makes every record
  look "recent" and idle eviction alone would never fire. 200k packets
  from 200k unique source IPs previously grew to 187MB and never shrank;
  it now holds at ~52MB regardless of how long the flood runs.

Port scan and SYN flood need state per source IP shared across every
worker thread. That state lives in `FlowTracker`, a **sharded map**: each
shard has its own mutex, keyed by `hash(src_ip) % num_shards`, so unrelated
source IPs never contend and all of one IP's packets land in the same
shard. Packets from the same IP can still be split across concurrent
worker batches, so the *exact* timing/count of debounced alerts can vary
slightly run to run under different thread scheduling — but the underlying
per-IP state (which ports/SYNs fall inside the time window) is always
correct, since every access to it is mutex-protected.

Testing: real `nmap -sS` runs against a local target for port scan/SYN
flood (both fire correctly — an SYN scan is itself a mini SYN flood, since
it never completes handshakes), plus `scripts/gen_synthetic_attacks.py`
for reproducible offline regression testing (also useful as Phase 5
benchmark input) covering all four rules plus a benign-traffic
false-positive check.

### Known limitations

Deliberate, understood trade-offs rather than oversights:

- **Spoofed-source SYN floods are not flagged.** The rule counts pending
  SYNs *per source IP*, as specified — but a real flood randomizes its
  source addresses precisely to defeat that, so each fake IP contributes
  one SYN and nothing crosses the threshold. Catching it needs a
  complementary per-*destination* half-open count. The tracker stays
  bounded under such a flood (above), it just won't alert on it.
- **Signature matching is whole-payload only.** Payloads are hashed
  entire, so a known-bad string *embedded* in a larger payload is missed.
  Catching that needs rolling-window hashing (Rabin-Karp). The current
  behaviour is pinned by a test so a future change is deliberate.
- **Entropy is per-packet, not per-flow.** Encrypted traffic split across
  many small packets may not trip a per-packet threshold (see the
  small-sample note above).
- **Alert timing is not deterministic under threading.** Packets from one
  source IP may land in different concurrent worker batches, so the exact
  count/timing of debounced alerts varies slightly run to run. The
  underlying per-IP state is always correct — every access is
  mutex-protected — only the alert cadence is loose.

## Non-goals (v1)

No distributed/multi-host capture, no ML-based detection, no live dashboard
UI beyond console/log output, no parsing beyond Ethernet/IP/TCP headers.

## Build

Requires CMake 3.20+, a C++17 compiler, and libpcap headers/library.

```sh
cmake -S . -B build
cmake --build build
./build/netsentinel -l               # list capture devices
sudo ./build/netsentinel -i en0      # live capture (see bpf note below)
./build/netsentinel -r sample.pcap   # offline replay from a pcap file
```

### Tests

```sh
cd build && ctest --output-on-failure
```

Four suites (parser, analysis, flow_tracker, queue) with no external test
framework, so they build anywhere the tool does. They cover the malformed
input the parser must survive (truncated headers, bogus IHL, a lying
`total_length`, snaplen cuts), entropy values derivable by hand, both
directions of every detection rule (fires on attacks, stays quiet on
traffic that merely resembles them), and the queue's concurrent
guarantees (FIFO order, backpressure rather than dropping, shutdown that
drains, no packet loss across 3 producers / 4 consumers).

The suites also run clean under sanitizers:

```sh
cmake -S . -B build-asan -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake -S . -B build-tsan -DCMAKE_CXX_FLAGS="-fsanitize=thread" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
```

- **macOS**: libpcap ships with the OS; headers come from the Xcode Command
  Line Tools (`xcode-select --install`). `brew install libpcap` gets you a
  newer version if needed.
- **Linux** (dev/CI convenience only — not the real capture target):
  `sudo apt-get install libpcap-dev`.

### macOS `/dev/bpf*` permission

Packet capture on macOS reads from `/dev/bpf*`, which normal user accounts
can't access by default. `pcap_findalldevs`/`pcap_open_live` will return no
devices or a permission error until this is resolved. Options, in order of
convenience:

1. **Run with sudo during development** (`sudo ./build/netsentinel`) — simplest,
   fine for local dev, not something to ship.
2. **One-off chmod**: `sudo chmod 644 /dev/bpf*` (resets on reboot).
3. **Persistent fix**: add your user to the `access_bpf` group so capture
   works without sudo across reboots:
   ```sh
   sudo dseditgroup -o edit -a "$(whoami)" -t user access_bpf
   ```
   (Log out/in for group membership to take effect.)

### Metal GPU path (Phase 4+)

Built only on macOS/Apple Silicon, gated behind the `NETSENTINEL_ENABLE_METAL`
CMake option. Off by default so the CPU-only baseline stays buildable
everywhere (including this dev/CI container, which has no GPU path).

One-time setup is a clone of Apple's metal-cpp headers — see
**[docs/METAL_SETUP.md](docs/METAL_SETUP.md)**. Then:

```sh
cmake -S . -B build -DNETSENTINEL_ENABLE_METAL=ON
cmake --build build
./build/metal_smoke_test
```

`metal_smoke_test` dispatches a trivial vector-add kernel and checks all
1024 results against CPU-computed values. It exists to validate the
device/queue/pipeline/buffer path on its own, before any detection logic
runs on the GPU. Verified on an Apple M5: builds clean, reports `PASS`.

In a Metal build, `-g` moves entropy onto the GPU: each worker sends its
whole batch (`-b`, default 64 packets) in one dispatch. Everything else
(signatures, port scan, SYN flood) stays on the CPU. The summary line
reports packets/sec. That figure is only meaningful when replaying a file
with `-r`; in live capture it includes the time spent waiting for traffic.

```sh
./build/netsentinel -r sample.pcap        # entropy on CPU
./build/netsentinel -r sample.pcap -g     # entropy on GPU
```

## Project status

Tracking against the phased build plan in `docs/PLAN.md`.

- [x] Phase 0 — Setup & scaffolding
- [x] Phase 1 — Packet capture + parsing
- [x] Phase 2 — Thread pool + queue
- [x] Phase 3 — CPU-only anomaly detection (checkpoint)
- [~] Phase 4 — Metal GPU kernel port (entropy kernel matches CPU on M5; `-g` GPU mode awaiting first M5 run)
- [ ] Phase 5 — Benchmark
- [ ] Phase 6 — Docs + demo

## Repo workflow

All development happens on `claude/*` branches, never directly on `main`.
This is a private working repo — a separate personal repository exists and
is never touched from here.
