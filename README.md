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

## Non-goals (v1)

No distributed/multi-host capture, no ML-based detection, no live dashboard
UI beyond console/log output, no parsing beyond Ethernet/IP/TCP headers.

## Build

Requires CMake 3.20+, a C++17 compiler, and libpcap headers/library.

```sh
cmake -S . -B build
cmake --build build
./build/netsentinel
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

```sh
cmake -S . -B build -DNETSENTINEL_ENABLE_METAL=ON
```

## Project status

Tracking against the phased build plan in `docs/PLAN.md`.

- [x] Phase 0 — Setup & scaffolding
- [ ] Phase 1 — Packet capture + parsing
- [ ] Phase 2 — Thread pool + queue
- [ ] Phase 3 — CPU-only anomaly detection (checkpoint)
- [ ] Phase 4 — Metal GPU kernel port
- [ ] Phase 5 — Benchmark
- [ ] Phase 6 — Docs + demo

## Repo workflow

All development happens on `claude/*` branches, never directly on `main`.
This is a private working repo — a separate personal repository exists and
is never touched from here.
