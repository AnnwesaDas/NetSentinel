# How NetSentinel works, and why

This explains each part of the design: what it does, why it was built
that way, what else was considered, and what was measured. The README
has the overview; this is the detail behind it.

## The pipeline in one paragraph

One **capture thread** reads packets through libpcap, parses the headers
itself, copies the payload, and pushes the packet into a **bounded
queue**. A **pool of worker threads** takes packets from the queue in
batches. For each batch, a worker computes **entropy** (on the CPU or the
GPU), checks each payload against **known-bad signature hashes**, and
updates the **per-IP state** used by the port-scan and SYN-flood rules.
Any rule that fires produces an **alert**.

## Capture

### Parsing headers by hand

**What:** `src/capture/parser.cpp` decodes Ethernet, IPv4, TCP and UDP
from raw bytes. Wire-format headers are packed structs, multi-byte
fields go through `ntohs`/`ntohl` (network byte order is big-endian;
Apple Silicon and x86 are little-endian), and the IPv4 and TCP header
lengths come from the packet itself (IHL and data offset), not assumed
to be 20 bytes.

**Why:** that was a project requirement, and it's where the classic
bugs live. Every field read is checked against `caplen`, the number of
bytes actually captured, which can be smaller than the packet on the
wire. The parser tests feed it truncated headers, an IHL smaller than
the minimum, a `total_length` that claims more bytes than exist, and
snaplen cuts. A packet the parser can't handle returns "not parsed"; it
never reads past the buffer. Frames that aren't IPv4 are skipped.

### The capture loop and poll()

**What:** for live capture, `Capture::run` waits with its own `poll()`
(100 ms timeout) and then reads every packet that's ready before polling
again. For a .pcap file it just reads.

**Why:** on Linux, libpcap's own timeout depends on a packet arriving
first. On an idle interface, `pcap_next_ex` could block forever, so
Ctrl-C never stopped the program. Polling ourselves, with a timeout,
means the stop flag is checked at least every 100 ms.

**The bug this caused, and the fix:** the first version polled before
*every* packet, including when reading a file (libpcap returns a
pollable handle for files too, contrary to a comment in the code). That's
one system call per packet. It went unnoticed until the benchmark: both
the CPU and GPU versions stalled at ~1.5M packets/sec on the M5. See
"The performance story" below for how it was found. Fixing it (poll only
for live capture, and drain all ready packets per poll) made the whole
pipeline 2–3× faster.

### Copying the payload

**What:** each queued packet owns a copy of its payload
(`QueuedPacket::payload`, a `std::vector<uint8_t>`).

**Why:** libpcap reuses its buffer for the next packet, so a pointer into
it is only valid during the callback. The workers process the packet
later, on another thread, so they need their own copy.

**Cost, measured** (bench_capture): the copy plus a memory allocation
per packet costs ~20 ns on the M5. On Linux, freeing that memory on a
different thread from the one that allocated it was expensive (~900 ns
per packet), because the Linux allocator is slow at cross-thread frees.
On the M5 it's ~30 ns. A pool of reusable buffers would remove it, but on
the M5 it isn't the bottleneck, so it wasn't worth the complexity.

## The queue

### Bounded, with backpressure

**What:** `PacketQueue` holds at most 4096 packets (`-q`). When it's
full, `push()` blocks until a worker makes room.

**Why:** the alternative is dropping packets when the detector falls
behind. For a security tool, that's the worst failure mode: an attacker
who can overload the detector could hide in the dropped traffic. Blocking
means an overloaded detector slows capture instead. (During live capture
the kernel's own buffer can still overflow if the detector falls far
behind; libpcap counts those drops.)

### Mutex and condition variables, not lock-free

**Why:** correctness first, and measurement showed the lock isn't the
bottleneck. On the M5, pushing a packet through the queue costs ~90 ns,
and the capture thread can feed workers at 4.2M packets/sec. A lock-free
queue is harder to get right and would have optimized something that
wasn't slow.

### Batching, linger, and when to wake a worker

**What:** `pop_batch(max_n, timeout, linger)` takes up to `max_n` packets
(`-b`). If fewer are waiting, it waits up to `linger` (`-L`, default
2 ms) for a full batch. `push()` wakes a worker only when the queue goes
from empty to non-empty or reaches a full batch, not on every packet.

**Why, with the numbers:** the first version woke a worker on every push.
Workers were faster than the capture thread, so each woke, took one
packet, and went back to sleep, while all of them fought over the queue
lock. Average batch size: 1.1 packets. Adding workers made it *slower*:
290k packets/sec with one worker, 46k with four. With linger and the new
wake-up rule: 372k with four workers, average batch 63.8. Batching also
matters for the GPU: a batch of one packet would mean one GPU dispatch
per packet.

## Detection

### Entropy

Shannon entropy of the payload bytes, in bits per byte: 0 for a payload
of one repeated byte, 8 for perfectly random bytes. Encrypted or
compressed data scores near 8, so the rule flags payloads at or above
7.0. Payloads under 32 bytes are skipped: with so few bytes, even random
data scores low, so the number means little.

### Signatures

Each payload is hashed (FNV-1a, 64-bit) and looked up in a set of
known-bad hashes, seeded with the EICAR antivirus test string, a
harmless standard string made for testing detectors. It only matches
whole payloads; finding a known string *inside* a payload needs a
rolling hash over every offset (Rabin-Karp), which is listed as a
limitation.

### Port scan and SYN flood: shared state

Both rules need history per source IP, across every worker: "has this IP
tried 10 different ports in the last 5 seconds?" and "does this IP have
20 SYNs without a completed handshake in the last 2 seconds?"

**Sharding:** `FlowTracker` keeps that state in 16 shards, picked by a
hash of the source IP, each with its own mutex. All of one IP's state is
in one shard, and two workers only wait on each other when their packets
come from IPs in the same shard. The alternative was routing each IP to
one fixed worker, which needs no locks but lets one busy IP overload one
worker while the others sit idle.

**Measured:** the flow rules take ~10 ns per packet on one M5 thread. With
several threads they slow down (13M packets/sec with 9 threads vs 100M
with 1), most likely from lock contention and shard data moving between
cores. That's still far faster than the rest of the pipeline, so it
wasn't changed.

**Constant time per packet:** each IP keeps its recent events in a queue
ordered by time plus a count of each port, so "how many distinct ports
in the window?" is a lookup, not a rescan. The first version rescanned
the window on every packet, which is quadratic: a sustained scan from one
source took 51 s for 40k packets and never finished 200k. Now 200k take
1.3 s.

**Bounded memory:** idle IPs are evicted after 60 s, and each shard holds
at most 1024 IPs. The cap matters because a flood with a fake source IP
on every packet makes every entry look recent, so idle eviction never
kicks in. Before the cap, 200k packets from 200k fake IPs grew to 187 MB
and never shrank; now memory stays at ~52 MB however long the flood runs.

**What counts as a scan attempt:** a TCP SYN without ACK, or a UDP
packet not sent from a port below 1024. The first version counted every
packet, which flagged busy servers: their replies go to hundreds of
client ports. That gave ~1,100 false alerts on the benchmark capture;
now 0, with every real scan still caught.

**Debounce:** an IP alerts at most once every 2 seconds per rule, so a
long scan produces a few alerts rather than one per packet. "Never
alerted" is stored as an empty `std::optional`, not as time 0. The first
version used 0, which made the first alert on captures with small
timestamps look like a repeat, and suppressed it.

**Known trade-off:** packets from one IP can be in two workers' batches
at the same time, so the exact number of repeat alerts varies slightly
between runs. The state itself is always correct, because every access
holds the shard's lock.

## The GPU path

### What runs on the GPU, and why only entropy

Only entropy. It's the heaviest per-byte work (every payload byte feeds a
256-bin histogram), and the rules for each packet are independent, which
suits a GPU. Signature hashing is also per-byte, but FNV-1a is sequential:
each step depends on the previous one, so one payload can't be split
across GPU threads. The port-scan and SYN-flood rules are small updates
to shared state, which GPUs are bad at.

### The kernel

`shaders/payload_entropy.metal` handles a whole batch in one dispatch:

- **One threadgroup per payload.** Threads split the payload bytes
  between them and build a histogram in fast threadgroup memory. The
  increments are atomic, because two threads can hit the same byte value
  at the same time and a plain `+= 1` would lose one of them.
- **A tree reduction** then adds up the 256 bins' contributions: half the
  threads add pairs, then a quarter, and so on, instead of one thread
  adding 256 numbers.
- **`precise::log2`:** Metal compiles with fast math by default, which
  uses a less accurate log. The precise version keeps GPU results within
  1.3e-6 bits/byte of the CPU's, so the two always agree on which packets
  cross the 7.0 threshold. The benchmark checks this: 188,341
  high-entropy alerts in every CPU and GPU run.

### Host side

- **Shared memory:** Apple Silicon's CPU and GPU share memory, so buffers
  use shared storage. Payloads are copied once, straight into
  GPU-visible memory.
- **Buffer pooling:** buffers are reused across dispatches and grow when a
  bigger batch arrives, instead of being allocated per dispatch.
- **Overlap:** `start()` sends the batch to the GPU and returns
  immediately; the worker runs the signature and flow rules while the GPU
  works, then `wait()`s for the result.
- **Fallback:** if a dispatch fails, that batch is computed on the CPU and
  the run summary reports how many batches fell back. A GPU benchmark
  number can't silently include CPU work.
- **Shaders compiled at startup:** CMake embeds the `.metal` source into
  a C++ header, and the program compiles it when it starts. The build
  doesn't need the offline Metal compiler, which comes with full Xcode
  rather than the Command Line Tools.

### The fixed cost per dispatch

Each dispatch costs ~0.22 ms regardless of size: handing work to the GPU,
having it scheduled, and hearing back. Pooling buffers didn't reduce it.
That's why the GPU loses with small batches (64 packets is too little
work to pay for 0.22 ms) and wins from 256 up.

## The performance story

The most useful part of the project to explain, because the first
answer was wrong.

1. **Round 1:** the GPU version was *slower* end to end, 0.84–0.96× the
   CPU, even though the GPU computed entropy up to 4.9× faster than one
   CPU core on large batches.
2. **Round 2:** buffer pooling, a single copy, and overlapping GPU work
   with CPU work. The GPU's entropy speed roughly doubled on big batches,
   but end to end nothing moved: both versions stalled at ~1.5M
   packets/sec. So entropy wasn't the bottleneck.
3. **Measuring the parts separately:** `bench_capture` timed the capture
   thread alone (4.2M packets/sec on the M5), and `bench_analysis` timed
   the workers alone (5.3M with 9 threads). Neither explained 1.5M.
4. **Measuring the real program:** the queue now records how long each
   side waits. The capture thread never waited; the workers were idle
   84% of the time. So the capture thread was the limit inside the real
   program, but it ran at 1.1M there against 4.2M in the benchmark tool.
   The only difference was the code in `Capture::run`, and `strace`
   found it: one `poll()` system call per packet.
5. **Round 3, after the fix:** CPU up to 3.58M packets/sec, GPU up to
   4.48M, so the GPU wins by 1.25×, and by up to 1.58× at equal settings.
   Alerts identical across all 160 runs.

The lesson: when two parts are each fast on their own but the whole is
slow, the problem is in whatever code only the whole runs.

## Questions you might be asked

**Why C++ and not Rust or Go?** Direct access to libpcap and Metal's C++
bindings, control over memory and threads, and it's the standard language
for this kind of systems work.

**Why not just use a library to parse packets?** The goal was to
understand the formats: byte order, variable header lengths, and handling
malformed input safely. The parser is small and fully tested.

**What happens if packets arrive faster than you can process them?** The
queue fills, then capture blocks. Nothing is dropped inside the program.
In live capture, the kernel's buffer can overflow if the program stays
behind for long.

**Why did adding workers make it slower at first?** Every packet woke a
worker, so workers took one packet each and fought over the queue lock.
Batching with a short wait fixed it.

**Is the GPU worth it?** On this workload, yes with batches of 256 or
more: up to 1.25× faster end to end than the best CPU setting. But only
after fixing an unrelated bottleneck, and only for the one rule that
fits a GPU. For small batches the CPU is faster.

**How do you know the GPU gives the same answers?** A test compares GPU
and CPU entropy on 2,020 payloads (max difference 1.15e-6), and every
benchmark run checks that the alert counts are identical.

**What would you do next?** Detect SYN floods per destination as well as
per source (to catch spoofed floods), match signatures anywhere inside a
payload (Rabin-Karp, which would also give the GPU heavier work), and
raise the capture thread's ceiling, which limits the GPU runs again now.
