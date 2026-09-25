# Demo walkthrough

A 10-minute demo, from a clean build to live traffic. Every step works
without a network except the last two. Outputs shown are from real runs.

## 1. Build and test (2 minutes)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DNETSENTINEL_ENABLE_METAL=ON
cmake --build build
ctest --test-dir build
```

Expect `100% tests passed out of 6` on a Mac with Metal (5 elsewhere).
Worth saying: the tests check both directions of every rule, so each
rule fires on an attack *and* stays quiet on similar-looking normal
traffic.

## 2. Catch one of each attack (1 minute)

`gen_synthetic_attacks.py` writes a small capture with a port scan, a SYN
flood, a random (encrypted-looking) payload, a payload matching the EICAR
antivirus test string, and ordinary web traffic that must *not* alert.

```sh
python3 scripts/gen_synthetic_attacks.py -o demo.pcap
./build/netsentinel -r demo.pcap
```

```
[ALERT] PORT_SCAN             src=10.0.0.66 — 10 distinct ports in 5000ms
[ALERT] SYN_FLOOD             src=10.0.0.66 — 20 pending SYNs in 2000ms
[ALERT] SIGNATURE_MATCH       src=10.0.0.78:6001 dst=10.0.0.2:8080 — payload matches a known-bad signature hash
[ALERT] HIGH_ENTROPY_PAYLOAD  src=10.0.0.77:6000 dst=10.0.0.2:443 — entropy=7.18 bits/byte over 256B
done — 47 packet(s) captured, 47 processed, 4 alert(s), ...
alerts by type: port_scan=1 syn_flood=1 high_entropy=1 signature=1
```

Four alerts, one per rule, and nothing for the benign traffic. The alert
order can differ between runs because workers run in parallel.

## 3. Show the parser (1 minute)

`-v` prints every decoded packet. `-w 1` keeps the output in order.

```sh
./build/netsentinel -r demo.pcap -v -w 1 | head -4
```

```
[1700000000.000000] len=54 cap=54  bb:bb:bb:bb:bb:bb -> aa:aa:aa:aa:aa:aa  10.0.0.66:50000 -> 10.0.0.1:20 proto=TCP ttl=64 flags=S payload=0B
[1700000000.050000] len=54 cap=54  bb:bb:bb:bb:bb:bb -> aa:aa:aa:aa:aa:aa  10.0.0.66:50001 -> 10.0.0.1:21 proto=TCP ttl=64 flags=S payload=0B
```

Each line is Ethernet, IPv4 and TCP headers, decoded by our own code:
MAC addresses, IPs, ports, TTL, TCP flags (`S` = SYN), payload size. The
first packets are the port scan: one source, SYNs to port 20, 21, 22 ...

## 4. CPU vs GPU (2 minutes)

```sh
python3 scripts/gen_benchmark_pcap.py -o benchmark.pcap
./build/netsentinel -r benchmark.pcap -s -b 1024
./build/netsentinel -r benchmark.pcap -s -b 1024 -g
```

The first command takes a few minutes, so run it before the demo. `-s`
counts alerts instead of printing them. On an Apple M5, expect about
3.3M packets/sec on the CPU and 4.2M with `-g`, with exactly 188,341
high-entropy alerts both times. Then point at the last line:

```
waiting: capture thread blocked on a full queue 0% of its ..., workers waiting for packets ...% of their time
```

It shows which side of the queue is the bottleneck. Then show
`docs/benchmark.svg`: with small batches (`-b 64`) the CPU is faster,
because each GPU dispatch has a fixed ~0.22 ms cost.

## 5. Live capture (2 minutes)

```sh
sudo ./build/netsentinel -l
sudo ./build/netsentinel -i en0
```

Open a few websites, then press Ctrl-C. Expect `HIGH_ENTROPY_PAYLOAD`
alerts on port 443: HTTPS is encrypted, and encrypted bytes look random.
That's a known limitation, and worth raising yourself: entropy alone
can't tell normal TLS from data being smuggled out; it needs context,
such as which ports normally carry plaintext.

## 6. A real port scan (optional)

Only scan a machine you own, such as another computer of yours on the
same network. With netsentinel running in one terminal:

```sh
sudo nmap -sS -p 1-200 <ip-of-a-machine-you-own>
```

Expect `PORT_SCAN` and `SYN_FLOOD` alerts with your Mac's IP as the
source. A SYN scan never completes its handshakes, so it's also a small
SYN flood. `brew install nmap` if needed. On macOS, capture on `en0`,
not `lo0`: loopback doesn't use Ethernet framing, and the parser only
reads Ethernet.

## The one-minute pitch

> NetSentinel is a packet capture and anomaly detection tool in C++17.
> One thread captures packets with libpcap and parses the headers by
> hand; a bounded queue feeds a pool of workers in batches; the workers
> run four detection rules, with shared per-IP state in a sharded, locked
> map. Entropy can run on the Apple GPU through Metal. I built a
> reproducible benchmark, and at first the GPU lost. Measuring each stage
> separately showed that the capture loop was making a system call per
> packet, which capped everything at 1.5M packets/sec. After fixing that,
> the pipeline reached 3.6M on the CPU and 4.5M with the GPU, and alerts
> were identical in all 160 runs.
