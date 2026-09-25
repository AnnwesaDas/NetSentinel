#!/usr/bin/env python3
"""Generates a reproducible benchmark capture with a realistic traffic mix.

Same seed, same file, byte for byte, so CPU and GPU runs (and runs on
different days) see identical input. The mix follows the usual shape of
internet traffic: bimodal packet sizes (bare ACKs and full-size segments),
mostly encrypted payloads, some plaintext and DNS.

  ~40% TCP, no payload (ACKs)
  ~35% TCP, 1460-byte payload (full segments; 85% encrypted-looking)
  ~15% TCP, 100-1000 bytes (mixed encrypted and plaintext)
  ~10% UDP, 20-120 bytes (DNS-like)

A real capture is an alternative (see docs/BENCHMARK.md), but it contains
your own traffic, which is why *.pcap is gitignored.
"""
import argparse
import random
import socket
import struct

PLAINTEXT = (b"GET /api/v1/items?page=2 HTTP/1.1\r\nHost: example.com\r\n"
             b"Accept: application/json\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
             b"The quick brown fox jumps over the lazy dog. " * 40)


def eth(payload):
    return b"\xbb" * 6 + b"\xaa" * 6 + struct.pack("!H", 0x0800) + payload


def ipv4(src, dst, proto, payload):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                       src, dst) + payload


def tcp(sport, dport, flags, payload):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def payload_bytes(rng, n, encrypted):
    if encrypted:
        return rng.randbytes(n)
    start = rng.randrange(len(PLAINTEXT) - n) if n < len(PLAINTEXT) else 0
    return PLAINTEXT[start:start + n]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", default="benchmark.pcap")
    parser.add_argument("-n", "--packets", type=int, default=500_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    # A few hundred hosts talking to a few dozen servers, like a busy LAN.
    clients = [socket.inet_aton(f"10.1.{i // 250}.{i % 250 + 1}") for i in range(400)]
    servers = [socket.inet_aton(f"172.16.0.{i + 1}") for i in range(40)]
    server_ports = [443] * 8 + [80, 53, 22, 8080]

    ts_usec = 1_700_000_000 * 1_000_000
    with open(args.output, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for _ in range(args.packets):
            client, server = rng.choice(clients), rng.choice(servers)
            sport, dport = rng.randrange(32768, 61000), rng.choice(server_ports)
            if rng.random() < 0.5:  # reply direction
                client, server, sport, dport = server, client, dport, sport

            r = rng.random()
            if r < 0.40:
                frame = eth(ipv4(client, server, 6, tcp(sport, dport, 0x10, b"")))
            elif r < 0.75:
                body = payload_bytes(rng, 1460, rng.random() < 0.85)
                frame = eth(ipv4(client, server, 6, tcp(sport, dport, 0x18, body)))
            elif r < 0.90:
                body = payload_bytes(rng, rng.randrange(100, 1001), rng.random() < 0.6)
                frame = eth(ipv4(client, server, 6, tcp(sport, dport, 0x18, body)))
            else:
                body = payload_bytes(rng, rng.randrange(20, 121), False)
                frame = eth(ipv4(client, server, 17, udp(sport, 53, body)))

            ts_usec += rng.randrange(20, 200)  # roughly 10k packets/sec of capture time
            f.write(struct.pack("<IIII", ts_usec // 1_000_000, ts_usec % 1_000_000,
                                len(frame), len(frame)))
            f.write(frame)

    print(f"wrote {args.packets} packets to {args.output}")


if __name__ == "__main__":
    main()
