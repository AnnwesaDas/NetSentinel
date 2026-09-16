#!/usr/bin/env python3
"""Generates a .pcap of synthetic attack + benign traffic for exercising
Phase 3's anomaly rules without needing a live attacker.

Covers what nmap/scapy would produce, without depending on either:
  - a SYN flood / port scan against a victim IP from many source IPs
  - a high-entropy (random-bytes) payload
  - a payload matching the built-in EICAR signature
  - ordinary plaintext HTTP-shaped traffic that must NOT trigger anything

For an even more realistic port-scan/SYN-flood test against a live process,
prefer a real `nmap -sS` run (see README) — this script exists for
reproducible regression testing (including Phase 5's benchmark replay
input) where a live scan tool isn't available or convenient.
"""
import argparse
import os
import socket
import struct


def eth(dst, src, ethertype, payload):
    return dst + src + struct.pack('!H', ethertype) + payload


def ipv4(src, dst, proto, payload, ttl=64, ident=1):
    total_len = 20 + len(payload)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ident, 0, ttl, proto, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def tcp(sport, dport, seq, ack, flags, payload):
    header = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return header + payload


MAC_ATTACKER = b'\xaa' * 6
MAC_VICTIM = b'\xbb' * 6

# Matches the C++ constant in src/analysis/signature_db.cpp exactly (built
# with an explicit backslash byte to avoid Python escape-sequence surprises).
EICAR = (b'X5O!P%@AP[4' + bytes([0x5c]) +
         b'PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')


def build_records():
    records = []  # (relative_seconds, raw_ethernet_frame)

    # Port scan + SYN flood: one attacker hitting 40 distinct ports with
    # bare SYNs (no completing ACK) in quick succession.
    attacker, victim = '10.0.0.66', '10.0.0.1'
    for i, port in enumerate(range(20, 60)):
        records.append((i * 0.05,
                         eth(MAC_ATTACKER, MAC_VICTIM, 0x0800,
                             ipv4(attacker, victim, 6, tcp(50000 + i, port, i, 0, 0x02, b'')))))

    # High-entropy payload (looks like encrypted/compressed exfil).
    records.append((10.0, eth(MAC_ATTACKER, MAC_VICTIM, 0x0800,
                               ipv4('10.0.0.77', '10.0.0.2', 6,
                                    tcp(6000, 443, 1, 1, 0x18, os.urandom(256))))))

    # Known-bad signature (EICAR test string).
    records.append((10.5, eth(MAC_ATTACKER, MAC_VICTIM, 0x0800,
                               ipv4('10.0.0.78', '10.0.0.2', 6,
                                    tcp(6001, 8080, 1, 1, 0x18, EICAR)))))

    # Benign plaintext traffic — must not trigger any rule.
    for i in range(5):
        payload = f'GET /page{i} HTTP/1.1\r\nHost: example.com\r\n\r\n'.encode()
        records.append((20.0 + i * 0.2,
                         eth(MAC_VICTIM, MAC_ATTACKER, 0x0800,
                             ipv4('10.0.0.50', '10.0.0.2', 6,
                                  tcp(51000 + i, 80, i, i, 0x18, payload)))))

    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-o', '--output', default='synthetic_attacks.pcap')
    args = parser.parse_args()

    records = build_records()
    with open(args.output, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        base_sec = 1700000000
        for rel_ts, rec in records:
            sec = base_sec + int(rel_ts)
            usec = int((rel_ts - int(rel_ts)) * 1_000_000)
            f.write(struct.pack('<IIII', sec, usec, len(rec), len(rec)))
            f.write(rec)

    print(f'wrote {len(records)} packets to {args.output}')


if __name__ == '__main__':
    main()
