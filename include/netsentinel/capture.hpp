// Thin wrapper over libpcap: opens a live device or an offline .pcap file
// and delivers parsed packets to a callback. No threading, no queue — that
// lands in Phase 2. This exists so main.cpp doesn't touch libpcap directly.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "netsentinel/packet.hpp"

struct pcap;
typedef struct pcap pcap_t;

namespace netsentinel {

using PacketHandler = std::function<void(const ParsedPacket&)>;

class Capture {
public:
    Capture() = default;
    ~Capture();

    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;

    // Opens a live network interface. Returns false and fills `error` on
    // failure (e.g. missing /dev/bpf* permission on macOS — see README).
    bool open_live(const std::string& device, std::string& error, int snaplen = 65535,
                    bool promiscuous = true, int timeout_ms = 100);

    // Opens a previously captured .pcap file for offline replay.
    bool open_offline(const std::string& path, std::string& error);

    // Runs the capture loop, invoking `handler` for every packet this
    // parser understands (Phase 1: Ethernet + IPv4). Blocks until the
    // capture source is exhausted (offline) or an error/interrupt occurs
    // (live). `max_packets` of 0 means unlimited.
    // Returns the number of packets handed to the parser (not necessarily
    // all packets seen — non-IPv4 frames are still counted as "seen" via
    // the raw pcap stats, but only parsed ones reach `handler`).
    int run(const PacketHandler& handler, int max_packets = 0);

    // Requests the running capture loop to stop at the next opportunity.
    // Safe to call from a signal handler.
    void request_stop();

private:
    pcap_t* handle_ = nullptr;
    bool live_ = false;  // a network interface, not a file
};

// Lists available capture device names (populated names only), for
// diagnostics/CLI use. Returns an empty vector and fills `error` on failure.
std::vector<std::string> list_devices(std::string& error);

}  // namespace netsentinel
