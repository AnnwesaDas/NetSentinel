// Per-source-IP state for the stateful rules (port scan, SYN flood),
// touched concurrently by every worker thread. Design: a sharded map keyed
// by hash(src_ip) — each shard has its own mutex, so unrelated source IPs
// never contend, and packets from the same IP always land on the same
// shard and see a consistent view of that IP's history.
//
// Two properties matter as much as correctness here, because both are
// reachable by an attacker who knows what the detector does:
//   - Per-packet work is O(1) amortized. A naive "recount the distinct
//     ports in the window on every packet" is O(window) per packet, i.e.
//     quadratic over a sustained scan — the detector collapses under
//     exactly the traffic it exists to catch.
//   - Tracked state is bounded. Per-IP records are evicted once idle, and
//     capped per shard, so a flood of unique (e.g. spoofed) source IPs
//     can't grow memory without limit.
#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include "netsentinel/alert.hpp"
#include "netsentinel/packet_queue.hpp"

namespace netsentinel {

struct FlowTrackerConfig {
    size_t num_shards = 16;

    // Port scan: flag a source IP once it has touched this many distinct
    // destination ports within the trailing window.
    int64_t port_scan_window_ms = 5000;
    size_t port_scan_distinct_port_threshold = 10;

    // SYN flood: flag a source IP once it has this many SYN-only packets
    // with no completing ACK yet, within the trailing window.
    int64_t syn_flood_window_ms = 2000;
    size_t syn_flood_pending_threshold = 20;

    // Once a source IP has been flagged for a rule, don't re-flag it again
    // for that same rule until this much time has passed — otherwise every
    // single subsequent packet from an ongoing scan/flood would each emit
    // their own alert.
    int64_t alert_debounce_ms = 2000;

    // Memory bounding. A source IP whose last packet is older than
    // idle_ttl_ms is forgotten; sweeps run every sweep_interval_packets
    // observations on a shard. If a shard still exceeds
    // max_tracked_ips_per_shard after a sweep, further records are dropped
    // to stay at the cap (approximate, not strict LRU — the point is a
    // hard memory ceiling, not perfect retention).
    //
    // Sizing: a tracked IP costs ~2KB measured (the per-IP deques and hash
    // maps each carry a fixed allocation), so these defaults put the
    // ceiling at 16 * 1024 ≈ 16k IPs ≈ 40MB even against a flood of
    // unique spoofed sources. Idle eviction alone is not enough for that
    // case — a flood's sources are all "recent" — which is why the hard
    // cap exists. Shrinking the per-IP state itself is the obvious next
    // optimization if more tracked hosts are ever needed.
    int64_t idle_ttl_ms = 60000;
    uint64_t sweep_interval_packets = 256;
    size_t max_tracked_ips_per_shard = 1024;
};

class FlowTracker {
public:
    explicit FlowTracker(FlowTrackerConfig config = {});

    // Thread-safe: safe to call concurrently from any number of worker
    // threads. Returns any alerts raised by observing this packet (usually
    // none).
    std::vector<Alert> observe(const QueuedPacket& packet);

    // Number of source IPs currently tracked across all shards. Exposed
    // for tests and diagnostics — this is the number the eviction policy
    // is there to bound.
    [[nodiscard]] size_t tracked_ip_count() const;

private:
    struct FlowKey {
        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port;
        bool operator==(const FlowKey& other) const {
            return src_ip == other.src_ip && dst_ip == other.dst_ip &&
                   src_port == other.src_port && dst_port == other.dst_port;
        }
    };
    struct FlowKeyHash {
        size_t operator()(const FlowKey& k) const;
    };

    struct PerIpState {
        // Sliding window of (timestamp, port) events, plus a live count of
        // how many times each port appears in that window. The counts map
        // is what makes "how many distinct ports?" an O(1) size() lookup
        // instead of an O(window) recount per packet.
        std::deque<std::pair<int64_t, uint16_t>> recent_dst_ports;
        std::unordered_map<uint16_t, uint32_t> port_counts;

        // Half-open connections: key -> timestamp of its most recent SYN.
        // `pending_syn_order` mirrors the insertions in time order so
        // expiry pops from the front instead of rescanning the whole map
        // on every packet (which is the same quadratic trap as the port
        // window above — and a sustained flood is precisely when the map
        // is largest).
        std::unordered_map<FlowKey, int64_t, FlowKeyHash> pending_syns;
        std::deque<std::pair<int64_t, FlowKey>> pending_syn_order;
        int64_t last_seen_ms = 0;

        // Empty means "never alerted for this rule". Encoding that as 0
        // instead would make the debounce check read as "last alerted at
        // the epoch", which silently swallows the first alert for any
        // capture whose timestamps are small (relative or synthetic ones).
        std::optional<int64_t> last_port_scan_alert_ms;
        std::optional<int64_t> last_syn_flood_alert_ms;
    };

    struct Shard {
        std::mutex mutex;
        std::unordered_map<uint32_t, PerIpState> per_ip;
        uint64_t observations_since_sweep = 0;
    };

    Shard& shard_for(uint32_t src_ip);

    // Caller must hold shard.mutex. Never evicts `keep_ip`, which the
    // caller is currently holding a reference to.
    void evict_stale(Shard& shard, int64_t now_ms, uint32_t keep_ip);

    // True if this rule may alert again for this IP now; stamps the alert
    // time as a side effect when it returns true.
    bool debounce_allows(std::optional<int64_t>& last_alert_ms, int64_t now_ms) const;

    FlowTrackerConfig config_;
    std::vector<std::unique_ptr<Shard>> shards_;
};

}  // namespace netsentinel
