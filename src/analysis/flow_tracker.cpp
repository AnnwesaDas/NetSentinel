#include "netsentinel/flow_tracker.hpp"

#include <cstdio>

#include "netsentinel/headers.hpp"

namespace netsentinel {

namespace {
int64_t timeval_to_ms(const struct timeval& tv) {
    return static_cast<int64_t>(tv.tv_sec) * 1000 + tv.tv_usec / 1000;
}

// What the port-scan rule counts: attempts to open a connection, not all
// traffic. Counting every packet flags busy servers, whose replies go to
// hundreds of clients' ephemeral ports. For TCP that's a SYN without an ACK.
// UDP has no handshake, so a datagram sent *from* a well-known service port
// (below 1024) is treated as a server's reply. A scanner can evade the UDP
// half by sending from such a port (e.g. nmap --source-port 53).
bool is_connection_attempt(const ParsedPacket& meta) {
    if (meta.transport == Transport::kTCP) {
        return (meta.tcp_flags & kTcpFlagSyn) != 0 && (meta.tcp_flags & kTcpFlagAck) == 0;
    }
    if (meta.transport == Transport::kUDP) {
        return meta.src_port >= 1024;
    }
    return false;
}
}  // namespace

size_t FlowTracker::FlowKeyHash::operator()(const FlowKey& k) const {
    size_t h = std::hash<uint32_t>{}(k.src_ip);
    h ^= std::hash<uint32_t>{}(k.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint16_t>{}(k.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint16_t>{}(k.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

FlowTracker::FlowTracker(FlowTrackerConfig config) : config_(config) {
    if (config_.num_shards == 0) {
        config_.num_shards = 1;
    }
    shards_.reserve(config_.num_shards);
    for (size_t i = 0; i < config_.num_shards; ++i) {
        shards_.push_back(std::make_unique<Shard>());
    }
}

FlowTracker::Shard& FlowTracker::shard_for(uint32_t src_ip) {
    return *shards_[std::hash<uint32_t>{}(src_ip) % shards_.size()];
}

void FlowTracker::evict_stale(Shard& shard, int64_t now_ms, uint32_t keep_ip) {
    const int64_t idle_cutoff = now_ms - config_.idle_ttl_ms;
    for (auto it = shard.per_ip.begin(); it != shard.per_ip.end();) {
        if (it->first != keep_ip && it->second.last_seen_ms < idle_cutoff) {
            it = shard.per_ip.erase(it);
        } else {
            ++it;
        }
    }

    // Hard ceiling: if idle eviction wasn't enough (a burst of many
    // simultaneously-active IPs, e.g. a spoofed-source flood), drop
    // records until back at the cap so memory stays bounded.
    for (auto it = shard.per_ip.begin();
         shard.per_ip.size() > config_.max_tracked_ips_per_shard && it != shard.per_ip.end();) {
        if (it->first == keep_ip) {
            ++it;
        } else {
            it = shard.per_ip.erase(it);
        }
    }
}

bool FlowTracker::debounce_allows(std::optional<int64_t>& last_alert_ms, int64_t now_ms) const {
    if (last_alert_ms.has_value() && now_ms - *last_alert_ms < config_.alert_debounce_ms) {
        return false;
    }
    last_alert_ms = now_ms;
    return true;
}

std::vector<Alert> FlowTracker::observe(const QueuedPacket& packet) {
    std::vector<Alert> alerts;
    const auto& meta = packet.meta;
    if (!meta.has_ip) {
        return alerts;
    }

    const int64_t now_ms = timeval_to_ms(meta.timestamp);
    Shard& shard = shard_for(meta.src_ip);
    std::lock_guard<std::mutex> lock(shard.mutex);

    {
        PerIpState& state = shard.per_ip[meta.src_ip];
        state.last_seen_ms = now_ms;

        // --- Port scan: distinct destination ports probed within the window ---
        if (is_connection_attempt(meta)) {
            state.recent_dst_ports.emplace_back(now_ms, meta.dst_port);
            ++state.port_counts[meta.dst_port];

            const int64_t cutoff = now_ms - config_.port_scan_window_ms;
            while (!state.recent_dst_ports.empty() &&
                   state.recent_dst_ports.front().first < cutoff) {
                const uint16_t expired_port = state.recent_dst_ports.front().second;
                state.recent_dst_ports.pop_front();
                auto count_it = state.port_counts.find(expired_port);
                if (count_it != state.port_counts.end() && --count_it->second == 0) {
                    state.port_counts.erase(count_it);
                }
            }

            const size_t distinct_ports = state.port_counts.size();
            if (distinct_ports >= config_.port_scan_distinct_port_threshold &&
                debounce_allows(state.last_port_scan_alert_ms, now_ms)) {
                Alert alert;
                alert.type = AnomalyType::kPortScan;
                alert.src_ip = meta.src_ip;
                alert.dst_ip = meta.dst_ip;
                char detail[96];
                std::snprintf(detail, sizeof(detail), "%zu distinct ports in %lldms",
                              distinct_ports,
                              static_cast<long long>(config_.port_scan_window_ms));
                alert.detail = detail;
                alerts.push_back(std::move(alert));
            }
        }

        // --- SYN flood: SYN packets from this source with no completing ACK ---
        if (meta.transport == Transport::kTCP) {
            const FlowKey key{meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port};
            const bool is_syn = (meta.tcp_flags & kTcpFlagSyn) != 0;
            const bool is_ack = (meta.tcp_flags & kTcpFlagAck) != 0;

            if (is_syn && !is_ack) {
                state.pending_syns[key] = now_ms;
                state.pending_syn_order.emplace_back(now_ms, key);
            } else if (is_ack) {
                // Any later packet from this same source on the same 4-tuple
                // with ACK set means the client is progressing/completing the
                // handshake itself — a real SYN-flood source never does this.
                // Its now-stale ordering entry is skipped during expiry.
                state.pending_syns.erase(key);
            }

            const int64_t cutoff = now_ms - config_.syn_flood_window_ms;
            while (!state.pending_syn_order.empty() &&
                   state.pending_syn_order.front().first < cutoff) {
                const auto& [queued_ms, queued_key] = state.pending_syn_order.front();
                auto pending_it = state.pending_syns.find(queued_key);
                // Only drop it if this really is the SYN that was queued —
                // a newer SYN on the same 4-tuple refreshes the timestamp
                // and gets its own, later ordering entry.
                if (pending_it != state.pending_syns.end() && pending_it->second == queued_ms) {
                    state.pending_syns.erase(pending_it);
                }
                state.pending_syn_order.pop_front();
            }

            if (state.pending_syns.size() >= config_.syn_flood_pending_threshold &&
                debounce_allows(state.last_syn_flood_alert_ms, now_ms)) {
                Alert alert;
                alert.type = AnomalyType::kSynFlood;
                alert.src_ip = meta.src_ip;
                char detail[96];
                std::snprintf(detail, sizeof(detail), "%zu pending SYNs in %lldms",
                              state.pending_syns.size(),
                              static_cast<long long>(config_.syn_flood_window_ms));
                alert.detail = detail;
                alerts.push_back(std::move(alert));
            }
        }
    }  // `state` reference ends here — eviction below may invalidate it

    if (++shard.observations_since_sweep >= config_.sweep_interval_packets) {
        shard.observations_since_sweep = 0;
        evict_stale(shard, now_ms, meta.src_ip);
    }

    return alerts;
}

size_t FlowTracker::tracked_ip_count() const {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard->mutex);
        total += shard->per_ip.size();
    }
    return total;
}

}  // namespace netsentinel
