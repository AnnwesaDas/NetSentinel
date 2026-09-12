// Manual Ethernet/IP/TCP/UDP header parsing over raw captured bytes.
#pragma once

#include <cstdint>
#include <ctime>
#include <optional>

#include "netsentinel/packet.hpp"

namespace netsentinel {

// Parses a single captured frame starting at `data` (Ethernet header first).
// `caplen` is the number of bytes actually available at `data` — every
// field access is bounds-checked against it, since a snaplen-truncated or
// malformed packet must never cause an out-of-bounds read.
// Returns std::nullopt for frames this parser doesn't understand (non-IPv4
// ethertypes) rather than a partially-filled packet.
std::optional<ParsedPacket> parse_packet(const uint8_t* data, uint32_t caplen,
                                          uint32_t wire_length, struct timeval ts);

}  // namespace netsentinel
