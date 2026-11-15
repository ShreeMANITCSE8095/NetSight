#include "packet_parser.h"
#include "platform.h"
#include <algorithm>
#include <cstdio>

using PortableNet::readBE16;
using PortableNet::readBE32;

namespace PacketAnalyzer {

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket();
    parsed.timestamp_sec = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;

    const uint8_t* data = raw.data.data();
    const size_t len = raw.data.size();
    size_t offset = 0;
    uint16_t l3 = 0;

    switch (raw.link_type) {
        case 1:  // Ethernet (+ VLAN tags)
            if (!parseEthernet(data, len, offset, l3)) return false;
            break;
        case 113:  // Linux cooked capture v1: 16-byte header, protocol in the last 2 bytes
            if (len < 16) return false;
            l3 = readBE16(data + 14);
            offset = 16;
            break;
        case 0:  // BSD loopback: 4-byte address family, then raw IP
            if (len < 4) return false;
            offset = 4;
            break;
        case 12: case 101: case 228: case 229:  // raw IP
            break;
        default:
            return false;
    }

    if (l3 == 0) {  // raw IP link types: the version nibble tells v4 from v6
        if (offset >= len) return false;
        const uint8_t v = data[offset] >> 4;
        l3 = (v == 4) ? EtherType::IPv4 : (v == 6) ? EtherType::IPv6 : 0;
    }
    parsed.ether_type = l3;

    size_t l3_end = len;
    if (l3 == EtherType::IPv4) {
        if (!parseIPv4(data, len, parsed, offset, l3_end)) return false;
    } else if (l3 == EtherType::IPv6) {
        if (!parseIPv6(data, len, parsed, offset, l3_end)) return false;
    } else {
        return true;  // ARP, LLDP, ... : valid, just not IP
    }

    parsed.frame_bytes = l3_end;

    if (!parsed.is_fragment) {
        if (!parseTransport(data, l3_end, parsed, offset)) return false;
    }

    if (offset <= l3_end && l3_end <= len && (parsed.has_tcp || parsed.has_udp || parsed.has_icmp)) {
        parsed.payload_length = l3_end - offset;
        parsed.payload_data = data + offset;
    }
    return true;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len, size_t& offset, uint16_t& ether_type) {
    constexpr size_t ETH_HEADER_LEN = 14;
    if (len < ETH_HEADER_LEN) return false;

    uint16_t et = readBE16(data + 12);
    offset = ETH_HEADER_LEN;

    // 802.1Q / 802.1ad / QinQ: skip up to four tags. Industrial networks are
    // VLAN-heavy and these frames were silently dropped before.
    for (int i = 0; i < 4 && (et == EtherType::VLAN || et == EtherType::QINQ || et == 0x9100); ++i) {
        if (len < offset + 4) return false;
        et = readBE16(data + offset + 2);
        offset += 4;
    }
    ether_type = et;
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed,
                             size_t& offset, size_t& l3_end) {
    constexpr size_t MIN_IP_HEADER_LEN = 20;
    if (len < offset + MIN_IP_HEADER_LEN) return false;

    const uint8_t* ip = data + offset;
    if ((ip[0] >> 4) != 4) return false;

    const size_t ihl = static_cast<size_t>(ip[0] & 0x0F);
    if (ihl < 5) return false;
    const size_t header_len = ihl * 4;
    if (header_len < MIN_IP_HEADER_LEN || len < offset + header_len) return false;

    size_t total = readBE16(ip + 2);
    if (total == 0) total = len - offset;  // TSO/GSO captures leave the length at 0
    if (total < header_len) return false;
    // Trust the IP length, not the frame length: short Ethernet frames are
    // padded and the padding is not payload.
    l3_end = std::min(len, offset + total);

    parsed.ip_version = 4;
    parsed.ttl = ip[8];
    parsed.protocol = ip[9];
    parsed.src_ip = DPI::IPAddress::fromV4(ip + 12);
    parsed.dest_ip = DPI::IPAddress::fromV4(ip + 16);
    parsed.has_ip = true;

    if ((readBE16(ip + 6) & 0x1FFF) != 0) parsed.is_fragment = true;  // fragment offset != 0

    offset += header_len;
    return true;
}

bool PacketParser::parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed,
                             size_t& offset, size_t& l3_end) {
    constexpr size_t IPV6_HEADER_LEN = 40;
    if (len < offset + IPV6_HEADER_LEN) return false;

    const uint8_t* ip = data + offset;
    if ((ip[0] >> 4) != 6) return false;

    size_t payload_len = readBE16(ip + 4);
    if (payload_len == 0) payload_len = len - offset - IPV6_HEADER_LEN;  // jumbogram / offload
    l3_end = std::min(len, offset + IPV6_HEADER_LEN + payload_len);

    parsed.ip_version = 6;
    parsed.ttl = ip[7];
    parsed.src_ip = DPI::IPAddress::fromV6(ip + 8);
    parsed.dest_ip = DPI::IPAddress::fromV6(ip + 24);
    parsed.has_ip = true;

    uint8_t next = ip[6];
    offset += IPV6_HEADER_LEN;

    // Walk the extension header chain to the real upper-layer protocol.
    for (int hops = 0; hops < 8; ++hops) {
        if (next == 0 || next == 43 || next == 60) {          // hop-by-hop, routing, destination options
            if (l3_end < offset + 2) return false;
            const size_t ext_len = (static_cast<size_t>(data[offset + 1]) + 1) * 8;
            if (l3_end < offset + ext_len) return false;
            next = data[offset];
            offset += ext_len;
        } else if (next == 51) {                               // authentication header
            if (l3_end < offset + 2) return false;
            const size_t ext_len = (static_cast<size_t>(data[offset + 1]) + 2) * 4;
            if (l3_end < offset + ext_len) return false;
            next = data[offset];
            offset += ext_len;
        } else if (next == 44) {                               // fragment header
            if (l3_end < offset + 8) return false;
            if ((readBE16(data + offset + 2) >> 3) != 0) parsed.is_fragment = true;
            next = data[offset];
            offset += 8;
            if (parsed.is_fragment) break;
        } else {
            break;
        }
    }
    parsed.protocol = next;
    return true;
}

bool PacketParser::parseTransport(const uint8_t* data, size_t& end, ParsedPacket& parsed, size_t& offset) {
    switch (parsed.protocol) {
        case Protocol::TCP:    return parseTCP(data, end, parsed, offset);
        case Protocol::UDP:    return parseUDP(data, end, parsed, offset);
        case Protocol::ICMP:
        case Protocol::ICMPV6: return parseICMP(end, parsed, offset);
        default:               return true;  // GRE, ESP, SCTP, ...: IP only
    }
}

bool PacketParser::parseTCP(const uint8_t* data, size_t end, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t MIN_TCP_HEADER_LEN = 20;
    if (end < offset + MIN_TCP_HEADER_LEN) return false;

    const uint8_t* tcp = data + offset;
    const size_t data_offset = static_cast<size_t>(tcp[12] >> 4);
    if (data_offset < 5) return false;
    const size_t header_len = data_offset * 4;
    if (header_len < MIN_TCP_HEADER_LEN || end < offset + header_len) return false;

    parsed.src_port = readBE16(tcp);
    parsed.dest_port = readBE16(tcp + 2);
    parsed.seq_number = readBE32(tcp + 4);
    parsed.ack_number = readBE32(tcp + 8);
    parsed.tcp_flags = tcp[13];
    parsed.has_tcp = true;
    offset += header_len;
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t& end, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t UDP_HEADER_LEN = 8;
    if (end < offset + UDP_HEADER_LEN) return false;

    const uint8_t* udp = data + offset;
    parsed.src_port = readBE16(udp);
    parsed.dest_port = readBE16(udp + 2);
    parsed.has_udp = true;

    // The UDP length bounds the payload (Ethernet padding must not leak in).
    const size_t udp_len = readBE16(udp + 4);
    if (udp_len >= UDP_HEADER_LEN && offset + udp_len <= end) end = offset + udp_len;

    offset += UDP_HEADER_LEN;
    return true;
}

bool PacketParser::parseICMP(size_t end, ParsedPacket& parsed, size_t& offset) {
    constexpr size_t ICMP_HEADER_LEN = 8;
    if (end < offset + ICMP_HEADER_LEN) return false;
    parsed.has_icmp = true;  // ports stay 0 so a request and its reply share one flow
    offset += ICMP_HEADER_LEN;
    return true;
}

std::string PacketParser::macToString(const uint8_t* mac) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case Protocol::ICMP:   return "ICMP";
        case Protocol::TCP:    return "TCP";
        case Protocol::UDP:    return "UDP";
        case Protocol::ICMPV6: return "ICMPv6";
        default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string result;
    if (flags & TCPFlags::SYN) result += "SYN ";
    if (flags & TCPFlags::ACK) result += "ACK ";
    if (flags & TCPFlags::FIN) result += "FIN ";
    if (flags & TCPFlags::RST) result += "RST ";
    if (flags & TCPFlags::PSH) result += "PSH ";
    if (flags & TCPFlags::URG) result += "URG ";
    if (!result.empty()) result.pop_back();
    return result.empty() ? "none" : result;
}

} // namespace PacketAnalyzer
