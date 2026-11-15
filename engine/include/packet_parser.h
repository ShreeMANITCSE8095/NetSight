#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include "pcap_reader.h"
#include "types.h"

namespace PacketAnalyzer {

// Parsed packet information. Every member has a default so nothing is ever
// read uninitialised.
struct ParsedPacket {
    uint32_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;

    uint16_t ether_type = 0;      // EtherType of the L3 payload (VLAN tags already skipped)

    // IP layer (IPv4 or IPv6)
    bool has_ip = false;
    uint8_t ip_version = 0;
    DPI::IPAddress src_ip;
    DPI::IPAddress dest_ip;
    uint8_t protocol = 0;         // final upper-layer protocol (after IPv6 extension headers)
    uint8_t ttl = 0;
    bool is_fragment = false;     // non-first IP fragment: no transport header in this packet

    // Transport layer
    bool has_tcp = false;
    bool has_udp = false;
    bool has_icmp = false;        // ICMP or ICMPv6; ports stay 0
    uint16_t src_port = 0;
    uint16_t dest_port = 0;

    // TCP-specific
    uint8_t tcp_flags = 0;
    uint32_t seq_number = 0;
    uint32_t ack_number = 0;

    // Link header + IP datagram. Excludes Ethernet padding and the FCS, which
    // used to be counted as payload on short frames.
    size_t frame_bytes = 0;

    // Payload (points into the original packet)
    size_t payload_length = 0;
    const uint8_t* payload_data = nullptr;
};

class PacketParser {
public:
    // Parse a raw packet. Returns false for a malformed/truncated packet.
    // A well-formed non-IP packet (ARP, ...) returns true with has_ip == false.
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

    static std::string macToString(const uint8_t* mac);
    static std::string protocolToString(uint8_t protocol);
    static std::string tcpFlagsToString(uint8_t flags);

private:
    static bool parseEthernet(const uint8_t* data, size_t len, size_t& offset, uint16_t& ether_type);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset, size_t& l3_end);
    static bool parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset, size_t& l3_end);
    static bool parseTransport(const uint8_t* data, size_t& end, ParsedPacket& parsed, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t end, ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t& end, ParsedPacket& parsed, size_t& offset);
    static bool parseICMP(size_t end, ParsedPacket& parsed, size_t& offset);
};

namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

namespace Protocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
    constexpr uint8_t ICMPV6 = 58;
}

namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP  = 0x0806;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t QINQ = 0x88A8;
}

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H
