#include "pcap_reader.h"
#include "platform.h"
#include <algorithm>
#include <cstring>
#include <iostream>

namespace PacketAnalyzer {

namespace {

constexpr uint32_t MAGIC_US      = 0xa1b2c3d4;
constexpr uint32_t MAGIC_US_SWAP = 0xd4c3b2a1;
constexpr uint32_t MAGIC_NS      = 0xa1b23c4d;
constexpr uint32_t MAGIC_NS_SWAP = 0x4d3cb2a1;

constexpr uint32_t NG_SHB = 0x0A0D0D0A;
constexpr uint32_t NG_IDB = 1;
constexpr uint32_t NG_SPB = 3;
constexpr uint32_t NG_EPB = 6;
constexpr uint32_t NG_BYTE_ORDER_MAGIC = 0x1A2B3C4D;
constexpr uint32_t kMaxBlockLen = (2u << 20);

// Link layers the parser understands (see PacketParser::parse).
bool supportedLinkType(uint32_t lt) {
    return lt == 1 ||                    // Ethernet
           lt == 0 ||                    // BSD loopback / null
           lt == 12 || lt == 101 ||      // raw IP
           lt == 228 || lt == 229 ||     // raw IPv4 / IPv6
           lt == 113;                    // Linux cooked capture (SLL)
}

} // namespace

PcapReader::~PcapReader() {
    close();
}

void PcapReader::fail(const std::string& msg) {
    error_ = true;
    std::cerr << "Error: " << msg << std::endl;
}

bool PcapReader::open(const std::string& filename) {
    close();
    error_ = false;

    file_ = std::fopen(filename.c_str(), "rb");
    if (!file_) {
        std::cerr << "Error: Could not open file: " << filename << std::endl;
        return false;
    }
    std::setvbuf(file_, nullptr, _IOFBF, 1 << 20);

    uint8_t first[4];
    if (std::fread(first, 1, 4, file_) != 4) {
        std::cerr << "Error: Could not read PCAP global header" << std::endl;
        close();
        return false;
    }
    std::rewind(file_);

    uint32_t magic;
    std::memcpy(&magic, first, 4);

    const bool ok = (magic == NG_SHB) ? openPcapNg() : openClassic();
    if (!ok) close();
    return ok;
}

bool PcapReader::openClassic() {
    if (std::fread(&global_header_, 1, sizeof(PcapGlobalHeader), file_) != sizeof(PcapGlobalHeader)) {
        std::cerr << "Error: Could not read PCAP global header" << std::endl;
        return false;
    }

    switch (global_header_.magic_number) {
        case MAGIC_US:      needs_byte_swap_ = false; nanosecond_ = false; break;
        case MAGIC_US_SWAP: needs_byte_swap_ = true;  nanosecond_ = false; break;
        case MAGIC_NS:      needs_byte_swap_ = false; nanosecond_ = true;  break;
        case MAGIC_NS_SWAP: needs_byte_swap_ = true;  nanosecond_ = true;  break;
        case NG_SHB:
            std::cerr << "Error: PCAPNG format detected (0x0A0D0D0A). Please use standard PCAP or enable PCAPNG parsing." << std::endl;
            return false;
        default:
            std::cerr << "Error: Invalid PCAP magic number: 0x" << std::hex
                      << global_header_.magic_number << std::dec << std::endl;
            return false;
    }

    if (needs_byte_swap_) {
        global_header_.version_major = maybeSwap16(global_header_.version_major);
        global_header_.version_minor = maybeSwap16(global_header_.version_minor);
        global_header_.thiszone = static_cast<int32_t>(maybeSwap32(static_cast<uint32_t>(global_header_.thiszone)));
        global_header_.sigfigs = maybeSwap32(global_header_.sigfigs);
        global_header_.snaplen = maybeSwap32(global_header_.snaplen);
        global_header_.network = maybeSwap32(global_header_.network);
    }

    if (!supportedLinkType(global_header_.network)) {
        std::cerr << "Error: Unsupported link type " << global_header_.network
                  << " (supported: Ethernet, raw IP, Linux cooked, loopback)" << std::endl;
        return false;
    }

    if (verbose_) {
        std::cout << "Opened PCAP file" << (nanosecond_ ? " (nanosecond timestamps)" : "") << "\n"
                  << "  Version: " << global_header_.version_major << "." << global_header_.version_minor << "\n"
                  << "  Snaplen: " << global_header_.snaplen << " bytes\n"
                  << "  Link type: " << global_header_.network
                  << (global_header_.network == 1 ? " (Ethernet)" : "") << std::endl;
    }
    return true;
}

bool PcapReader::openPcapNg() {
    pcapng_ = true;
    interfaces_.clear();
    // The first block must be a Section Header Block; readPcapNg() parses it
    // like any other block (it also fixes the byte order), so just check the
    // length of what is there and announce the format.
    if (verbose_) std::cout << "Opened pcapng file" << std::endl;
    return true;
}

void PcapReader::close() {
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }
    needs_byte_swap_ = false;
    nanosecond_ = false;
    pcapng_ = false;
    interfaces_.clear();
    last_ts_us_ = 0;
}

bool PcapReader::skipBytes(size_t n) {
    uint8_t buf[4096];
    while (n > 0) {
        const size_t k = std::min(n, sizeof(buf));
        if (std::fread(buf, 1, k, file_) != k) return false;
        n -= k;
    }
    return true;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (!file_) return false;
    return pcapng_ ? readPcapNg(packet) : readClassic(packet);
}

bool PcapReader::readClassic(RawPacket& packet) {
    const size_t n = std::fread(&packet.header, 1, sizeof(PcapPacketHeader), file_);
    if (n == 0) return false;  // clean EOF
    if (n != sizeof(PcapPacketHeader)) {
        fail("truncated packet header at end of file");
        return false;
    }

    if (needs_byte_swap_) {
        packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
        packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
        packet.header.incl_len = maybeSwap32(packet.header.incl_len);
        packet.header.orig_len = maybeSwap32(packet.header.orig_len);
    }
    if (nanosecond_) packet.header.ts_usec /= 1000;

    // Do not trust snaplen: tools write 262144 or more, and some write 0.
    if (packet.header.incl_len > kMaxPacketLen) {
        fail("invalid packet length " + std::to_string(packet.header.incl_len) + ", stopping");
        return false;
    }

    packet.data.resize(packet.header.incl_len);
    if (packet.header.incl_len > 0 &&
        std::fread(packet.data.data(), 1, packet.header.incl_len, file_) != packet.header.incl_len) {
        fail("truncated packet data at end of file");
        return false;
    }
    packet.link_type = global_header_.network;
    return true;
}

bool PcapReader::readPcapNg(RawPacket& packet) {
    for (;;) {
        uint8_t hdr[8];
        const size_t n = std::fread(hdr, 1, 8, file_);
        if (n == 0) return false;
        if (n != 8) { fail("truncated pcapng block header"); return false; }

        uint32_t type, len;
        std::memcpy(&type, hdr, 4);
        std::memcpy(&len, hdr + 4, 4);

        if (type == NG_SHB) {
            // The block length is in the section's own byte order, which is
            // only known after the byte-order magic that follows it.
            uint8_t bom[4];
            if (std::fread(bom, 1, 4, file_) != 4) { fail("truncated pcapng section header"); return false; }
            uint32_t b;
            std::memcpy(&b, bom, 4);
            if (b == NG_BYTE_ORDER_MAGIC) needs_byte_swap_ = false;
            else if (b == PortableNet::swap32(NG_BYTE_ORDER_MAGIC)) needs_byte_swap_ = true;
            else { fail("bad pcapng byte-order magic"); return false; }
            len = maybeSwap32(len);
            if (len < 28 || len > kMaxBlockLen || (len & 3)) { fail("bad pcapng section length"); return false; }
            if (!skipBytes(len - 12)) { fail("truncated pcapng section header"); return false; }
            interfaces_.clear();
            continue;
        }

        type = maybeSwap32(type);
        len = maybeSwap32(len);
        if (len < 12 || len > kMaxBlockLen || (len & 3)) {
            fail("bad pcapng block length " + std::to_string(len));
            return false;
        }

        block_.resize(len - 8);  // body + trailing length field
        if (std::fread(block_.data(), 1, block_.size(), file_) != block_.size()) {
            fail("truncated pcapng block");
            return false;
        }
        const uint8_t* body = block_.data();
        const size_t body_len = len - 12;

        auto rd16 = [&](size_t off) { uint16_t v; std::memcpy(&v, body + off, 2); return maybeSwap16(v); };
        auto rd32 = [&](size_t off) { uint32_t v; std::memcpy(&v, body + off, 4); return maybeSwap32(v); };

        if (type == NG_IDB) {
            if (body_len < 8) continue;
            NgInterface itf;
            itf.link_type = rd16(0);
            itf.snaplen = rd32(4);
            uint8_t tsresol = 6;
            size_t o = 8;
            while (o + 4 <= body_len) {
                const uint16_t code = rd16(o);
                const uint16_t olen = rd16(o + 2);
                o += 4;
                if (code == 0) break;
                if (o + olen > body_len) break;
                if (code == 9 && olen >= 1) tsresol = body[o];  // if_tsresol
                o += (static_cast<size_t>(olen) + 3) & ~static_cast<size_t>(3);
            }
            if (tsresol & 0x80) {
                itf.units_per_sec = 1ull << std::min<int>(tsresol & 0x7F, 62);
            } else {
                uint64_t u = 1;
                for (int i = 0; i < std::min<int>(tsresol, 18); ++i) u *= 10;
                itf.units_per_sec = u;
            }
            interfaces_.push_back(itf);
            if (verbose_ && interfaces_.size() == 1) {
                std::cout << "  Link type: " << itf.link_type << (itf.link_type == 1 ? " (Ethernet)" : "") << std::endl;
            }
            continue;
        }

        if (type == NG_EPB) {
            if (body_len < 20) continue;
            const uint32_t ifid = rd32(0);
            const uint64_t ts = (static_cast<uint64_t>(rd32(4)) << 32) | rd32(8);
            const uint32_t cap = rd32(12);
            const uint32_t orig = rd32(16);
            if (ifid >= interfaces_.size()) continue;
            if (cap > kMaxPacketLen || cap > body_len - 20) { fail("invalid pcapng packet length"); return false; }
            const NgInterface& itf = interfaces_[ifid];
            if (!supportedLinkType(itf.link_type)) continue;

            const long double us = static_cast<long double>(ts) * 1000000.0L /
                                   static_cast<long double>(itf.units_per_sec);
            const uint64_t us64 = static_cast<uint64_t>(us);
            last_ts_us_ = us64;
            packet.header.ts_sec = static_cast<uint32_t>(us64 / 1000000ull);
            packet.header.ts_usec = static_cast<uint32_t>(us64 % 1000000ull);
            packet.header.incl_len = cap;
            packet.header.orig_len = orig;
            packet.data.assign(body + 20, body + 20 + cap);
            packet.link_type = itf.link_type;
            return true;
        }

        if (type == NG_SPB) {
            if (body_len < 4 || interfaces_.empty()) continue;
            const NgInterface& itf = interfaces_[0];
            if (!supportedLinkType(itf.link_type)) continue;
            const uint32_t orig = rd32(0);
            uint32_t cap = static_cast<uint32_t>(std::min<size_t>(orig, body_len - 4));
            if (itf.snaplen) cap = std::min(cap, itf.snaplen);
            if (cap > kMaxPacketLen) { fail("invalid pcapng packet length"); return false; }
            packet.header.ts_sec = static_cast<uint32_t>(last_ts_us_ / 1000000ull);  // SPB has no timestamp
            packet.header.ts_usec = static_cast<uint32_t>(last_ts_us_ % 1000000ull);
            packet.header.incl_len = cap;
            packet.header.orig_len = orig;
            packet.data.assign(body + 4, body + 4 + cap);
            packet.link_type = itf.link_type;
            return true;
        }
        // Any other block type (statistics, name resolution, ...) is skipped.
    }
}

uint16_t PcapReader::maybeSwap16(uint16_t value) const {
    return needs_byte_swap_ ? PortableNet::swap16(value) : value;
}

uint32_t PcapReader::maybeSwap32(uint32_t value) const {
    return needs_byte_swap_ ? PortableNet::swap32(value) : value;
}

} // namespace PacketAnalyzer
