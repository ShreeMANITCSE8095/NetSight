#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace PacketAnalyzer {

// PCAP Global Header (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number = 0;   // 0xa1b2c3d4 / 0xa1b23c4d (or byte-swapped)
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 0;
    uint32_t network = 0;        // link type (1 = Ethernet)
};

// Packet record header. ts_usec is ALWAYS microseconds, whatever the file used
// (nanosecond pcap and pcapng are converted while reading).
struct PcapPacketHeader {
    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;
    uint32_t incl_len = 0;
    uint32_t orig_len = 0;
};

struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
    uint32_t link_type = 1;  // pcap DLT of the interface this packet came from
};

// Reads classic pcap (microsecond and nanosecond, both byte orders) and pcapng.
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    bool open(const std::string& filename);
    void close();

    // false at clean end of file AND on a damaged file; hadError() tells which.
    bool readNextPacket(RawPacket& packet);

    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    bool isOpen() const { return file_ != nullptr; }
    bool needsByteSwap() const { return needs_byte_swap_; }
    bool isPcapNg() const { return pcapng_; }
    bool hadError() const { return error_; }
    void setVerbose(bool v) { verbose_ = v; }

    // Largest captured packet accepted (a sane bound against corrupt headers).
    static constexpr uint32_t kMaxPacketLen = 1u << 20;

private:
    struct NgInterface {
        uint32_t link_type = 1;
        uint32_t snaplen = 0;
        uint64_t units_per_sec = 1000000;  // if_tsresol, default microseconds
    };

    bool openClassic();
    bool openPcapNg();
    bool readClassic(RawPacket& packet);
    bool readPcapNg(RawPacket& packet);
    bool skipBytes(size_t n);
    void fail(const std::string& msg);

    uint16_t maybeSwap16(uint16_t value) const;
    uint32_t maybeSwap32(uint32_t value) const;

    FILE* file_ = nullptr;
    PcapGlobalHeader global_header_;
    bool needs_byte_swap_ = false;  // classic: file order != host order. pcapng: same, per section
    bool nanosecond_ = false;
    bool pcapng_ = false;
    bool error_ = false;
    bool verbose_ = true;
    std::vector<NgInterface> interfaces_;
    std::vector<uint8_t> block_;
    uint64_t last_ts_us_ = 0;
};

} // namespace PacketAnalyzer

#endif // PCAP_READER_H
