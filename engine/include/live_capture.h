#ifndef NETSIGHT_LIVE_CAPTURE_H
#define NETSIGHT_LIVE_CAPTURE_H

#include <string>
#include <vector>
#include <cstdint>
#include "pcap_reader.h"

namespace DPI {

struct LiveDevice {
    std::string name;
    std::string description;
};

struct CaptureStats {
    uint64_t received = 0;
    uint64_t dropped = 0;
};

class LiveCapture {
public:
    LiveCapture();
    ~LiveCapture();

    static bool isAvailable();
    static std::vector<LiveDevice> listDevices();
    static std::string getDefaultDevice();

    bool open(const std::string& device_name);
    bool readNextPacket(PacketAnalyzer::RawPacket& raw);
    void close();

    CaptureStats getStats();
    bool isErrorOrEof() const { return is_eof_or_error_; }
    int getLinkType() const { return link_type_; }
    const std::string& getLastError() const { return last_error_; }

private:
    void* handle_ = nullptr;
    int link_type_ = 1;
    bool is_eof_or_error_ = false;
    std::string last_error_;
};

} // namespace DPI

#endif // NETSIGHT_LIVE_CAPTURE_H

