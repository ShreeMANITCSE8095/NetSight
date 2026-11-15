#include "live_capture.h"
#include <iostream>
#include <cstring>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <dlfcn.h>
#endif

namespace DPI {

namespace {

struct PcapTimeval {
    long tv_sec;
    long tv_usec;
};

struct PcapPkthdr {
    PcapTimeval ts;
    uint32_t caplen;
    uint32_t len;
};

struct PcapIfItem {
    PcapIfItem* next;
    char* name;
    char* description;
    void* addresses;
    uint32_t flags;
};

struct PcapStat {
    uint32_t ps_recv;
    uint32_t ps_drop;
    uint32_t ps_ifdrop;
#if defined(_WIN32)
    uint32_t bs_capt;
#endif
};

typedef void* pcap_handle_t;
typedef int (*fn_pcap_findalldevs)(PcapIfItem**, char*);
typedef void (*fn_pcap_freealldevs)(PcapIfItem*);
typedef pcap_handle_t (*fn_pcap_open_live)(const char*, int, int, int, char*);
typedef pcap_handle_t (*fn_pcap_create)(const char*, char*);
typedef int (*fn_pcap_set_snaplen)(pcap_handle_t, int);
typedef int (*fn_pcap_set_promisc)(pcap_handle_t, int);
typedef int (*fn_pcap_set_timeout)(pcap_handle_t, int);
typedef int (*fn_pcap_set_buffer_size)(pcap_handle_t, int);
typedef int (*fn_pcap_set_immediate_mode)(pcap_handle_t, int);
typedef int (*fn_pcap_activate)(pcap_handle_t);
typedef int (*fn_pcap_next_ex)(pcap_handle_t, PcapPkthdr**, const uint8_t**);
typedef void (*fn_pcap_close)(pcap_handle_t);
typedef int (*fn_pcap_datalink)(pcap_handle_t);
typedef int (*fn_pcap_stats)(pcap_handle_t, PcapStat*);

struct PcapApi {
    void* lib_handle = nullptr;
    fn_pcap_findalldevs findalldevs = nullptr;
    fn_pcap_freealldevs freealldevs = nullptr;
    fn_pcap_open_live open_live = nullptr;
    fn_pcap_create create = nullptr;
    fn_pcap_set_snaplen set_snaplen = nullptr;
    fn_pcap_set_promisc set_promisc = nullptr;
    fn_pcap_set_timeout set_timeout = nullptr;
    fn_pcap_set_buffer_size set_buffer_size = nullptr;
    fn_pcap_set_immediate_mode set_immediate_mode = nullptr;
    fn_pcap_activate activate = nullptr;
    fn_pcap_next_ex next_ex = nullptr;
    fn_pcap_close close = nullptr;
    fn_pcap_datalink datalink = nullptr;
    fn_pcap_stats stats = nullptr;

    bool loaded = false;

    void init() {
        if (loaded) return;

#if defined(_WIN32)
        // Npcap's wpcap.dll dynamically loads Packet.dll from the same Npcap directory
        SetDllDirectoryA("C:\\Windows\\System32\\Npcap");
        const char* paths[] = {
            "wpcap.dll",
            "C:\\Windows\\System32\\Npcap\\wpcap.dll",
            "C:\\Windows\\System32\\wpcap.dll"
        };
        for (const char* p : paths) {
            lib_handle = reinterpret_cast<void*>(LoadLibraryA(p));
            if (lib_handle) break;
        }

        if (lib_handle) {
            HMODULE h = reinterpret_cast<HMODULE>(lib_handle);
            findalldevs = reinterpret_cast<fn_pcap_findalldevs>(GetProcAddress(h, "pcap_findalldevs"));
            freealldevs = reinterpret_cast<fn_pcap_freealldevs>(GetProcAddress(h, "pcap_freealldevs"));
            open_live = reinterpret_cast<fn_pcap_open_live>(GetProcAddress(h, "pcap_open_live"));
            create = reinterpret_cast<fn_pcap_create>(GetProcAddress(h, "pcap_create"));
            set_snaplen = reinterpret_cast<fn_pcap_set_snaplen>(GetProcAddress(h, "pcap_set_snaplen"));
            set_promisc = reinterpret_cast<fn_pcap_set_promisc>(GetProcAddress(h, "pcap_set_promisc"));
            set_timeout = reinterpret_cast<fn_pcap_set_timeout>(GetProcAddress(h, "pcap_set_timeout"));
            set_buffer_size = reinterpret_cast<fn_pcap_set_buffer_size>(GetProcAddress(h, "pcap_set_buffer_size"));
            set_immediate_mode = reinterpret_cast<fn_pcap_set_immediate_mode>(GetProcAddress(h, "pcap_set_immediate_mode"));
            activate = reinterpret_cast<fn_pcap_activate>(GetProcAddress(h, "pcap_activate"));
            next_ex = reinterpret_cast<fn_pcap_next_ex>(GetProcAddress(h, "pcap_next_ex"));
            close = reinterpret_cast<fn_pcap_close>(GetProcAddress(h, "pcap_close"));
            datalink = reinterpret_cast<fn_pcap_datalink>(GetProcAddress(h, "pcap_datalink"));
            stats = reinterpret_cast<fn_pcap_stats>(GetProcAddress(h, "pcap_stats"));
            loaded = (findalldevs && freealldevs && (open_live || create) && next_ex && close && datalink);
        }
#else
        const char* paths[] = {"libpcap.so.1", "libpcap.so"};
        for (const char* p : paths) {
            lib_handle = dlopen(p, RTLD_LAZY);
            if (lib_handle) break;
        }
        if (lib_handle) {
            findalldevs = reinterpret_cast<fn_pcap_findalldevs>(dlsym(lib_handle, "pcap_findalldevs"));
            freealldevs = reinterpret_cast<fn_pcap_freealldevs>(dlsym(lib_handle, "pcap_freealldevs"));
            open_live = reinterpret_cast<fn_pcap_open_live>(dlsym(lib_handle, "pcap_open_live"));
            create = reinterpret_cast<fn_pcap_create>(dlsym(lib_handle, "pcap_create"));
            set_snaplen = reinterpret_cast<fn_pcap_set_snaplen>(dlsym(lib_handle, "pcap_set_snaplen"));
            set_promisc = reinterpret_cast<fn_pcap_set_promisc>(dlsym(lib_handle, "pcap_set_promisc"));
            set_timeout = reinterpret_cast<fn_pcap_set_timeout>(dlsym(lib_handle, "pcap_set_timeout"));
            set_buffer_size = reinterpret_cast<fn_pcap_set_buffer_size>(dlsym(lib_handle, "pcap_set_buffer_size"));
            set_immediate_mode = reinterpret_cast<fn_pcap_set_immediate_mode>(dlsym(lib_handle, "pcap_set_immediate_mode"));
            activate = reinterpret_cast<fn_pcap_activate>(dlsym(lib_handle, "pcap_activate"));
            next_ex = reinterpret_cast<fn_pcap_next_ex>(dlsym(lib_handle, "pcap_next_ex"));
            close = reinterpret_cast<fn_pcap_close>(dlsym(lib_handle, "pcap_close"));
            datalink = reinterpret_cast<fn_pcap_datalink>(dlsym(lib_handle, "pcap_datalink"));
            stats = reinterpret_cast<fn_pcap_stats>(dlsym(lib_handle, "pcap_stats"));
            loaded = (findalldevs && freealldevs && (open_live || create) && next_ex && close && datalink);
        }
#endif
    }
};

PcapApi& getApi() {
    static PcapApi api;
    api.init();
    return api;
}

} // namespace

LiveCapture::LiveCapture() = default;

LiveCapture::~LiveCapture() {
    close();
}

bool LiveCapture::isAvailable() {
    return getApi().loaded;
}

std::vector<LiveDevice> LiveCapture::listDevices() {
    std::vector<LiveDevice> list;
    auto& api = getApi();
    if (!api.loaded || !api.findalldevs) return list;

    PcapIfItem* alldevs = nullptr;
    char errbuf[256] = {0};
    if (api.findalldevs(&alldevs, errbuf) == 0 && alldevs) {
        for (PcapIfItem* dev = alldevs; dev != nullptr; dev = dev->next) {
            LiveDevice d;
            d.name = dev->name ? dev->name : "";
            d.description = dev->description ? dev->description : "";
            if (!d.name.empty()) {
                list.push_back(std::move(d));
            }
        }
        api.freealldevs(alldevs);
    }
    return list;
}

std::string LiveCapture::getDefaultDevice() {
    auto devs = listDevices();
    if (devs.empty()) return "";

#if defined(_WIN32)
    // Query Windows routing table to find which interface reaches default gateway (8.8.8.8)
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

    DWORD best_if_index = 0;
    if (GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&dest), &best_if_index) == NO_ERROR) {
        ULONG out_buf_len = 15000;
        std::vector<uint8_t> buffer(out_buf_len);
        PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

        if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAddresses, &out_buf_len) == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(out_buf_len);
            pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        }

        if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAddresses, &out_buf_len) == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
                if (pCurr->IfIndex == best_if_index || pCurr->Ipv6IfIndex == best_if_index) {
                    std::string adapter_guid = pCurr->AdapterName ? pCurr->AdapterName : "";
                    if (!adapter_guid.empty()) {
                        for (const auto& dev : devs) {
                            if (dev.name.find(adapter_guid) != std::string::npos) {
                                std::cout << "[LiveCapture] Auto-selected default route adapter: "
                                          << dev.description << " (" << dev.name << ")\n";
                                return dev.name;
                            }
                        }
                    }
                }
            }
        }
    }
#endif

    // Fallback: search for active physical Ethernet or Wi-Fi adapters (skip virtual, WAN miniports, loopback)
    for (const auto& dev : devs) {
        std::string desc = dev.description;
        for (char& c : desc) c = static_cast<char>(std::tolower(c));
        std::string name = dev.name;
        for (char& c : name) c = static_cast<char>(std::tolower(c));

        if (desc.find("virtual") != std::string::npos ||
            desc.find("hyper-v") != std::string::npos ||
            desc.find("vethernet") != std::string::npos ||
            desc.find("virtualbox") != std::string::npos ||
            desc.find("vmware") != std::string::npos ||
            desc.find("wan miniport") != std::string::npos ||
            desc.find("loopback") != std::string::npos ||
            name.find("loopback") != std::string::npos) {
            continue;
        }

        if (desc.find("wi-fi") != std::string::npos ||
            desc.find("wireless") != std::string::npos ||
            desc.find("802.11") != std::string::npos ||
            desc.find("ethernet") != std::string::npos) {
            return dev.name;
        }
    }

    // Final fallback: first non-loopback device
    for (const auto& dev : devs) {
        if (dev.name.find("Loopback") == std::string::npos &&
            dev.description.find("Loopback") == std::string::npos) {
            return dev.name;
        }
    }

    return devs.front().name;
}

bool LiveCapture::open(const std::string& device_name) {
    close();
    is_eof_or_error_ = false;
    auto& api = getApi();
    if (!api.loaded || (!api.open_live && !api.create)) {
        last_error_ = "Npcap driver or libpcap library not available on system.";
        return false;
    }

    char errbuf[256] = {0};

    // Prefer pcap_create + 16 MB ring buffer + immediate mode to prevent kernel packet drops on gigabit bursts
    if (api.create && api.activate) {
        handle_ = api.create(device_name.c_str(), errbuf);
        if (handle_) {
            if (api.set_snaplen) api.set_snaplen(handle_, 65535);
            if (api.set_promisc) api.set_promisc(handle_, 1);
            if (api.set_timeout) api.set_timeout(handle_, 100);
            if (api.set_buffer_size) api.set_buffer_size(handle_, 16 * 1024 * 1024); // 16 MB ring buffer
            if (api.set_immediate_mode) api.set_immediate_mode(handle_, 1);
            if (api.activate(handle_) < 0) {
                if (api.close) api.close(handle_);
                handle_ = nullptr;
            }
        }
    }

    if (!handle_ && api.open_live) {
        // Fallback to pcap_open_live
        handle_ = api.open_live(device_name.c_str(), 65535, 1, 100, errbuf);
    }

    if (!handle_) {
        last_error_ = std::string("Failed to open capture device: ") + errbuf;
        return false;
    }

    if (api.datalink) {
        link_type_ = api.datalink(handle_);
    } else {
        link_type_ = 1; // DLT_EN10MB
    }
    return true;
}

bool LiveCapture::readNextPacket(PacketAnalyzer::RawPacket& raw) {
    if (!handle_) return false;
    auto& api = getApi();
    if (!api.next_ex) return false;

    PcapPkthdr* hdr = nullptr;
    const uint8_t* data = nullptr;

    int res = api.next_ex(handle_, &hdr, &data);
    if (res == 1 && hdr && data) {
        raw.header.ts_sec = static_cast<uint32_t>(hdr->ts.tv_sec);
        raw.header.ts_usec = static_cast<uint32_t>(hdr->ts.tv_usec);
        raw.header.incl_len = hdr->caplen;
        raw.header.orig_len = hdr->len;
        raw.link_type = link_type_;
        raw.data.assign(data, data + hdr->caplen);
        return true;
    } else if (res == 0) {
        // Read timeout (no packet arrived within timeout_ms)
        return false;
    } else {
        // res == -1 (pcap error) or res == -2 (EOF/breakloop)
        is_eof_or_error_ = true;
        last_error_ = (res == -2) ? "Capture loop terminated (EOF)" : "pcap_next_ex returned an error";
        return false;
    }
}

CaptureStats LiveCapture::getStats() {
    CaptureStats cs{};
    if (!handle_) return cs;
    auto& api = getApi();
    if (api.stats) {
        PcapStat ps{};
        if (api.stats(handle_, &ps) == 0) {
            cs.received = ps.ps_recv;
            cs.dropped = ps.ps_drop;
        }
    }
    return cs;
}

void LiveCapture::close() {
    if (handle_) {
        auto& api = getApi();
        if (api.close) {
            api.close(handle_);
        }
        handle_ = nullptr;
    }
}

} // namespace DPI
