#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace DPI {

struct DNSFeatures {
    std::string domain;
    double entropy = 0.0;
    uint16_t record_type = 0;
};

struct DNSAnswer {
    std::string ip;
    uint32_t ip_num = 0; // Host-byte order IPv4
    uint16_t type = 0;   // 1 = A
    uint32_t ttl = 0;
};

struct DNSResponseFeatures {
    std::string query_domain;
    uint8_t rcode = 0;       // 0 = NoError, 3 = NXDOMAIN
    bool is_nxdomain = false;
    std::vector<DNSAnswer> answers;
};

class DNSExtractor {
public:
    // First question of a standard DNS query. Returns nullopt for responses,
    // non-QUERY opcodes, or malformed packets.
    static std::optional<DNSFeatures> extractQuery(const uint8_t* payload, size_t length);
    static bool isDNSQuery(const uint8_t* payload, size_t length);

    // DNS response inspection (QR = 1). Extracts answers (A records) and NXDOMAIN.
    static bool isDNSResponse(const uint8_t* payload, size_t length);
    static std::optional<DNSResponseFeatures> extractResponse(const uint8_t* payload, size_t length);

    static double calculateShannonEntropy(const std::string& str);
    static double calculateDomainEntropy(const std::string& fqdn);
    static std::string extractRegistrableLabel(const std::string& fqdn);
};

} // namespace DPI

#endif // DNS_PARSER_H
