/**
 * @file dns_parser.cpp
 * @brief Extracts queried names, answers, and entropy from DNS queries and responses.
 */

#include "dns_parser.h"
#include "platform.h"
#include <cmath>
#include <cctype>
#include <algorithm>
#include <sstream>

namespace DPI {

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    if (!payload || length < 12) return false;
    if (payload[2] & 0x80) return false;               // QR = 1 is a response
    if (((payload[2] >> 3) & 0x0F) != 0) return false; // opcode must be QUERY
    return true;
}

bool DNSExtractor::isDNSResponse(const uint8_t* payload, size_t length) {
    if (!payload || length < 12) return false;
    if ((payload[2] & 0x80) == 0) return false;        // QR = 0 is a query
    if (((payload[2] >> 3) & 0x0F) != 0) return false; // opcode must be QUERY
    return true;
}

double DNSExtractor::calculateShannonEntropy(const std::string& str) {
    if (str.empty()) return 0.0;

    uint32_t freq[256] = {0};
    for (unsigned char c : str) freq[c]++;

    const double len = static_cast<double>(str.size());
    double entropy = 0.0;
    for (uint32_t count : freq) {
        if (!count) continue;
        const double p = count / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// Reads a wire-format DNS name, following compression pointers safely up to 16 jumps.
// Names are automatically converted to lowercase.
static bool readWireName(const uint8_t* payload, size_t length, size_t& offset, std::string& out_name) {
    size_t curr = offset;
    bool jumped = false;
    size_t wire_len = 0;
    int jumps = 0;
    constexpr int MAX_JUMPS = 16;
    size_t last_ptr = length;

    while (curr < length) {
        const uint8_t len = payload[curr];
        if (len == 0) {
            if (!jumped) offset = curr + 1;
            return true;
        }
        if ((len & 0xC0) == 0xC0) { // Compression pointer
            if (curr + 1 >= length) return false;
            const uint16_t ptr = (static_cast<uint16_t>(len & 0x3F) << 8) | payload[curr + 1];
            if (++jumps > MAX_JUMPS) return false; // Max 16 jumps
            // Every pointer jump must strictly point backwards to a prior offset and stay within bounds
            if (ptr >= length || ptr >= curr || ptr >= last_ptr) return false;
            last_ptr = ptr;
            if (!jumped) {
                offset = curr + 2;
                jumped = true;
            }
            curr = ptr;
        } else if ((len & 0xC0) == 0) { // Plain label
            curr++;
            if (curr + len > length) return false;
            wire_len += static_cast<size_t>(len) + 1;
            if (wire_len > 255) return false;
            if (!out_name.empty()) out_name += '.';
            for (size_t i = 0; i < len; ++i) {
                out_name += static_cast<char>(std::tolower(payload[curr + i]));
            }
            curr += len;
            if (!jumped) offset = curr;
        } else {
            return false;
        }
    }
    return false;
}

std::string DNSExtractor::extractRegistrableLabel(const std::string& fqdn) {
    if (fqdn.empty()) return "";

    std::vector<std::string> labels;
    size_t start = 0;
    while (start < fqdn.size()) {
        size_t dot = fqdn.find('.', start);
        if (dot == std::string::npos) {
            labels.push_back(fqdn.substr(start));
            break;
        }
        if (dot > start) {
            labels.push_back(fqdn.substr(start, dot - start));
        }
        start = dot + 1;
    }

    if (labels.empty()) return "";
    if (labels.size() == 1) return labels[0];

    // Check for common two-part TLDs (e.g. co.uk, com.au, co.in)
    static const char* kTwoPartTlds[] = {
        "co", "com", "org", "net", "gov", "edu", "ac"
    };
    bool two_part = false;
    if (labels.size() >= 3) {
        const std::string& second_last = labels[labels.size() - 2];
        for (const char* tld : kTwoPartTlds) {
            if (second_last == tld) {
                two_part = true;
                break;
            }
        }
    }

    if (two_part && labels.size() >= 3) {
        return labels[labels.size() - 3];
    }
    return labels[labels.size() - 2];
}

double DNSExtractor::calculateDomainEntropy(const std::string& fqdn) {
    std::string label = extractRegistrableLabel(fqdn);
    // E14: Minimum length 8 required to avoid false positives on short words
    if (label.size() < 8) return 0.0;
    return calculateShannonEntropy(label);
}

std::optional<DNSFeatures> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) return std::nullopt;

    const uint16_t qdcount = PortableNet::readBE16(payload + 4);
    if (qdcount == 0) return std::nullopt;

    size_t offset = 12;
    std::string domain;
    if (!readWireName(payload, length, offset, domain)) {
        return std::nullopt;
    }

    if (domain.empty()) return std::nullopt;

    DNSFeatures features;
    features.domain = std::move(domain);
    // Use domain entropy on registrable label with minimum-length guard
    features.entropy = calculateDomainEntropy(features.domain);
    if (length - offset >= 2) {
        features.record_type = PortableNet::readBE16(payload + offset);
    }
    return features;
}

std::optional<DNSResponseFeatures> DNSExtractor::extractResponse(const uint8_t* payload, size_t length) {
    if (!isDNSResponse(payload, length)) return std::nullopt;

    DNSResponseFeatures res;
    res.rcode = payload[3] & 0x0F;
    res.is_nxdomain = (res.rcode == 3);

    const uint16_t qdcount = PortableNet::readBE16(payload + 4);
    const uint16_t ancount = PortableNet::readBE16(payload + 6);

    // SEC-10: Defensive bounds check to prevent CPU exhaustion on malformed/spoofed packets
    if (qdcount > 10) return std::nullopt;
    const uint16_t max_ancount = std::min<uint16_t>(ancount, 100);

    size_t offset = 12;

    // Skip/read question section
    for (uint16_t q = 0; q < qdcount; ++q) {
        std::string qname;
        if (!readWireName(payload, length, offset, qname)) return std::nullopt;
        if (res.query_domain.empty()) res.query_domain = std::move(qname);
        if (offset + 4 > length) return std::nullopt;
        offset += 4; // Skip QTYPE (2) + QCLASS (2)
    }

    // Parse answer section
    for (uint16_t a = 0; a < max_ancount && offset < length; ++a) {
        std::string name;
        if (!readWireName(payload, length, offset, name)) break;
        if (offset + 10 > length) break;

        uint16_t type = PortableNet::readBE16(payload + offset);
        uint16_t rclass = PortableNet::readBE16(payload + offset + 2);
        (void)rclass;
        uint32_t ttl = (static_cast<uint32_t>(PortableNet::readBE16(payload + offset + 4)) << 16) |
                        static_cast<uint32_t>(PortableNet::readBE16(payload + offset + 6));
        uint16_t rdlength = PortableNet::readBE16(payload + offset + 8);
        offset += 10;

        if (offset + rdlength > length) break;

        if (type == 1 && rdlength == 4) { // A Record (IPv4)
            DNSAnswer ans;
            ans.type = 1;
            ans.ttl = ttl;
            uint32_t b0 = payload[offset];
            uint32_t b1 = payload[offset + 1];
            uint32_t b2 = payload[offset + 2];
            uint32_t b3 = payload[offset + 3];
            ans.ip = std::to_string(b0) + "." + std::to_string(b1) + "." +
                     std::to_string(b2) + "." + std::to_string(b3);
            ans.ip_num = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
            res.answers.push_back(std::move(ans));
        }

        offset += rdlength;
    }

    return res;
}

} // namespace DPI
