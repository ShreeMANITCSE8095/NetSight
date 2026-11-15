/**
 * @file tls_extractor.cpp
 * @brief Parses a TLS ClientHello into a JA3 string and the SNI.
 *
 * All reads go through a bounds-checked cursor. The previous version indexed
 * the buffer directly and read one byte past the end when the cipher-suite
 * length was odd (found with AddressSanitizer).
 */

#include "tls_extractor.h"
#include "platform.h"
#include <algorithm>
#include <cstring>

namespace DPI {

namespace {

using PortableNet::readBE16;

inline bool isGrease(uint16_t v) { return (v & 0x0F0F) == 0x0A0A; }

// Forward-only cursor. Once a read fails, ok stays false and later reads are no-ops.
struct Cursor {
    const uint8_t* p;
    size_t n;
    size_t off = 0;
    bool ok = true;

    Cursor(const uint8_t* data, size_t len) : p(data), n(len) {}

    size_t remaining() const { return n - off; }
    bool has(size_t k) const { return ok && n - off >= k; }

    uint8_t u8() {
        if (!has(1)) { ok = false; return 0; }
        return p[off++];
    }
    uint16_t u16() {
        if (!has(2)) { ok = false; return 0; }
        const uint16_t v = readBE16(p + off);
        off += 2;
        return v;
    }
    uint32_t u24() {
        if (!has(3)) { ok = false; return 0; }
        const uint32_t v = (static_cast<uint32_t>(p[off]) << 16) | readBE16(p + off + 1);
        off += 3;
        return v;
    }
    const uint8_t* take(size_t k) {
        if (!has(k)) { ok = false; return nullptr; }
        const uint8_t* r = p + off;
        off += k;
        return r;
    }
};

void appendList(std::string& out, const std::vector<uint32_t>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += '-';
        out += std::to_string(v[i]);
    }
}

} // namespace

bool TLSExtractor::looksLikeClientHelloStart(const uint8_t* payload, size_t length) {
    if (length >= 1 && payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    if (length >= 2 && payload[1] != 0x03) return false;       // record version 3.x
    if (length >= 3 && payload[2] > 0x04) return false;
    if (length >= 6 && payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    return length >= 1;
}

size_t TLSExtractor::expectedRecordSize(const uint8_t* payload, size_t length) {
    if (length < 5) return 0;
    return 5 + static_cast<size_t>(readBE16(payload + 3));
}

bool TLSExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (length < 47) return false;
    return payload[0] == CONTENT_TYPE_HANDSHAKE && payload[5] == HANDSHAKE_CLIENT_HELLO;
}

std::optional<TLSMetadata> TLSExtractor::extract(const uint8_t* payload, size_t length) {
    if (!payload || !isTLSClientHello(payload, length)) return std::nullopt;

    Cursor c(payload, length);
    if (c.remaining() < 5) return std::nullopt;
    c.take(5);                         // record header: type, version, length
    if (c.remaining() < 1) return std::nullopt;
    c.u8();                            // handshake type (checked above)
    if (c.remaining() < 3) return std::nullopt;
    c.u24();                           // handshake length
    if (c.remaining() < 2) return std::nullopt;
    const uint16_t client_version = c.u16();
    if (c.remaining() < 32) return std::nullopt;
    c.take(32);                        // random
    if (c.remaining() < 1) return std::nullopt;
    const uint8_t session_len = c.u8();
    if (c.remaining() < session_len) return std::nullopt;
    c.take(session_len);

    if (c.remaining() < 2) return std::nullopt;
    const uint16_t cipher_len = c.u16();
    if (!c.ok || cipher_len == 0 || (cipher_len & 1) || c.remaining() < cipher_len) return std::nullopt;
    const uint8_t* ciphers = c.take(cipher_len);
    if (!c.ok || !ciphers) return std::nullopt;

    if (c.remaining() < 1) return std::nullopt;
    const uint8_t comp_len = c.u8();
    if (c.remaining() < comp_len) return std::nullopt;
    c.take(comp_len);
    if (!c.ok) return std::nullopt;

    std::vector<uint32_t> cipher_list, ext_list, curve_list, pf_list;
    for (size_t i = 0; i + 1 < cipher_len; i += 2) {
        const uint16_t cs = readBE16(ciphers + i);
        if (!isGrease(cs)) cipher_list.push_back(cs);
    }

    TLSMetadata meta;

    if (c.remaining() >= 2) {          // extensions are optional
        const uint16_t ext_total = c.u16();
        if (c.remaining() < ext_total) return std::nullopt;

        Cursor e(payload + c.off, ext_total);
        while (e.remaining() >= 4) {
            const uint16_t type = e.u16();
            const uint16_t dlen = e.u16();
            if (e.remaining() < dlen) break;
            const uint8_t* dptr = e.take(dlen);
            if (!dptr) break;
            Cursor d(dptr, dlen);

            if (!isGrease(type)) ext_list.push_back(type);

            if (type == 0x0000) {                       // server_name
                if (d.remaining() < 2) break;
                d.u16();                                // list length
                if (d.remaining() < 3) break;
                const uint8_t name_type = d.u8();
                const uint16_t name_len = d.u16();
                if (d.remaining() < name_len) break;
                const uint8_t* name = d.take(name_len);
                if (d.ok && name && name_type == 0 && name_len > 0 && name_len <= 255) {
                    std::string s(reinterpret_cast<const char*>(name), name_len);
                    std::transform(s.begin(), s.end(), s.begin(),
                                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    while (!s.empty() && s.back() == '.') s.pop_back();
                    meta.sni = std::move(s);
                }
            } else if (type == 0x000a) {                // supported groups
                if (d.remaining() < 2) break;
                const uint16_t list_len = d.u16();
                const size_t usable = std::min<size_t>(list_len, d.remaining()) & ~static_cast<size_t>(1);
                for (size_t i = 0; i < usable && d.remaining() >= 2; i += 2) {
                    const uint16_t g = d.u16();
                    if (!isGrease(g)) curve_list.push_back(g);
                }
            } else if (type == 0x000b) {                // EC point formats
                if (d.remaining() < 1) break;
                const uint8_t list_len = d.u8();
                const size_t usable = std::min<size_t>(list_len, d.remaining());
                for (size_t i = 0; i < usable && d.remaining() >= 1; ++i) pf_list.push_back(d.u8());
            }
        }
    }

    std::string ja3 = std::to_string(client_version) + ",";
    appendList(ja3, cipher_list); ja3 += ',';
    appendList(ja3, ext_list);    ja3 += ',';
    appendList(ja3, curve_list);  ja3 += ',';
    appendList(ja3, pf_list);
    meta.ja3_fingerprint = std::move(ja3);
    return meta;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!payload || length < 16) return std::nullopt;

    const std::string data(reinterpret_cast<const char*>(payload), std::min(length, static_cast<size_t>(1024)));

    if (data.compare(0, 4, "GET ") != 0 &&
        data.compare(0, 5, "POST ") != 0 &&
        data.compare(0, 5, "HEAD ") != 0) {
        return std::nullopt;
    }

    size_t host_pos = data.find("\r\nHost: ");
    if (host_pos == std::string::npos) host_pos = data.find("\r\nhost: ");
    if (host_pos == std::string::npos) return std::nullopt;

    host_pos += 8;  // skip "\r\nHost: "
    const size_t end_pos = data.find("\r\n", host_pos);
    if (end_pos == std::string::npos) return std::nullopt;
    std::string host = data.substr(host_pos, end_pos - host_pos);
    while (!host.empty() && (host.back() == ' ' || host.back() == '\t')) host.pop_back();
    size_t colon = host.find(':');
    if (colon != std::string::npos) {
        host = host.substr(0, colon);
    }
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    while (!host.empty() && host.back() == '.') host.pop_back();
    return host.empty() ? std::nullopt : std::make_optional(host);
}

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (!payload || length < 16) return false;
    return (std::memcmp(payload, "GET ", 4) == 0 ||
            std::memcmp(payload, "POST ", 5) == 0 ||
            std::memcmp(payload, "HEAD ", 5) == 0);
}

} // namespace DPI
