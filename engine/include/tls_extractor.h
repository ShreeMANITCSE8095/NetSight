#ifndef TLS_EXTRACTOR_H
#define TLS_EXTRACTOR_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace DPI {

struct TLSMetadata {
    std::optional<std::string> sni;
    std::string ja3_fingerprint;
};

class TLSExtractor {
public:
    // Parse a complete ClientHello record. Every read is bounds-checked.
    static std::optional<TLSMetadata> extract(const uint8_t* payload, size_t length);

    // Full structural check (needs at least 47 bytes).
    static bool isTLSClientHello(const uint8_t* payload, size_t length);

    // Prefix check that works on a partial first segment: could these bytes be
    // the start of a TLS handshake ClientHello record? Checks as many of the
    // first 6 bytes as are present.
    static bool looksLikeClientHelloStart(const uint8_t* payload, size_t length);

    // Total size (5-byte record header + record body) announced by the record
    // header, or 0 when fewer than 5 bytes are available.
    static size_t expectedRecordSize(const uint8_t* payload, size_t length);

    // A ClientHello never needs more than one maximum-size TLS record.
    static constexpr size_t kMaxRecordSize = 5 + 16384;

private:
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
};

class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

} // namespace DPI

#endif // TLS_EXTRACTOR_H
