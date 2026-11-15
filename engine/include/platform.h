#ifndef NETSIGHT_PLATFORM_H
#define NETSIGHT_PLATFORM_H

#include <cstdint>
#include <ctime>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef DOMAIN
#undef DOMAIN
#endif
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
constexpr socket_t INVALID_SOCKET_FD = INVALID_SOCKET;
constexpr int SOCKET_ERR = SOCKET_ERROR;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
using socket_t = int;
constexpr socket_t INVALID_SOCKET_FD = -1;
constexpr int SOCKET_ERR = -1;
#endif

namespace PortableNet {

// Explicit byte readers: work on any endianness, never require aligned pointers.
inline uint16_t readBE16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t readBE24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
           static_cast<uint32_t>(p[2]);
}

inline uint32_t readBE32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline uint16_t swap16(uint16_t v) {
    return static_cast<uint16_t>((v >> 8) | (v << 8));
}

inline uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
}

inline uint32_t ntohl(uint32_t v) {
    return ::ntohl(v);
}

// Thread-safe UTC broken-down time.
inline bool utcTime(std::time_t t, std::tm& out) {
#if defined(_WIN32)
    return gmtime_s(&out, &t) == 0;
#else
    return gmtime_r(&t, &out) != nullptr;
#endif
}

// Socket subsystem initialization and cleanup
inline bool initSockets() {
#if defined(_WIN32)
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return true;
#endif
}

inline void cleanupSockets() {
#if defined(_WIN32)
    WSACleanup();
#endif
}

inline void closeSocket(socket_t sock) {
    if (sock != INVALID_SOCKET_FD) {
#if defined(_WIN32)
        closesocket(sock);
#else
        close(sock);
#endif
    }
}

} // namespace PortableNet

#endif // NETSIGHT_PLATFORM_H
