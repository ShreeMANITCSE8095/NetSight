#ifndef NETSIGHT_TCP_SERVER_H
#define NETSIGHT_TCP_SERVER_H

#include "platform.h"
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>

namespace DPI {

class TcpServer {
public:
    TcpServer(const std::string& host = "127.0.0.1", uint16_t port = 9999);
    ~TcpServer();

    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    bool start();
    void stop();

    // Broadcast a JSON line (automatically appends '\n' if missing)
    void broadcast(const std::string& line);

    bool hasClients() const;
    size_t clientCount() const;

private:
    void acceptLoop();
    void sendLoop();
    void sendToClients(const std::string& msg);

    std::string host_;
    uint16_t port_;
    socket_t listen_sock_ = INVALID_SOCKET_FD;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::thread send_thread_;

    std::deque<std::string> queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    static constexpr size_t kMaxQueueSize = 10000;

    mutable std::mutex clients_mutex_;
    std::vector<socket_t> clients_;
};

} // namespace DPI

#endif // NETSIGHT_TCP_SERVER_H

