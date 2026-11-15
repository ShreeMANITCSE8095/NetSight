#include "tcp_server.h"
#include <iostream>
#include <algorithm>

namespace DPI {

TcpServer::TcpServer(const std::string& host, uint16_t port)
    : host_(host), port_(port) {
    PortableNet::initSockets();
}

TcpServer::~TcpServer() {
    stop();
    PortableNet::cleanupSockets();
}

bool TcpServer::start() {
    if (running_) return true;

    listen_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_ == INVALID_SOCKET_FD) {
        std::cerr << "[TcpServer] Failed to create socket\n";
        return false;
    }

    // Set SO_REUSEADDR
    int opt = 1;
#if defined(_WIN32)
    setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_);
    inet_pton(AF_INET, host_.c_str(), &server_addr.sin_addr);

    if (bind(listen_sock_, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERR) {
        std::cerr << "[TcpServer] Bind failed on " << host_ << ":" << port_ << "\n";
        PortableNet::closeSocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET_FD;
        return false;
    }

    if (listen(listen_sock_, 10) == SOCKET_ERR) {
        std::cerr << "[TcpServer] Listen failed\n";
        PortableNet::closeSocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET_FD;
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&TcpServer::acceptLoop, this);
    send_thread_ = std::thread(&TcpServer::sendLoop, this);
    std::cout << "[TcpServer] Streaming NDJSON on " << host_ << ":" << port_ << "\n";
    return true;
}

void TcpServer::stop() {
    if (!running_.exchange(false)) return;

    queue_cv_.notify_all();

    if (listen_sock_ != INVALID_SOCKET_FD) {
#if defined(_WIN32)
        shutdown(listen_sock_, SD_BOTH);
#else
        shutdown(listen_sock_, SHUT_RDWR);
#endif
        PortableNet::closeSocket(listen_sock_);
        listen_sock_ = INVALID_SOCKET_FD;
    }

    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    if (send_thread_.joinable()) {
        send_thread_.join();
    }

    std::lock_guard<std::mutex> lock(clients_mutex_);
    for (socket_t client : clients_) {
#if defined(_WIN32)
        shutdown(client, SD_BOTH);
#else
        shutdown(client, SHUT_RDWR);
#endif
        PortableNet::closeSocket(client);
    }
    clients_.clear();
}

void TcpServer::acceptLoop() {
    while (running_) {
        if (listen_sock_ == INVALID_SOCKET_FD) break;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock_, &read_fds);

        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100 ms poll

#if defined(_WIN32)
        int sel = select(0, &read_fds, nullptr, nullptr, &tv);
#else
        int sel = select(listen_sock_ + 1, &read_fds, nullptr, nullptr, &tv);
#endif

        if (sel <= 0 || !running_) {
            continue;
        }

        sockaddr_in client_addr{};
#if defined(_WIN32)
        int addr_len = sizeof(client_addr);
#else
        socklen_t addr_len = sizeof(client_addr);
#endif
        socket_t client_sock = accept(listen_sock_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_sock == INVALID_SOCKET_FD) {
            if (!running_) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        std::cout << "[TcpServer] Collector connected from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

        // Set send timeout (50 ms) to prevent slow-read clients from blocking capture threads
#if defined(_WIN32)
        DWORD timeout_ms = 50;
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        int nodelay = 1;
        setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
#else
        struct timeval tv_snd{0, 50000}; // 50 ms
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv_snd, sizeof(tv_snd));
        int nodelay = 1;
        setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#if defined(SO_NOSIGPIPE)
        int nosig = 1;
        setsockopt(client_sock, SOL_SOCKET, SO_NOSIGPIPE, &nosig, sizeof(nosig));
#endif
#endif

        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.push_back(client_sock);
    }
}

void TcpServer::broadcast(const std::string& line) {
    if (!hasClients()) return;
    std::string msg = line;
    if (msg.empty() || msg.back() != '\n') {
        msg.push_back('\n');
    }

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (queue_.size() >= kMaxQueueSize) {
            queue_.pop_front(); // drop oldest to protect capture threads from slow consumers
        }
        queue_.push_back(std::move(msg));
    }
    queue_cv_.notify_one();
}

void TcpServer::sendLoop() {
    while (running_) {
        std::string msg;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
                return !running_ || !queue_.empty();
            });
            if (!running_) break;
            if (queue_.empty()) continue;
            msg = std::move(queue_.front());
            queue_.pop_front();
        }
        sendToClients(msg);
    }
}

void TcpServer::sendToClients(const std::string& msg) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    if (clients_.empty()) return;

    std::vector<socket_t> active_clients;
    for (socket_t sock : clients_) {
        const char* ptr = msg.data();
        size_t remaining = msg.size();
        bool send_ok = true;

        while (remaining > 0) {
#if defined(_WIN32)
            int sent = send(sock, ptr, static_cast<int>(remaining), 0);
#else
            ssize_t sent = send(sock, ptr, remaining, MSG_NOSIGNAL);
#endif
            if (sent <= 0) {
                send_ok = false;
                break;
            }
            ptr += sent;
            remaining -= static_cast<size_t>(sent);
        }

        if (send_ok) {
            active_clients.push_back(sock);
        } else {
            PortableNet::closeSocket(sock);
        }
    }
    clients_ = std::move(active_clients);
}

bool TcpServer::hasClients() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    return !clients_.empty();
}

size_t TcpServer::clientCount() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    return clients_.size();
}

} // namespace DPI

