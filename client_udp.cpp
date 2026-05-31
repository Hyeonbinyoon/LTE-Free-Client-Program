#include "client.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <mutex>

#define CLIENT_UDP_REGISTER_PREFIX "CUSTOMVPN_CLIENT_UDP_REGISTER_2024350225:"
#define PROXY_UDP_REGISTER_ACK_PREFIX "CUSTOMVPN_PROXY_UDP_REGISTER_ACK_2024350225:"
#define PROXY_LEARN_READY_PREFIX "CUSTOMVPN_PROXY_LEARN_READY_2024350225:"
#define CLIENT_TUNNEL_READY_PREFIX "CUSTOMVPN_CLIENT_TUNNEL_READY_2024350225:"
#define PROXY_TUNNEL_READY_ACK_PREFIX "CUSTOMVPN_PROXY_TUNNEL_READY_ACK_2024350225:"
#define CLIENT_START_ACK_PREFIX "CUSTOMVPN_CLIENT_START_ACK_2024350225:"
#define UDP_STOP_PREFIX "CUSTOMVPN_UDP_STOP_2024350225:"

#define UDP_RETRY_INTERVAL_MS 500
#define UDP_TIMEOUT_SECONDS 20
#define UDP_STOP_REPEAT_COUNT 5
#define UDP_STOP_INTERVAL_MS 100
#define UDP_BUFFER_SIZE 512


static std::string make_client_nonce() 
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    std::ostringstream oss;
    oss << "client_" << getpid() << "_" << ts.tv_sec << "_" << ts.tv_nsec;

    return oss.str();
}

static bool make_proxy_addr(const char* proxy_ip, uint16_t ready_port, sockaddr_in& addr)
{
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ready_port);

    if(inet_pton(AF_INET, proxy_ip, &addr.sin_addr) != 1)
    {
        std::fprintf(stderr, "invalid proxy ip for UDP: %s\n", proxy_ip);
        return false;
    }

    return true;
}


// UDP marker 송신
static bool udp_send_string(int udp_fd, const sockaddr_in& addr, const std::string& msg)
{
    ssize_t n = sendto(udp_fd, msg.data(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    if(n < 0)
    {
        perror("sendto UDP");
        return false;
    }

    if(static_cast<size_t>(n) != msg.size())
    {
        std::fprintf(stderr, "partial UDP send\n");
        return false;
    }

    return true;
}


// timeout 기반 UDP marker 수신
static bool udp_recv_string(int udp_fd, std::string& msg, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udp_fd, &rfds);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(udp_fd + 1, &rfds, nullptr, nullptr, &tv);
    if(ret == 0)
        return false;

    if(ret < 0)
    {
        if(errno == EINTR)
            return false;

        perror("select UDP");
        return false;
    }

    char buf[UDP_BUFFER_SIZE];
    ssize_t n = recvfrom(udp_fd, buf, sizeof(buf) - 1, 0, nullptr, nullptr);
    if(n < 0)
    {
        if(errno == EINTR)
            return false;

        perror("recvfrom UDP");
        return false;
    }

    buf[n] = '\0';
    msg.assign(buf, static_cast<size_t>(n));

    return true;
}


// marker prefix 확인
static bool starts_with(const std::string& s, const char* prefix)
{
    size_t prefix_len = std::strlen(prefix);

    if(s.size() < prefix_len)
        return false;

    return s.compare(0, prefix_len, prefix) == 0;
}


// UDP_TIMEOUT_SECONDS 계산
static uint64_t now_ms()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}

static bool is_valid_udp_stop(const std::string& msg, const ClientReadyState& state)
{
    std::string client_nonce;
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
    }

    if(client_nonce.empty() || proxy_nonce.empty())
        return false;

    std::string expected = std::string(UDP_STOP_PREFIX) + client_nonce + ":" + proxy_nonce;

    return msg == expected;
}

static bool is_valid_proxy_learn_ready(const std::string& msg, const ClientReadyState& state)
{
    if(!starts_with(msg, PROXY_LEARN_READY_PREFIX))
        return false;

    std::string client_nonce;
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
    }

    if(client_nonce.empty() || proxy_nonce.empty())
        return false;

    std::string body = msg.substr(std::strlen(PROXY_LEARN_READY_PREFIX));
    std::string expected_body = client_nonce + ":" + proxy_nonce;

    return body == expected_body;
}

static bool is_valid_proxy_ready_ack(const std::string& msg, const ClientReadyState& state)
{
    if(!starts_with(msg, PROXY_TUNNEL_READY_ACK_PREFIX))
        return false;

    std::string client_nonce;
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
    }

    if(client_nonce.empty() || proxy_nonce.empty())
        return false;

    std::string body = msg.substr(std::strlen(PROXY_TUNNEL_READY_ACK_PREFIX));
    std::string expected_body = client_nonce + ":" + proxy_nonce;

    return body == expected_body;
}


// Client UDP endpoint를 Proxy에 등록하고, Proxy nonce를 획득
bool run_client_udp_register(int udp_fd, const char* proxy_ip, uint16_t ready_port, ClientReadyState& state, std::atomic<bool>& stop)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP REGISTER] invalid udp fd\n");
        return false;
    }

    sockaddr_in proxy_addr;
    if(!make_proxy_addr(proxy_ip, ready_port, proxy_addr))
        return false;

    if(state.client_nonce.empty())
        state.client_nonce = make_client_nonce();

    std::string register_msg =
        std::string(CLIENT_UDP_REGISTER_PREFIX) + state.client_nonce;

    uint64_t start_time = now_ms();
    uint64_t next_send_time = 0;

    std::printf("[UDP REGISTER] start\n");
    std::printf("[UDP REGISTER] client_nonce=%s\n",
                state.client_nonce.c_str());

    while(!g_signal_stop && !stop.load())
    {
        uint64_t current_time = now_ms();

        if(current_time - start_time >= UDP_TIMEOUT_SECONDS * 1000ULL)
        {
            std::fprintf(stderr, "[UDP REGISTER] timeout\n");
            return false;
        }

        if(current_time >= next_send_time)
        {
            if(!udp_send_string(udp_fd, proxy_addr, register_msg))
                return false;

            std::printf("[UDP REGISTER] sent CLIENT_REGISTER\n");

            next_send_time = current_time + UDP_RETRY_INTERVAL_MS;
        }

        std::string recv_msg;
        if(!udp_recv_string(udp_fd, recv_msg, UDP_RETRY_INTERVAL_MS))
            continue;

        if(!starts_with(recv_msg, PROXY_UDP_REGISTER_ACK_PREFIX))
        {
            std::printf("[UDP REGISTER] ignore unexpected UDP message: %s\n", recv_msg.c_str());
            continue;
        }

        std::string body = recv_msg.substr(std::strlen(PROXY_UDP_REGISTER_ACK_PREFIX));

        std::string expected_prefix = state.client_nonce + ":";
        if(!starts_with(body, expected_prefix.c_str()))
        {
            std::printf("[UDP REGISTER] ignore ACK with wrong client nonce: %s\n", recv_msg.c_str());
            continue;
        }

        std::string proxy_nonce = body.substr(expected_prefix.size());
        if(proxy_nonce.empty())
        {
            std::printf("[UDP REGISTER] ignore ACK with empty proxy nonce\n");
            continue;
        }

        state.proxy_nonce = proxy_nonce;
        state.registered = true;

        std::printf("[UDP REGISTER] done\n");
        std::printf("[UDP REGISTER] proxy_nonce=%s\n", state.proxy_nonce.c_str());

        return true;
    }

    return false;
}

bool wait_for_proxy_learn_ready(ClientReadyState& state, std::atomic<bool>& stop)
{
    std::printf("[UDP LEARN] waiting for PROXY_LEARN_READY\n");

    while(!g_signal_stop && !stop.load())
    {
        bool proxy_learn_ready_received = false;
        bool stop_received = false;

        {
            std::lock_guard<std::mutex> guard(state.lock);
            proxy_learn_ready_received = state.proxy_learn_ready_received;
            stop_received = state.stop_received;
        }

        if(stop_received)
        {
            std::fprintf(stderr, "[UDP LEARN] stop received while waiting PROXY_LEARN_READY\n");
            return false;
        }

        if(proxy_learn_ready_received)
        {
            std::printf("[UDP LEARN] PROXY_LEARN_READY received\n");
            return true;
        }

        usleep(10 * 1000);
    }

    return false;
}

// 양쪽 tunnel NFQUEUE가 준비됐는지 확인하고, data plane 시작 OK 맞춤
bool run_client_ready_handshake(int udp_fd, const char* proxy_ip, uint16_t ready_port, ClientReadyState& state, std::atomic<bool>& stop)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP READY] invalid udp fd\n");
        return false;
    }

    std::string client_nonce;
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);

        if(!state.registered || state.client_nonce.empty() || state.proxy_nonce.empty())
        {
            std::fprintf(stderr, "[UDP READY] UDP register is not completed\n");
            return false;
        }

        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
    }

    sockaddr_in proxy_addr;
    if(!make_proxy_addr(proxy_ip, ready_port, proxy_addr))
        return false;

    std::string ready_msg = std::string(CLIENT_TUNNEL_READY_PREFIX) + client_nonce;
    std::string start_ack_msg = std::string(CLIENT_START_ACK_PREFIX) + proxy_nonce;

    uint64_t start_time = now_ms();
    uint64_t next_send_time = 0;

    std::printf("[UDP READY] start\n");

    while(!g_signal_stop && !stop.load())
    {
        bool proxy_ready_ack_received = false;
        bool stop_received = false;

        {
            std::lock_guard<std::mutex> guard(state.lock);
            proxy_ready_ack_received = state.proxy_ready_ack_received;
            stop_received = state.stop_received;
        }

        if(stop_received)
        {
            std::fprintf(stderr, "[UDP READY] stop received while waiting READY_ACK\n");
            return false;
        }

        if(proxy_ready_ack_received)
        {
            for(int i = 0; i < 3; ++i)
            {
                if(!udp_send_string(udp_fd, proxy_addr, start_ack_msg))
                    return false;

                std::printf("[UDP READY] sent CLIENT_START_ACK\n");
                usleep(100 * 1000);
            }

            {
                std::lock_guard<std::mutex> guard(state.lock);
                state.ready_done = true;
            }

            std::printf("[UDP READY] done\n");
            return true;
        }

        uint64_t current_time = now_ms();

        if(current_time - start_time >= UDP_TIMEOUT_SECONDS * 1000ULL)
        {
            std::fprintf(stderr, "[UDP READY] timeout\n");
            return false;
        }

        if(current_time >= next_send_time)
        {
            if(!udp_send_string(udp_fd, proxy_addr, ready_msg))
                return false;

            std::printf("[UDP READY] sent CLIENT_READY\n");

            next_send_time = current_time + UDP_RETRY_INTERVAL_MS;
        }

        usleep(10 * 1000);
    }

    return false;
}


// Ctrl+C 또는 local cleanup 시 Proxy에게 종료 신호를 보냄
void send_client_udp_stop(int udp_fd, const char* proxy_ip, uint16_t ready_port, const ClientReadyState& state)
{
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "[UDP STOP] invalid udp fd\n");
        return;
    }

    std::string client_nonce;
    std::string proxy_nonce;

    {
        std::lock_guard<std::mutex> guard(state.lock);
        client_nonce = state.client_nonce;
        proxy_nonce = state.proxy_nonce;
    }

    if(client_nonce.empty() || proxy_nonce.empty())
    {
        std::fprintf(stderr, "[UDP STOP] nonce is not ready. skip UDP STOP\n");
        return;
    }

    sockaddr_in proxy_addr;
    if(!make_proxy_addr(proxy_ip, ready_port, proxy_addr))
        return;

    std::string stop_msg = std::string(UDP_STOP_PREFIX) + client_nonce + ":" + proxy_nonce;

    for(int i = 0; i < UDP_STOP_REPEAT_COUNT; ++i)
    {
        if(!udp_send_string(udp_fd, proxy_addr, stop_msg))
        {
            std::fprintf(stderr, "[UDP STOP] failed to send UDP STOP\n");
            return;
        }

        std::printf("[UDP STOP] sent UDP STOP\n");
        usleep(UDP_STOP_INTERVAL_MS * 1000);
    }
}

void client_udp_control_loop(int udp_fd, ClientReadyState& state, ClientTunnelState& tunnel_state, std::atomic<bool>& stop)
{
    while(!g_signal_stop && !stop.load() && !tunnel_state.session_stop.load() && !tunnel_state.session_error.load())
    {
        std::string recv_msg;
        if(!udp_recv_string(udp_fd, recv_msg, UDP_RETRY_INTERVAL_MS))
            continue;

        if(starts_with(recv_msg, UDP_STOP_PREFIX))
        {
            if(!is_valid_udp_stop(recv_msg, state))
            {
                std::printf("[UDP CONTROL] ignore UDP STOP with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            {
                std::lock_guard<std::mutex> guard(state.lock);
                state.stop_received = true;
            }

            std::fprintf(stderr, "[UDP CONTROL] received valid UDP STOP\n");
            tunnel_state.session_stop.store(true);
            stop.store(true);
            return;
        }

        if(starts_with(recv_msg, PROXY_LEARN_READY_PREFIX))
        {
            if(!is_valid_proxy_learn_ready(recv_msg, state))
            {
                std::printf("[UDP CONTROL] ignore PROXY_LEARN_READY with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            {
                std::lock_guard<std::mutex> guard(state.lock);
                state.proxy_learn_ready_received = true;
            }

            std::printf("[UDP CONTROL] received valid PROXY_LEARN_READY\n");
            continue;
        }

        if(starts_with(recv_msg, PROXY_TUNNEL_READY_ACK_PREFIX))
        {
            if(!is_valid_proxy_ready_ack(recv_msg, state))
            {
                std::printf("[UDP CONTROL] ignore READY_ACK with wrong nonce: %s\n", recv_msg.c_str());
                continue;
            }

            {
                std::lock_guard<std::mutex> guard(state.lock);
                state.proxy_ready_ack_received = true;
            }

            std::printf("[UDP CONTROL] received valid PROXY_READY_ACK\n");
            continue;
        }

        std::printf("[UDP CONTROL] ignore unexpected UDP message: %s\n", recv_msg.c_str());
    }
}