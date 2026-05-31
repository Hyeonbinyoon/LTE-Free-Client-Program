#include "client.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

bool send_all(int fd, const uint8_t* data, size_t len)
{
    size_t sent = 0;

    while(sent < len)
    {
        ssize_t n = send(fd, data + sent, len - sent, 0);

        if(n > 0)
        {
            sent += static_cast<size_t>(n);
            continue;
        }

        if(n < 0 && errno == EINTR)
            continue;

        perror("send");
        return false;
    }

    return true;
}

bool set_tcp_mss(int sock, int mss)
{
    if(setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0)
    {
        perror("setsockopt TCP_MAXSEG");
        return false;
    }

    return true;
}

int connect_proxy(const char* proxy_ip, uint16_t proxy_port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        perror("socket");
        return -1;
    }

    if(!set_tcp_mss(sock, TCP_MSS))
    {
        close(sock);
        return -1;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);

    if(inet_pton(AF_INET, proxy_ip, &addr.sin_addr) != 1)
    {
        std::fprintf(stderr, "invalid proxy ip: %s\n", proxy_ip);
        close(sock);
        return -1;
    }

    if(connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        perror("connect");
        close(sock);
        return -1;
    }

    if(!set_tcp_keepalive(sock, 20, 1, 3))
    {
        close(sock);
        return -1;
    } 

    std::printf("connected to proxy %s:%u\n", proxy_ip, proxy_port);

    return sock;
}

/*void proxy_to_tun_loop(int proxy_fd, int tun_fd, std::atomic<bool>& stop)
{
    std::vector<uint8_t> stream_buffer;
    uint8_t buf[2048];

    while(!stop.load())
    {
        ssize_t n = recv(proxy_fd, buf, sizeof(buf), 0);
        if(n == 0)
        {
            std::fprintf(stderr, "[P->C] proxy disconnected\n");
            stop.store(true);
            break;
        }

        if(n < 0)
        {
            if(stop.load())
                break;

            if(errno == EINTR)
                continue;

            perror("recv proxy");
            stop.store(true);
            break;
        }

        std::printf("[P->C] recv %zd bytes from proxy\n", n);

        stream_buffer.insert(stream_buffer.end(), buf, buf + n);

        while(true)
        {
            std::vector<uint8_t> packet;
            if(!try_pop_ipv4_packet(stream_buffer, packet))
                break;

            print_ipv4_packet_info(packet);

            if(!write_packet_to_tun(tun_fd, packet))
            {
                stop.store(true);
                return;
            }
        }
    }
} */




//for free LTE
bool get_socket_local_tuple(int sock, uint32_t& local_ip, uint16_t& local_port)
{
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));

    socklen_t addr_len = sizeof(addr);

    if(getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &addr_len) < 0)
    {
        perror("getsockname");
        return false;
    }

    if(addr.sin_family != AF_INET)
    {
        std::fprintf(stderr, "local socket address is not IPv4\n");
        return false;
    }

    local_ip = addr.sin_addr.s_addr;
    local_port = ntohs(addr.sin_port);

    return true;
}

bool set_tcp_keepalive(int sock, int idle, int interval, int count)
{
    int optval = 1;

    if(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt SO_KEEPALIVE");
        return false;
    }

    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0)
    {
        perror("setsockopt TCP_KEEPIDLE");
        return false;
    }

    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0)
    {
        perror("setsockopt TCP_KEEPINTVL");
        return false;
    }

    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0)
    {
        perror("setsockopt TCP_KEEPCNT");
        return false;
    }

    std::printf("TCP keepalive enabled: idle=%d interval=%d count=%d\n",
                idle,
                interval,
                count);

    return true;
}

int open_client_ready_socket()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("socket UDP ready");
        return -1;
    }

    return sock;
}