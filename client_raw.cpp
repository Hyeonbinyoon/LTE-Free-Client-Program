// for free LTE
#include "client.h"
#include "hb_headers.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <chrono>

static_assert(sizeof(hb_ip_hdr) == HB_IPV4_H_SIZE, "hb_ip_hdr size mismatch");
static_assert(sizeof(hb_tcp_hdr) == HB_TCP_H_SIZE, "hb_tcp_hdr size mismatch");

static constexpr uint8_t TCP_FLAG_PSH = 0x08;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;
static constexpr uint16_t IP_FLAG_DF = 0x4000;

static uint16_t checksum16(const void* data, size_t len)
{
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    while(len > 1)
    {
        uint16_t word;
        std::memcpy(&word, bytes, sizeof(word));
        sum += ntohs(word);

        bytes += 2;
        len -= 2;
    }

    if(len == 1)
    {
        uint16_t word = static_cast<uint16_t>(bytes[0]) << 8;
        sum += word;
    }

    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htons(static_cast<uint16_t>(~sum));
}


#pragma pack(push, 1)

struct TcpPseudoHeader
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};
#pragma pack(pop)


static uint16_t tcp_checksum( const hb_ip_hdr* ip, const hb_tcp_hdr* tcp, const uint8_t* payload, size_t payload_len)
{
    size_t tcp_len = HB_TCP_H_SIZE + payload_len;
    size_t pseudo_len = sizeof(TcpPseudoHeader) + tcp_len;

    std::vector<uint8_t> pseudo_packet(pseudo_len);

    TcpPseudoHeader pseudo;
    pseudo.src_ip = ip->src_ip;
    pseudo.dst_ip = ip->dst_ip;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.tcp_len = htons(static_cast<uint16_t>(tcp_len));

    std::memcpy(pseudo_packet.data(), &pseudo, sizeof(pseudo));
    std::memcpy(pseudo_packet.data() + sizeof(pseudo), tcp, HB_TCP_H_SIZE);

    if(payload_len > 0)
        std::memcpy(pseudo_packet.data() + sizeof(pseudo) + HB_TCP_H_SIZE, payload, payload_len);

    return checksum16(pseudo_packet.data(), pseudo_packet.size());
}

static bool build_outer_packet(const uint8_t* inner_packet, size_t inner_len, const ClientRawConfig& config, uint32_t seq, uint32_t ack, std::vector<uint8_t>& outer_packet)
{
    if(inner_packet == nullptr || inner_len == 0)
        return false;

    if(inner_len > TUN_MTU)
    {
        std::fprintf(stderr, "[RAW C->P] inner packet too large for TUN MTU: %zu > %d\n", inner_len, TUN_MTU);
        return false;
    }

    size_t total_len = HB_IPV4_H_SIZE + HB_TCP_H_SIZE + inner_len;

    if(total_len > RAW_OUTER_MAX_LEN)
    {
        std::fprintf(stderr, "[RAW C->P] outer packet too large: %zu > %d\n", total_len, RAW_OUTER_MAX_LEN);
        return false;
    }

    outer_packet.assign(total_len, 0);

    hb_ip_hdr* ip = reinterpret_cast<hb_ip_hdr*>(outer_packet.data());
    hb_tcp_hdr* tcp = reinterpret_cast<hb_tcp_hdr*>(outer_packet.data() + HB_IPV4_H_SIZE);
    uint8_t* payload = outer_packet.data() + HB_IPV4_H_SIZE + HB_TCP_H_SIZE;

    std::memcpy(payload, inner_packet, inner_len);

    ip->ver_and_hdr_len = static_cast<uint8_t>((IP_VERSION_IPv4 << 4) | (HB_IPV4_H_SIZE / 4));
    ip->tos = 0;
    ip->total_len = htons(static_cast<uint16_t>(total_len));
    ip->id = htons(0);
    ip->offset = htons(IP_FLAG_DF);
    ip->ttl = RAW_TTL;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->hdr_checksum = 0;
    ip->src_ip = config.local_ip;
    ip->dst_ip = config.proxy_ip;
    ip->hdr_checksum = checksum16(ip, HB_IPV4_H_SIZE);

    tcp->src_port = htons(config.local_port);
    tcp->dst_port = htons(config.proxy_port);
    tcp->seq_num = htonl(seq);
    tcp->ack_num = htonl(ack);
    tcp->hdr_len_and_reserved = static_cast<uint8_t>((HB_TCP_H_SIZE / 4) << 4);
    tcp->flags = TCP_FLAG_PSH | TCP_FLAG_ACK;
    tcp->window = htons(65535);
    tcp->checksum = 0;
    tcp->urg_p = 0;
    tcp->checksum = tcp_checksum(ip, tcp, payload, inner_len);

    return true;
}

bool init_client_raw_config(const char* proxy_ip, uint16_t proxy_port, int proxy_fd, ClientRawConfig& config)
{
    std::memset(&config, 0, sizeof(config));

    if(!get_socket_local_tuple(proxy_fd, config.local_ip, config.local_port))
        return false;

    if(inet_pton(AF_INET, proxy_ip, &config.proxy_ip) != 1)
    {
        std::fprintf(stderr, "invalid proxy ip for raw config: %s\n", proxy_ip);
        return false;
    }

    config.proxy_port = proxy_port;

    char local_ip_str[INET_ADDRSTRLEN];
    char proxy_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &config.local_ip, local_ip_str, sizeof(local_ip_str));
    inet_ntop(AF_INET, &config.proxy_ip, proxy_ip_str, sizeof(proxy_ip_str));

    std::printf("[RAW] local ip  : %s\n", local_ip_str);
    std::printf("[RAW] proxy ip  : %s\n", proxy_ip_str);
    std::printf("[RAW] local port: %u\n", config.local_port);
    std::printf("[RAW] proxy port: %u\n", config.proxy_port);

    return true;
}

int open_raw_send_socket()
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(fd < 0)
    {
        perror("socket SOCK_RAW IPPROTO_RAW");
        return -1;
    }

    int on = 1;
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt IP_HDRINCL");
        close(fd);
        return -1;
    }

    return fd;
}

void tun_to_raw_loop( int tun_fd, int raw_send_fd, const ClientRawConfig& config, const FakeBase& fake_base, RawSendState& send_state, std::atomic<bool>& stop)
{
    uint8_t buf[2000];
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = config.proxy_ip;

    while(!stop.load())
    {
        if(!fake_base.initialized)
        {
            std::fprintf(stderr, "[RAW C->P] fake base is not initialized\n");
            stop.store(true);
            return;
        }

        ssize_t n = read(tun_fd, buf, sizeof(buf));
        if(n < 0)
        {
            if(stop.load())
                break;

            if(errno == EINTR)
                continue;

            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            perror("[RAW C->P] read tun");
            stop.store(true);
            break;
        }

        if(n == 0)
        {
            std::fprintf(stderr, "[RAW C->P] tun read returned 0\n");
            stop.store(true);
            break;
        }

        uint64_t old_real = send_state.real_bytes_sent;
        uint64_t old_fake = send_state.fake_seq_offset;

        uint32_t seq = fake_base.fake_client_seq + static_cast<uint32_t>(old_fake);
        uint32_t ack = fake_base.fake_proxy_seq;

        std::vector<uint8_t> outer_packet;
        if(!build_outer_packet(buf, static_cast<size_t>(n), config, seq, ack, outer_packet))
        {
            stop.store(true);
            break;
        }

        ssize_t sent = sendto(raw_send_fd, outer_packet.data(), outer_packet.size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        if(sent < 0)
        {
            perror("[RAW C->P] sendto");
            stop.store(true);
            break;
        }

        if(static_cast<size_t>(sent) != outer_packet.size())
        {
            std::fprintf(stderr, "[RAW C->P] partial raw send: %zd / %zu\n", sent, outer_packet.size());
            stop.store(true);
            break;
        }

        send_state.real_bytes_sent += static_cast<uint64_t>(n);
        send_state.fake_seq_offset = send_state.real_bytes_sent / 10;

        std::printf("[RAW C->P] inner=%zd outer=%zu seq=%u ack=%u real=%llu->%llu fake=%llu->%llu fake_inc=%llu\n",
                    n,
                    outer_packet.size(),
                    seq,
                    ack,
                    static_cast<unsigned long long>(old_real),
                    static_cast<unsigned long long>(send_state.real_bytes_sent),
                    static_cast<unsigned long long>(old_fake),
                    static_cast<unsigned long long>(send_state.fake_seq_offset),
                    static_cast<unsigned long long>(send_state.fake_seq_offset - old_fake));
    }
}