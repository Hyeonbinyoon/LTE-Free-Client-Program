// for free LTE
/* 1. TCP connect 완료
   2. get_socket_local_tuple()으로 Client local IP/port 확보
   3. install_client_nfqueue_rule()
   4. learn_client_tcp_base_with_nfqueue()
    4-1. Proxy → Client keepalive ACK 대기
    4-2. packet 수신
    4-3. seq/ack 추출
    4-4. realBase = C/P 저장
    4-5. fakeBase = C+1/P+1 저장
    4-6. 해당 packet NF_ACCEPT
   5. learning 성공 후 tunC 생성/설정 단계로 이동 */

#include "client.h"
#include "hb_headers.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static constexpr uint8_t TCP_FLAG_FIN = 0x01;
static constexpr uint8_t TCP_FLAG_SYN = 0x02;
static constexpr uint8_t TCP_FLAG_RST = 0x04;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;

struct ParsedOuterTcpPacket
{
    const hb_ip_hdr* ip = nullptr;
    const hb_tcp_hdr* tcp = nullptr;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
};

struct ClientNfqueueContext
{
    const ClientRawConfig* config = nullptr;
    RealBase* real_base = nullptr;
    FakeBase* fake_base = nullptr;
    bool learned = false;
};

static uint32_t get_packet_id(nfq_data* nfad)
{
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if(ph == nullptr)
        return 0;

    return ntohl(ph->packet_id);
}

static bool ip_to_string(uint32_t ip_net, std::string& out)
{
    char buf[INET_ADDRSTRLEN];

    if(inet_ntop(AF_INET, &ip_net, buf, sizeof(buf)) == nullptr)
        return false;

    out = buf;
    return true;
}

static bool parse_proxy_to_client_tcp_packet(
    const uint8_t* packet,
    size_t packet_len,
    const ClientRawConfig& config,
    ParsedOuterTcpPacket& parsed)
{
    if(packet == nullptr)
        return false;

    if(packet_len < HB_IPV4_H_SIZE)
        return false;

    const hb_ip_hdr* ip = reinterpret_cast<const hb_ip_hdr*>(packet);

    if(ip->version() != IP_VERSION_IPv4)
        return false;

    if(ip->protocol_value() != IP_PROTOCOL_TCP)
        return false;

    size_t ip_header_len = ip->header_len();
    if(ip_header_len < HB_IPV4_H_SIZE)
        return false;

    if(packet_len < ip_header_len + HB_TCP_H_SIZE)
        return false;

    uint16_t ip_total_len = ip->total_length();
    if(ip_total_len < ip_header_len + HB_TCP_H_SIZE)
        return false;

    if(packet_len < ip_total_len)
        return false;

    if(ip->src_ip != config.proxy_ip)
        return false;

    if(ip->dst_ip != config.local_ip)
        return false;

    const hb_tcp_hdr* tcp = reinterpret_cast<const hb_tcp_hdr*>(packet + ip_header_len);

    size_t tcp_header_len = tcp->header_len();
    if(tcp_header_len < HB_TCP_H_SIZE)
        return false;

    if(ip_total_len < ip_header_len + tcp_header_len)
        return false;

    if(tcp->src_port_value() != config.proxy_port)
        return false;

    if(tcp->dst_port_value() != config.local_port)
        return false;

    size_t payload_offset = ip_header_len + tcp_header_len;
    size_t payload_len = ip_total_len - payload_offset;

    parsed.ip = ip;
    parsed.tcp = tcp;
    parsed.payload = packet + payload_offset;
    parsed.payload_len = payload_len;
    parsed.seq = ntohl(tcp->seq_num);
    parsed.ack = ntohl(tcp->ack_num);

    return true;
}

static bool is_client_learning_keepalive_ack(const ParsedOuterTcpPacket& parsed)
{
    if(parsed.tcp == nullptr)
        return false;

    if(parsed.payload_len != 0)
        return false;

    if((parsed.tcp->flags & TCP_FLAG_ACK) == 0)
        return false;

    if((parsed.tcp->flags & TCP_FLAG_SYN) != 0)
        return false;

    if((parsed.tcp->flags & TCP_FLAG_FIN) != 0)
        return false;

    if((parsed.tcp->flags & TCP_FLAG_RST) != 0)
        return false;

    return true;
}

static int client_learning_callback(
    nfq_q_handle* qh,
    nfgenmsg*,
    nfq_data* nfad,
    void* data)
{
    ClientNfqueueContext* ctx = reinterpret_cast<ClientNfqueueContext*>(data);
    uint32_t packet_id = get_packet_id(nfad);

    unsigned char* raw_payload = nullptr;
    int payload_len = nfq_get_payload(nfad, &raw_payload);

    if(payload_len < 0)
    {
        std::fprintf(stderr, "[NFQ C-LEARN] failed to get payload\n");
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    ParsedOuterTcpPacket parsed;
    if(!parse_proxy_to_client_tcp_packet(raw_payload,
                                         static_cast<size_t>(payload_len),
                                         *ctx->config,
                                         parsed))
    {
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    std::printf("[NFQ C-LEARN] tcp packet seq=%u ack=%u flags=0x%02x payload_len=%zu\n",
                parsed.seq,
                parsed.ack,
                parsed.tcp->flags,
                parsed.payload_len);

    if(!is_client_learning_keepalive_ack(parsed))
    {
        return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
    }

    ctx->real_base->client_seq = parsed.ack - 1;
    ctx->real_base->proxy_seq = parsed.seq - 1;
    ctx->real_base->learned = true;

    ctx->fake_base->fake_client_seq = ctx->real_base->client_seq + 1;
    ctx->fake_base->fake_proxy_seq = ctx->real_base->proxy_seq + 1;
    ctx->fake_base->initialized = true;

    ctx->learned = true;

    std::printf("[NFQ C-LEARN] learned realBase: client_seq=%u proxy_seq=%u\n",
                ctx->real_base->client_seq,
                ctx->real_base->proxy_seq);

    std::printf("[NFQ C-LEARN] initialized fakeBase: fake_client_seq=%u fake_proxy_seq=%u\n",
                ctx->fake_base->fake_client_seq,
                ctx->fake_base->fake_proxy_seq);

    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
}

bool install_client_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num)
{
    std::string local_ip;
    std::string proxy_ip;

    if(!ip_to_string(config.local_ip, local_ip))
    {
        std::fprintf(stderr, "failed to convert local ip\n");
        return false;
    }

    if(!ip_to_string(config.proxy_ip, proxy_ip))
    {
        std::fprintf(stderr, "failed to convert proxy ip\n");
        return false;
    }

    std::string cmd =
        "iptables -I INPUT "
        "-p tcp "
        "-s " + proxy_ip + " "
        "--sport " + std::to_string(config.proxy_port) + " "
        "-d " + local_ip + " "
        "--dport " + std::to_string(config.local_port) + " "
        "-j NFQUEUE --queue-num " + std::to_string(queue_num);

    return run_cmd(cmd);
}

void cleanup_client_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num)
{
    std::string local_ip;
    std::string proxy_ip;

    if(!ip_to_string(config.local_ip, local_ip))
        return;

    if(!ip_to_string(config.proxy_ip, proxy_ip))
        return;

    std::string cmd =
        "iptables -D INPUT "
        "-p tcp "
        "-s " + proxy_ip + " "
        "--sport " + std::to_string(config.proxy_port) + " "
        "-d " + local_ip + " "
        "--dport " + std::to_string(config.local_port) + " "
        "-j NFQUEUE --queue-num " + std::to_string(queue_num) +
        " 2>/dev/null";

    run_cmd(cmd);
}

bool learn_client_tcp_base_with_nfqueue(
    uint16_t queue_num,
    const ClientRawConfig& config,
    RealBase& real_base,
    FakeBase& fake_base,
    std::atomic<bool>& stop)
{
    nfq_handle* h = nfq_open();
    if(h == nullptr)
    {
        std::fprintf(stderr, "nfq_open failed\n");
        return false;
    }

    if(nfq_unbind_pf(h, AF_INET) < 0)
    {
        std::fprintf(stderr, "nfq_unbind_pf(AF_INET) failed\n");
        nfq_close(h);
        return false;
    }

    if(nfq_bind_pf(h, AF_INET) < 0)
    {
        std::fprintf(stderr, "nfq_bind_pf(AF_INET) failed\n");
        nfq_close(h);
        return false;
    }

    ClientNfqueueContext ctx;
    ctx.config = &config;
    ctx.real_base = &real_base;
    ctx.fake_base = &fake_base;
    ctx.learned = false;

    nfq_q_handle* qh = nfq_create_queue(h,
                                        queue_num,
                                        &client_learning_callback,
                                        &ctx);
    if(qh == nullptr)
    {
        std::fprintf(stderr, "nfq_create_queue failed\n");
        nfq_close(h);
        return false;
    }

    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        std::fprintf(stderr, "nfq_set_mode failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return false;
    }

    int fd = nfq_fd(h);
    char buf[4096];

    std::printf("[NFQ C-LEARN] waiting for Proxy -> Client keepalive ACK on queue %u...\n",
                queue_num);

    while(!stop.load() && !ctx.learned)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if(ret < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ C-LEARN] select");
            break;
        }

        if(ret == 0)
            continue;

        ssize_t rv = recv(fd, buf, sizeof(buf), 0);
        if(rv < 0)
        {
            if(errno == EINTR)
                continue;

            perror("[NFQ C-LEARN] recv");
            break;
        }

        nfq_handle_packet(h, buf, static_cast<int>(rv));
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    if(!ctx.learned)
    {
        std::fprintf(stderr, "[NFQ C-LEARN] learning failed or stopped\n");
        return false;
    }

    return true;
}