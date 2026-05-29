#include "client.h"

#include <cstdio>
#include <cstring>
#include <arpa/inet.h>

/*bool try_pop_ipv4_packet(std::vector<uint8_t>& buffer, std::vector<uint8_t>& packet)
{
    if(buffer.size() < 20)
        return false;

    uint8_t version = buffer[0] >> 4;
    uint8_t ihl = buffer[0] & 0x0f;

    if(version != 4)
    {
        std::fprintf(stderr, "invalid packet: version=%u, first_byte=0x%02x\n",
                     version, buffer[0]);
        return false;
    }

    if(ihl < 5)
    {
        std::fprintf(stderr, "invalid IPv4 IHL: %u\n", ihl);
        return false;
    }

    size_t ip_header_len = static_cast<size_t>(ihl) * 4;
    if(buffer.size() < ip_header_len)
        return false;

    uint16_t total_len_net;
    std::memcpy(&total_len_net, &buffer[2], sizeof(total_len_net));

    uint16_t total_len = ntohs(total_len_net);
    if(total_len < ip_header_len)
    {
        std::fprintf(stderr, "invalid IPv4 total length: %u\n", total_len);
        return false;
    }

    if(buffer.size() < total_len)
        return false;

    packet.assign(buffer.begin(), buffer.begin() + total_len);
    buffer.erase(buffer.begin(), buffer.begin() + total_len);

    return true;
} */

void print_ipv4_packet_info(const std::vector<uint8_t>& packet)
{
    if(packet.size() < 20)
        return;

    uint8_t version = packet[0] >> 4;
    uint8_t ihl = packet[0] & 0x0f;

    uint16_t total_len_net;
    std::memcpy(&total_len_net, &packet[2], sizeof(total_len_net));
    uint16_t total_len = ntohs(total_len_net);

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &packet[12], src, sizeof(src));
    inet_ntop(AF_INET, &packet[16], dst, sizeof(dst));

    std::printf("inner IPv4 packet parsed\n");
    std::printf("first byte       : 0x%02x\n", packet[0]);
    std::printf("ip version       : %u\n", version);
    std::printf("ihl              : %u (%u bytes)\n", ihl, ihl * 4);
    std::printf("ipv4 total length: %u\n", total_len);
    std::printf("src ip           : %s\n", src);
    std::printf("dst ip           : %s\n", dst);
}
