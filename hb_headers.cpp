//hb_headers.cpp
#include "hb_headers.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <optional>
#include <stdio.h>
#include <string>


// ------------------------------------------------------------
// Header field getter functions
// ------------------------------------------------------------
uint16_t hb_eth_hdr::ethertype_value() const
{
    return ntohs(ethertype);
}

uint16_t hb_arp_hdr::hardware_type_value() const
{
    return ntohs(hardware_type);
}

uint16_t hb_arp_hdr::protocol_type_value() const
{
    return ntohs(protocol_type);
}

uint16_t hb_arp_hdr::opcode_value() const
{
    return ntohs(opcode);
}

uint32_t hb_arp_hdr::sender_ip_value() const
{
    return ntohl(sender_ip);
}

uint32_t hb_arp_hdr::target_ip_value() const
{
    return ntohl(target_ip);
}

uint8_t hb_ip_hdr::version() const
{
    return (ver_and_hdr_len & 0xF0) >> 4;
}

uint8_t hb_ip_hdr::header_len() const
{
    return (ver_and_hdr_len & 0x0F) * 4;
}

uint16_t hb_ip_hdr::total_length() const
{
    return ntohs(total_len);
}

uint8_t hb_ip_hdr::protocol_value() const
{
    return protocol;
}

uint32_t hb_ip_hdr::src_ip_value() const
{
    return ntohl(src_ip);
}

uint32_t hb_ip_hdr::dst_ip_value() const
{
    return ntohl(dst_ip);
}

uint16_t hb_tcp_hdr::src_port_value() const
{
    return ntohs(src_port);
}

uint16_t hb_tcp_hdr::dst_port_value() const
{
    return ntohs(dst_port);
}

uint8_t hb_tcp_hdr::header_len() const
{
    return ((hdr_len_and_reserved >> 4) & 0x0F) * 4;
}


// ------------------------------------------------------------
// Internal helper: convert one hex character to integer
// ------------------------------------------------------------
static int hex_value(char ch)
{
    unsigned char c = static_cast<unsigned char>(ch);

    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}


// ------------------------------------------------------------
// Parse functions
// ------------------------------------------------------------
std::optional<hb_mac> Mac_parse(const std::string& s)
{
    std::string hex;
    hex.reserve(12);

    for (char ch : s)
    {
        if (isxdigit(static_cast<unsigned char>(ch)))
        {
            if (hex.size() >= 12) return std::nullopt;
            hex.push_back(ch);
        }
    }

    if (hex.size() != 12) return std::nullopt;


    hb_mac mac = {{0}};

    for (int i = 0; i < MAC_ADDR_LEN; i++)
    {
        int high = hex_value(hex[i * 2]);
        int low = hex_value(hex[i * 2 + 1]);

        if (high < 0 || low < 0) return std::nullopt;
        mac.bytes[i] = static_cast<uint8_t>((high << 4) | low);
    }

    return mac;
}

std::optional<uint32_t> Ip_parse(const std::string& s)
{
    unsigned int part[4];
    char tail;

    int res = sscanf(s.c_str(), "%u.%u.%u.%u%c", &part[0], &part[1], &part[2], &part[3], &tail);
    if (res != 4) return std::nullopt;

    for (int i = 0; i < 4; i++)
    {
        if (part[i] > 255) return std::nullopt;
    }

    uint32_t ip = 0;
    ip |= (part[0] << 24);
    ip |= (part[1] << 16);
    ip |= (part[2] << 8);
    ip |= part[3];

    return ip;
}



// ------------------------------------------------------------
// Special MAC values
// ------------------------------------------------------------
hb_mac Mac_null(void)
{
    hb_mac mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    return mac;
}

hb_mac Mac_broadcast(void)
{
    hb_mac mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    return mac;
}


// ------------------------------------------------------------
// MAC tests
// ------------------------------------------------------------
bool Mac_is_null(hb_mac mac)
{
    for (int i = 0; i < MAC_ADDR_LEN; i++)
    {
        if (mac.bytes[i] != 0x00) return false;
    }

    return true;
}

bool Mac_is_broadcast(hb_mac mac)
{
    for (int i = 0; i < MAC_ADDR_LEN; i++)
    {
        if (mac.bytes[i] != 0xFF) return false;
    }

    return true;
}
