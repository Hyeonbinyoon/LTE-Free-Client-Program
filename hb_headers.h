//hb_headers.h
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <optional>


// ============================================================
// Header sizes
// ============================================================

#define HB_ETH_H_SIZE            0x0e    /* Ethernet header: 14 bytes */
#define HB_ARP_H_SIZE            0x1c    /* ARP header:      28 bytes */
#define HB_IPV4_H_SIZE           0x14    /* IPv4 header:     20 bytes */
#define HB_TCP_H_SIZE            0x14    /* TCP header:      20 bytes */



// ============================================================
// Ethernet
// ============================================================

#define MAC_ADDR_LEN             0x06    /* MAC address length: 6 bytes */

#define ETH_OFFSET_DST_MAC       0x00
#define ETH_OFFSET_SRC_MAC       0x06
#define ETH_OFFSET_ETHERTYPE     0x0c

#define ETHERTYPE_IPV4           0x0800
#define ETHERTYPE_ARP            0x0806



// ============================================================
// ARP
// ============================================================

#define ARP_HARDWARE_ETHERNET    0x0001
#define ARP_OPCODE_REQUEST       0x0001
#define ARP_OPCODE_REPLY         0x0002
#define ARP_PROTOCOL_ADDR_LEN_IP 0x04



// ============================================================
// IPv4
// ============================================================

#define IP_OFFSET_VERSION_IHL    0x00
#define IP_OFFSET_TOTAL_LEN      0x02
#define IP_OFFSET_PROTOCOL       0x09
#define IP_OFFSET_SRC_IP         0x0c
#define IP_OFFSET_DST_IP         0x10

#define IP_VERSION_IPv4          0x04
#define IP_PROTOCOL_TCP          0x06
#define IP_FLAG_MF               0x2000
#define IP_FRAG_OFFSET_MASK      0x1FFF



// ============================================================
// TCP
// ============================================================

#define TCP_OFFSET_SRC_PORT      0x00
#define TCP_OFFSET_DST_PORT      0x02
#define TCP_OFFSET_HDR_LEN       0x0c



#pragma pack(push, 1)

struct hb_mac
{
    uint8_t bytes[MAC_ADDR_LEN];
};

struct hb_eth_hdr
{
    hb_mac dst_mac;
    hb_mac src_mac;
    uint16_t ethertype;

    uint16_t ethertype_value() const;
};

struct hb_arp_hdr
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_addr_len;
    uint8_t  protocol_addr_len;
    uint16_t opcode;
    hb_mac   sender_mac;
    uint32_t sender_ip;
    hb_mac   target_mac;
    uint32_t target_ip;

    uint16_t hardware_type_value() const;
    uint16_t protocol_type_value() const;
    uint16_t opcode_value() const;
    uint32_t sender_ip_value() const;
    uint32_t target_ip_value() const;
};

struct hb_ip_hdr
{
    uint8_t  ver_and_hdr_len;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hdr_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    uint8_t version() const;
    uint8_t header_len() const;
    uint16_t total_length() const;
    uint8_t protocol_value() const;
    uint32_t src_ip_value() const;
    uint32_t dst_ip_value() const;
};

struct hb_tcp_hdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  hdr_len_and_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_p;

    uint16_t src_port_value() const;
    uint16_t dst_port_value() const;
    uint8_t header_len() const;
};

#pragma pack(pop)



// Parse functions
std::optional<hb_mac>   Mac_parse(const std::string& s);
std::optional<uint32_t> Ip_parse(const std::string& s);

// Special MAC values
hb_mac   Mac_null(void);
hb_mac   Mac_broadcast(void);

// MAC tests
bool     Mac_is_null(hb_mac mac);
bool     Mac_is_broadcast(hb_mac mac);


