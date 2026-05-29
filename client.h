#ifndef CLIENT_H
#define CLIENT_H

#include <array>
#include <atomic>
#include <cstdint>
#include <csignal>
#include <string>
#include <vector>

#define CLIENT_TUN_NAME "tunC"
#define CLIENT_TUN_IP_CIDR "10.8.0.2/30"

////// for free LTE
#define TUN_MTU 1400
#define TCP_MSS 1360
#define OUTER_IP_TCP_HEADER_LEN 40
#define RAW_OUTER_MAX_LEN (TUN_MTU + OUTER_IP_TCP_HEADER_LEN)
#define RAW_TTL 64
#define CLIENT_NFQUEUE_NUM 33

struct ClientRawConfig
{
    uint32_t local_ip;
    uint32_t proxy_ip;
    uint16_t local_port;
    uint16_t proxy_port;
};

struct RealBase
{
    uint32_t client_seq = 0;
    uint32_t proxy_seq = 0;
    bool learned = false;
};

struct FakeBase
{
    uint32_t fake_client_seq = 0;
    uint32_t fake_proxy_seq = 0;
    bool initialized = false;
};

struct RawSendState
{
    uint64_t real_bytes_sent = 0;
    uint64_t fake_seq_offset = 0;
};
//////

extern volatile std::sig_atomic_t g_signal_stop;

struct RouteSnapshot
{
    std::string gateway;
    std::string ifname;
    std::string src;
    std::vector<std::string> added_routes;
    bool default_route_changed = false;
};

void handle_signal(int);
bool wait_for_stop_request();
bool run_cmd(const std::string& cmd);
bool add_route(RouteSnapshot& route, const std::string& cidr);
void cleanup_routes(const RouteSnapshot& route);
bool load_default_route(RouteSnapshot& route);
bool replace_default_route_to_tun(RouteSnapshot& route, const std::string& tun_name);
void restore_default_route(const RouteSnapshot& route);

bool set_nonblocking(int fd);
int tun_alloc(const char* dev_name);
bool setup_tun_interface(const char* dev_name);
bool write_packet_to_tun(int tun_fd, const std::vector<uint8_t>& packet);
//void tun_to_proxy_loop(int tun_fd, int proxy_fd, std::atomic<bool>& stop);

bool send_all(int fd, const uint8_t* data, size_t len);
bool set_tcp_mss(int sock, int mss);
int connect_proxy(const char* proxy_ip, uint16_t proxy_port);
//void proxy_to_tun_loop(int proxy_fd, int tun_fd, std::atomic<bool>& stop);

//bool try_pop_ipv4_packet(std::vector<uint8_t>& buffer, std::vector<uint8_t>& packet);
void print_ipv4_packet_info(const std::vector<uint8_t>& packet);



//for free LTE
bool init_client_raw_config(const char* proxy_ip, uint16_t proxy_port, int proxy_fd, ClientRawConfig& config);
int open_raw_send_socket();
void tun_to_raw_loop(int tun_fd, int raw_send_fd, const ClientRawConfig& config, const FakeBase& fake_base, RawSendState& send_state, std::atomic<bool>& stop);

bool set_tcp_keepalive(int sock, int idle, int interval, int count);
bool get_socket_local_tuple(int sock, uint32_t& local_ip, uint16_t& local_port);

bool install_client_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num);
void cleanup_client_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num);
bool learn_client_tcp_base_with_nfqueue(uint16_t queue_num, const ClientRawConfig& config, RealBase& real_base, FakeBase& fake_base, std::atomic<bool>& stop);

//
#endif
