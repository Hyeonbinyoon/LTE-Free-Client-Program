#ifndef CLIENT_H
#define CLIENT_H

#include <array>
#include <atomic>
#include <cstdint>
#include <csignal>
#include <string>
#include <vector>
#include <mutex>

#define CLIENT_TUN_NAME "tunC"
#define CLIENT_TUN_IP_CIDR "10.8.0.2/30"

////// for free LTE
#define TUN_MTU 1400
#define TCP_MSS 1360
#define OUTER_IP_TCP_HEADER_LEN 40
#define RAW_OUTER_MAX_LEN (TUN_MTU + OUTER_IP_TCP_HEADER_LEN)
#define RAW_TTL 64
#define CLIENT_NFQUEUE_NUM 33
#define TCP_LEARN_MARKER 'L'

struct ClientRawConfig
{
    uint32_t local_ip;
    uint32_t proxy_ip;
    uint16_t local_port;
    uint16_t proxy_port;
};

struct ClientReadyState
{
    std::string client_nonce;
    std::string proxy_nonce;

    bool registered = false;
    bool proxy_ready_ack_received = false;
    bool ready_done = false;
    bool stop_received = false;
    bool proxy_learn_ready_received = false;

    mutable std::mutex lock;
};

struct ClientControlAckState
{
    uint32_t ip_src = 0;
    uint32_t ip_dst = 0;
    uint16_t tcp_src = 0;
    uint16_t tcp_dst = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    bool learned = false;
};

struct ClientTunnelState
{
    std::atomic<int> tun_fd;
    std::atomic<bool> nfqueue_ready;
    std::atomic<bool> data_plane_ready;
    std::atomic<bool> session_stop;
    std::atomic<bool> session_error;

    ClientControlAckState control_ack;

    ClientTunnelState()
        : tun_fd(-1),
          nfqueue_ready(false),
          data_plane_ready(false),
          session_stop(false),
          session_error(false)
    {
    }
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





/////// for free LTE

// tcp/udp socket
int open_client_ready_socket();

// udp
bool run_client_udp_register(int udp_fd, const char* proxy_ip, uint16_t ready_port, ClientReadyState& state, std::atomic<bool>& stop);
bool run_client_ready_handshake(int udp_fd, const char* proxy_ip, uint16_t ready_port, ClientReadyState& state, std::atomic<bool>& stop);
void send_client_udp_stop(int udp_fd, const char* proxy_ip, uint16_t ready_port, const ClientReadyState& state);
bool wait_for_stop_request(std::atomic<bool>& session_stop, std::atomic<bool>& session_error);
void client_udp_control_loop(int udp_fd, ClientReadyState& state, ClientTunnelState& tunnel_state, std::atomic<bool>& stop);
bool wait_for_proxy_learn_ready(ClientReadyState& state, std::atomic<bool>& stop);

// raw socket
bool init_client_raw_config(const char* proxy_ip, uint16_t proxy_port, int proxy_fd, ClientRawConfig& config);
int open_raw_send_socket();
void tun_to_raw_loop(int tun_fd, int raw_send_fd, const ClientRawConfig& config, const FakeBase& fake_base, RawSendState& send_state, std::atomic<bool>& stop);

// tcp control socket & learning
bool set_tcp_keepalive(int sock, int idle, int interval, int count);
bool get_socket_local_tuple(int sock, uint32_t& local_ip, uint16_t& local_port);

// learning
bool install_client_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num);
void cleanup_client_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num);
bool learn_client_tcp_base_with_nfqueue(uint16_t queue_num, int proxy_fd, const ClientRawConfig& config, RealBase& real_base, FakeBase& fake_base, ClientControlAckState& control_ack, std::atomic<bool>& stop);

// final nfqueue rule
bool install_client_tunnel_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num);
void cleanup_client_tunnel_nfqueue_rule(const ClientRawConfig& config, uint16_t queue_num);
void client_tunnel_nfqueue_loop(uint16_t queue_num, const ClientRawConfig& config, ClientTunnelState& tunnel_state, std::atomic<bool>& stop);

#endif
// CLIENT_H