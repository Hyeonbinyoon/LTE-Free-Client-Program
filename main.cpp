#include "client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <atomic>
#include <thread>
#include <string>
#include <functional>
#include <unistd.h>
#include <sys/socket.h>

static bool parse_port(const char* s, uint16_t& port)
{
    if(s == nullptr || s[0] == '\0')
        return false;

    char* end = nullptr;
    unsigned long value = std::strtoul(s, &end, 10);

    if(end == s || *end != '\0')
        return false;

    if(value == 0 || value > 65535)
        return false;

    port = static_cast<uint16_t>(value);
    return true;
}

static void usage(const char* prog)
{
    std::fprintf(stderr, "usage: %s <proxy-ip> <port>\n", prog);
    std::fprintf(stderr, "sample: %s 172.30.1.64 3502\n", prog);
}

int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        usage(argv[0]);
        return 1;
    }

    const char* proxy_ip = argv[1];

    uint16_t proxy_port = 0;
    if(!parse_port(argv[2], proxy_port))
    {
        std::fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    int exit_code = 1;

    std::atomic<bool> stop(false);

    int proxy_fd = -1;
    int udp_fd = -1;
    int tun_fd = -1;
    int raw_send_fd = -1;

    bool learning_rule_installed = false;
    bool tunnel_rule_installed = false;
    bool tunnel_thread_started = false;
    bool udp_control_thread_started = false;
    bool raw_thread_started = false;

    RouteSnapshot route;
    ClientRawConfig raw_config;
    ClientReadyState ready_state;
    ClientTunnelState tunnel_state;
    RealBase real_base;
    FakeBase fake_base;
    RawSendState raw_send_state;
    std::string proxy_route;

    std::thread tunnel_thread;
    std::thread udp_control_thread;
    std::thread raw_thread;

    proxy_fd = connect_proxy(proxy_ip, proxy_port);
    if(proxy_fd < 0)
    {
        std::fprintf(stderr, "failed to connect proxy\n");
        goto cleanup;
    }

    udp_fd = open_client_ready_socket();
    if(udp_fd < 0)
    {
        std::fprintf(stderr, "failed to open UDP ready socket\n");
        goto cleanup;
    }

    if(!init_client_raw_config(proxy_ip, proxy_port, proxy_fd, raw_config))
    {
        std::fprintf(stderr, "failed to initialize raw config\n");
        goto cleanup;
    }

    if(!run_client_udp_register(udp_fd, proxy_ip, proxy_port, ready_state, stop))
    {
        std::fprintf(stderr, "failed to complete UDP register\n");
        goto cleanup;
    }

    udp_control_thread = std::thread(client_udp_control_loop, udp_fd, std::ref(ready_state), std::ref(tunnel_state), std::ref(stop));
    udp_control_thread_started = true;

    if(!wait_for_proxy_learn_ready(ready_state, stop))
    {
        std::fprintf(stderr, "[MAIN] failed to wait for PROXY_LEARN_READY\n");
        goto cleanup;
    }

    if(!install_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM))
    {
        std::fprintf(stderr, "failed to install client learning NFQUEUE rule\n");
        goto cleanup;
    }

    learning_rule_installed = true;

    if(!learn_client_tcp_base_with_nfqueue(CLIENT_NFQUEUE_NUM, proxy_fd, raw_config, real_base, fake_base, tunnel_state.control_ack, stop))
    {
        std::fprintf(stderr, "failed to learn TCP real/fake base\n");
        goto cleanup;
    }

    if(!real_base.learned || !fake_base.initialized || !tunnel_state.control_ack.learned)
    {
        std::fprintf(stderr, "base learning state is invalid\n");
        goto cleanup;
    }

    std::printf("[MAIN] realBase learned: client_seq=%u proxy_seq=%u\n", real_base.client_seq, real_base.proxy_seq);
    std::printf("[MAIN] fakeBase initialized: fake_client_seq=%u fake_proxy_seq=%u\n", fake_base.fake_client_seq, fake_base.fake_proxy_seq);

    if(learning_rule_installed)
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        learning_rule_installed = false;
    }

    if(!install_client_tunnel_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM))
    {
        std::fprintf(stderr, "failed to install client tunnel NFQUEUE rule\n");
        goto cleanup;
    }

    tunnel_rule_installed = true;

    tunnel_thread = std::thread(client_tunnel_nfqueue_loop, CLIENT_NFQUEUE_NUM, std::cref(raw_config), std::ref(tunnel_state), std::ref(stop));
    tunnel_thread_started = true;

    while(!g_signal_stop &&
          !stop.load() &&
          !tunnel_state.session_stop.load() &&
          !tunnel_state.session_error.load() &&
          !tunnel_state.nfqueue_ready.load())
    {
        usleep(10 * 1000);
    }

    if(g_signal_stop || stop.load() || tunnel_state.session_stop.load() || tunnel_state.session_error.load())
        goto cleanup;

    if(!tunnel_state.nfqueue_ready.load())
    {
        std::fprintf(stderr, "client tunnel NFQUEUE loop is not ready\n");
        goto cleanup;
    }

    if(!run_client_ready_handshake(udp_fd, proxy_ip, proxy_port, ready_state, stop))
    {
        std::fprintf(stderr, "failed to complete UDP ready handshake\n");
        goto cleanup;
    }

    if(!ready_state.ready_done)
    {
        std::fprintf(stderr, "UDP ready state is invalid\n");
        goto cleanup;
    }

    std::printf("[MAIN] UDP ready handshake done. settling before data plane start\n");

    for(int i = 0; i < 100; ++i)
    {
        if(g_signal_stop || stop.load() || tunnel_state.session_stop.load() || tunnel_state.session_error.load())
            goto cleanup;

        usleep(100 * 1000);
    }

    tun_fd = tun_alloc(CLIENT_TUN_NAME);
    if(tun_fd < 0)
    {
        std::fprintf(stderr, "failed to allocate tunC\n");
        goto cleanup;
    }

    if(!setup_tun_interface(CLIENT_TUN_NAME))
    {
        std::fprintf(stderr, "failed to setup tunC\n");
        goto cleanup;
    }

    if(!set_nonblocking(tun_fd))
    {
        std::fprintf(stderr, "failed to set tunC nonblocking\n");
        goto cleanup;
    }

    if(!load_default_route(route))
    {
        std::fprintf(stderr, "failed to load default route\n");
        goto cleanup;
    }

    std::printf("default gateway : %s\n", route.gateway.c_str());
    std::printf("default ifname  : %s\n", route.ifname.c_str());
    std::printf("default src     : %s\n", route.src.c_str());

    proxy_route = std::string(proxy_ip) + "/32";
    if(!add_route(route, proxy_route))
    {
        std::fprintf(stderr, "failed to add proxy route exception\n");
        goto cleanup;
    }

    if(!replace_default_route_to_tun(route, CLIENT_TUN_NAME))
    {
        std::fprintf(stderr, "failed to replace default route to tunC\n");
        goto cleanup;
    }

    if(stop.load() || tunnel_state.session_stop.load() || tunnel_state.session_error.load())
        goto cleanup;

    raw_send_fd = open_raw_send_socket();
    if(raw_send_fd < 0)
    {
        std::fprintf(stderr, "failed to open raw send socket\n");
        goto cleanup;
    }

    tunnel_state.tun_fd.store(tun_fd);
    tunnel_state.data_plane_ready.store(true);

    raw_thread = std::thread(tun_to_raw_loop, tun_fd, raw_send_fd, std::cref(raw_config), std::cref(fake_base), std::ref(raw_send_state), std::ref(stop));
    raw_thread_started = true;

    std::printf("client tunnel data plane started\n");
    std::printf("press Enter or Ctrl+C to stop\n");

    if(!wait_for_stop_request(tunnel_state.session_stop, tunnel_state.session_error))
    {
        std::fprintf(stderr, "client stopped by session error\n");
        goto cleanup;
    }

    exit_code = 0;

cleanup:
    if(udp_fd >= 0 && ready_state.registered && !tunnel_state.session_stop.load())
        send_client_udp_stop(udp_fd, proxy_ip, proxy_port, ready_state);

    stop.store(true);
    tunnel_state.session_stop.store(true);
    tunnel_state.data_plane_ready.store(false);

    if(raw_thread_started && raw_thread.joinable())
        raw_thread.join();

    restore_default_route(route);
    cleanup_routes(route);

    if(tunnel_rule_installed)
    {
        cleanup_client_tunnel_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        tunnel_rule_installed = false;
    }

    if(learning_rule_installed)
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        learning_rule_installed = false;
    }

    if(tunnel_thread_started && tunnel_thread.joinable())
        tunnel_thread.join();

    if(udp_control_thread_started && udp_control_thread.joinable())
        udp_control_thread.join();

    if(raw_send_fd >= 0)
    {
        close(raw_send_fd);
        raw_send_fd = -1;
    }

    if(tun_fd >= 0)
    {
        close(tun_fd);
        tun_fd = -1;
    }

    if(proxy_fd >= 0)
    {
        close(proxy_fd);
        proxy_fd = -1;
    }

    if(udp_fd >= 0)
    {
        close(udp_fd);
        udp_fd = -1;
    }

    if(exit_code == 0)
        std::printf("client stopped\n");
    else
        std::fprintf(stderr, "client stopped with error\n");

    return exit_code;
}