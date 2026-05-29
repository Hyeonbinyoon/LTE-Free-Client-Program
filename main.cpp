#include "client.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <atomic>
#include <thread>
#include <string>
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

    std::atomic<bool> stop(false);

    int proxy_fd = -1;
    int tun_fd = -1;
    int raw_send_fd = -1;

    bool nfqueue_rule_installed = false;
    bool raw_thread_started = false;

    RouteSnapshot route;
    ClientRawConfig raw_config;
    RealBase real_base;
    FakeBase fake_base;
    RawSendState raw_send_state;

    std::thread raw_thread;


    /*
     * 1. TCP connect
     *
     * connect_proxy() 내부에서:
     * - TCP_MSS 설정
     * - connect()
     * - kernel TCP keepalive 설정
     */
    proxy_fd = connect_proxy(proxy_ip, proxy_port);
    if(proxy_fd < 0)
    {
        std::fprintf(stderr, "failed to connect proxy\n");
        return 1;
    }

    /*
     * 2. raw config 초기화
     *
     * control TCP socket의 실제 local IP/local port를 얻고,
     * proxy IP/port를 함께 저장한다.
     */
    if(!init_client_raw_config(proxy_ip, proxy_port, proxy_fd, raw_config))
    {
        std::fprintf(stderr, "failed to initialize raw config\n");
        close(proxy_fd);
        return 1;
    }

    /*
     * 3. NFQUEUE learning rule 설치
     *
     * Proxy -> Client 방향의 control TCP packet을 NFQUEUE로 보낸다.
     * learning packet은 callback에서 NF_ACCEPT된다.
     */
    if(!install_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM))
    {
        std::fprintf(stderr, "failed to install client NFQUEUE rule\n");
        close(proxy_fd);
        return 1;
    }

    nfqueue_rule_installed = true;

    /*
     * 4. realBase/fakeBase 학습
     *
     * Client는 Proxy -> Client keepalive ACK를 관찰한다.
     *
     * expected:
     *   seq = P + 1
     *   ack = C + 1
     *
     * learned:
     *   realBase.client_seq = C
     *   realBase.proxy_seq  = P
     *
     * initialized:
     *   fakeBase.fake_client_seq = C + 1
     *   fakeBase.fake_proxy_seq  = P + 1
     */
    if(!learn_client_tcp_base_with_nfqueue(CLIENT_NFQUEUE_NUM,
                                           raw_config,
                                           real_base,
                                           fake_base,
                                           stop))
    {
        std::fprintf(stderr, "failed to learn TCP real/fake base\n");

        if(nfqueue_rule_installed)
            cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);

        close(proxy_fd);
        return 1;
    }

    if(!real_base.learned || !fake_base.initialized)
    {
        std::fprintf(stderr, "base learning state is invalid\n");

        if(nfqueue_rule_installed)
            cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);

        close(proxy_fd);
        return 1;
    }

    std::printf("[MAIN] realBase learned: client_seq=%u proxy_seq=%u\n",
                real_base.client_seq,
                real_base.proxy_seq);

    std::printf("[MAIN] fakeBase initialized: fake_client_seq=%u fake_proxy_seq=%u\n",
                fake_base.fake_client_seq,
                fake_base.fake_proxy_seq);
if(nfqueue_rule_installed)
{
    cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
    nfqueue_rule_installed = false;
}
    /*
     * 5. tunC 생성/설정
     *
     * fakeBase 학습이 끝난 뒤에 tunC를 만들고 route를 넘긴다.
     */
    tun_fd = tun_alloc(CLIENT_TUN_NAME);
    if(tun_fd < 0)
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(proxy_fd);
        return 1;
    }

    if(!setup_tun_interface(CLIENT_TUN_NAME))
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(tun_fd);
        close(proxy_fd);
        return 1;
    }

    if(!set_nonblocking(tun_fd))
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(tun_fd);
        close(proxy_fd);
        return 1;
    }

    /*
     * 6. route 준비
     *
     * 현재 default route를 저장한다.
     * Proxy IP는 tunnel 밖 원래 경로로 나가야 하므로 /32 예외 route를 추가한다.
     */
    if(!load_default_route(route))
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(tun_fd);
        close(proxy_fd);
        return 1;
    }

    std::printf("default gateway : %s\n", route.gateway.c_str());
    std::printf("default ifname  : %s\n", route.ifname.c_str());
    std::printf("default src     : %s\n", route.src.c_str());

    std::string proxy_route = std::string(proxy_ip) + "/32";
    if(!add_route(route, proxy_route))
    {
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(tun_fd);
        close(proxy_fd);
        return 1;
    }

    if(!replace_default_route_to_tun(route, CLIENT_TUN_NAME))
    {
        cleanup_routes(route);
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(tun_fd);
        close(proxy_fd);
        return 1;
    }

    /*
     * 7. raw send socket 생성
     */
    raw_send_fd = open_raw_send_socket();
    if(raw_send_fd < 0)
    {
        restore_default_route(route);
        cleanup_routes(route);
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);
        close(tun_fd);
        close(proxy_fd);
        return 1;
    }

    /*
     * 8. raw send loop 시작
     *
     * fakeBase는 이미 initialized 상태
     */
    raw_thread = std::thread(tun_to_raw_loop,
                             tun_fd,
                             raw_send_fd,
                             std::cref(raw_config),
                             std::cref(fake_base),
                             std::ref(raw_send_state),
                             std::ref(stop));

    raw_thread_started = true;

    std::printf("client raw send thread started\n");
    std::printf("press Enter or Ctrl+C to stop\n");

    wait_for_stop_request();

    /*
     * cleanup
     */
    stop.store(true);

    restore_default_route(route);
    cleanup_routes(route);

    if(nfqueue_rule_installed)
        cleanup_client_nfqueue_rule(raw_config, CLIENT_NFQUEUE_NUM);

    if(proxy_fd >= 0)
        shutdown(proxy_fd, SHUT_RDWR);

    if(raw_thread_started && raw_thread.joinable())
        raw_thread.join();

    if(raw_send_fd >= 0)
        close(raw_send_fd);

    if(tun_fd >= 0)
        close(tun_fd);

    if(proxy_fd >= 0)
        close(proxy_fd);

    std::printf("client stopped\n");

    return 0;
}