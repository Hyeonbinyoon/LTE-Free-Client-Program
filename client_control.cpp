#include "client.h"

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <sstream>
#include <unistd.h>
#include <sys/select.h>

volatile std::sig_atomic_t g_signal_stop = 0;

void handle_signal(int)
{
    g_signal_stop = 1;
}

bool wait_for_stop_request()
{
    while(!g_signal_stop)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
        if(ret > 0 && FD_ISSET(STDIN_FILENO, &rfds))
        {
            char ch;
            if(read(STDIN_FILENO, &ch, 1) >= 0)
                return true;
        }
        else if(ret < 0)
        {
            if(errno == EINTR)
                continue;

            perror("select");
            return false;
        }
    }

    return true;
}

bool run_cmd(const std::string& cmd)
{
    int ret = std::system(cmd.c_str());
    if(ret != 0)
    {
        std::fprintf(stderr, "command failed: %s\n", cmd.c_str());
        return false;
    }

    return true;
}

bool add_route(RouteSnapshot& route, const std::string& cidr)
{
    std::string cmd = "ip route add " + cidr +
                      " via " + route.gateway +
                      " dev " + route.ifname;

    if(!run_cmd(cmd))
        return false;

    route.added_routes.push_back(cidr);
    return true;
}

void cleanup_routes(const RouteSnapshot& route)
{
    for(const std::string& cidr : route.added_routes)
    {
        std::string cmd = "ip route del " + cidr +
                          " via " + route.gateway +
                          " dev " + route.ifname;

        run_cmd(cmd);
    }
}

bool load_default_route(RouteSnapshot& route)
{
    FILE* fp = popen("ip route show default", "r");
    if(fp == nullptr)
    {
        perror("popen ip route show default");
        return false;
    }

    std::array<char, 512> buf{};
    if(fgets(buf.data(), static_cast<int>(buf.size()), fp) == nullptr)
    {
        pclose(fp);
        std::fprintf(stderr, "failed to read default route\n");
        return false;
    }

    int ret = pclose(fp);
    if(ret == -1)
    {
        perror("pclose");
        return false;
    }

    std::string line(buf.data());
    std::istringstream iss(line);
    std::string token;

    while(iss >> token)
    {
        if(token == "via")
        {
            iss >> route.gateway;
        }
        else if(token == "dev")
        {
            iss >> route.ifname;
        }
        else if(token == "src")
        {
            iss >> route.src;
        }
    }

    if(route.gateway.empty() || route.ifname.empty())
    {
        std::fprintf(stderr, "invalid default route: %s\n", line.c_str());
        return false;
    }

    return true;
}

bool replace_default_route_to_tun(RouteSnapshot& route, const std::string& tun_name)
{
    std::string cmd = "ip route replace default dev " + tun_name;

    if(!run_cmd(cmd))
        return false;

    route.default_route_changed = true;
    return true;
}

void restore_default_route(const RouteSnapshot& route)
{
    if(!route.default_route_changed)
        return;

    std::string cmd = "ip route replace default via " + route.gateway +
                      " dev " + route.ifname;

    if(!route.src.empty())
    {
        cmd += " src " + route.src;
    }

    run_cmd(cmd);
}
