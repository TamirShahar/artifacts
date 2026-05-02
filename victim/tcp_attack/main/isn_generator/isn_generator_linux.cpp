#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <thread>
#include <vector>
#include <numeric>
#include <atomic>
#include <mutex>
#include <ctime>
#include "isnGenerator.h"

const int MAC_TIME_FACTOR_ISN = 7;

ISNGenerator::ISNGenerator(std::string csv_path, int time_factor) : TIME_FACTOR(time_factor), CSV_PATH(std::move(csv_path))
{
    printf("csv path: %s\n", CSV_PATH.c_str());
    if (load_results_csv(CSV_PATH, ports_isns))
    {
        printf("Loaded ISN data from %s successfully!\n", CSV_PATH.c_str());
    }
    else
    {
        printf("Failed to load ISN data from %s!\n", CSV_PATH.c_str());
        exit(EXIT_FAILURE);
    }
}

long long ISNGenerator::get_real_time_ns() const
{
    struct timespec ts;
    if (TIME_FACTOR == MAC_TIME_FACTOR_ISN)
    {
        // for mac, we need to use mach_absolute_time which is in ticks, and convert it to ns using mach_timebase_info
        // but for simplicity, we can just use clock_gettime with CLOCK_MONOTONIC_RAW which is not affected by NTP adjustments
        // and has a similar resolution to mach_absolute_time
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
        return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

bool ISNGenerator::load_results_csv(const std::string &path, std::vector<std::pair<uint32_t, long long>> &out_vec)
{
    std::ifstream in(path);
    if (!in)
        return false;
    std::string line;
    // skip header
    if (!std::getline(in, line))
        return false;
    std::vector<std::pair<uint32_t, long long>> tmp;
    while (std::getline(in, line))
    {
        if (line.empty())
            continue;
        // expect port,isn,timestamp
        std::stringstream ss(line);
        std::string portstr, isnstr, tsstr;
        if (!std::getline(ss, portstr, ','))
            continue;
        if (!std::getline(ss, isnstr, ','))
            continue;
        if (!std::getline(ss, tsstr))
            tsstr = "";
        int port = 0;
        try
        {
            port = std::stoi(portstr);
        }
        catch (...)
        {
            continue;
        }
        uint32_t val = UINT32_MAX;
        long long ts = -1;
        if (isnstr != "ERROR")
        {
            try
            {
                val = static_cast<uint32_t>(std::stoul(isnstr));
            }
            catch (...)
            {
                val = UINT32_MAX;
            }
        }
        if (!tsstr.empty() && tsstr != "ERROR")
        {
            try
            {
                ts = std::stoll(tsstr);
            }
            catch (...)
            {
                ts = -1;
            }
        }
        if ((size_t)port >= tmp.size())
            tmp.resize(port + 1, {UINT32_MAX, -1});
        tmp[port] = {val, ts};
    }
    out_vec = std::move(tmp);
    return true;
}

uint32_t ISNGenerator::generate_isn(int src_port) const
{
    return generate_isn(src_port, get_real_time_ns());
}

uint32_t ISNGenerator::generate_isn(int src_port, long long current_timestamp) const
{
    if (src_port < 0 || (size_t)src_port >= ports_isns.size())
        return 0;
    uint32_t stored_isn = ports_isns[src_port].first;
    long long timestamp = ports_isns[src_port].second;
    if (stored_isn == UINT32_MAX || timestamp == -1)
    {
        return 0;
    }
    uint32_t hash_val = (stored_isn - (timestamp >> TIME_FACTOR)) & 0xFFFFFFFF;
    if (hash_val == 0)
    {
        std::cerr << "secret hash is still 0" << std::endl;
        return 0;
    }
    uint32_t isn = (hash_val + (current_timestamp >> TIME_FACTOR));
    return isn;
}

void ISNGenerator::initiate_tcp_handshake_ipv4(int src_port, const std::string &dst_ip, int dst_port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return;
    }

    // options for close(socket) - prevent the TIME_WAIT behaviour
    struct linger lin;
    lin.l_onoff = 1;
    lin.l_linger = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)) < 0)
    {
        perror("setsockopt SO_LINGER failed");
        close(sock);
        return;
    }

    // Bind to the requested source port
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(static_cast<uint16_t>(src_port));
    if (bind(sock, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)) < 0)
    {
        perror("bind failed");
        close(sock);
        return;
    }

    // configure server's socket
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(static_cast<uint16_t>(dst_port));
    if (inet_pton(AF_INET, dst_ip.c_str(), &server.sin_addr) != 1)
    {
        std::cerr << "Invalid destination IP: " << dst_ip << std::endl;
        close(sock);
        return;
    }

    long long ts = get_real_time_ns();
    if (connect(sock, reinterpret_cast<sockaddr *>(&server), sizeof(server)) < 0)
    {
        perror("connect failed");
        close(sock);
        return;
    }

    std::cout << "Connected from src port " << src_port << " to " << dst_ip << ":" << dst_port << " at ts=" << ts << std::endl;
    close(sock);
}

void ISNGenerator::initiate_tcp_handshake_ipv6(int src_port, const std::string &dst_ip, int dst_port)
{
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return;
    }

    // options for close(socket) - prevent the TIME_WAIT behaviour
    struct linger lin;
    lin.l_onoff = 1;
    lin.l_linger = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)) < 0)
    {
        perror("setsockopt SO_LINGER failed");
        close(sock);
        return;
    }

    // Bind to the requested source port
    sockaddr_in6 local_addr{};
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_addr = in6addr_any;
    local_addr.sin6_port = htons(static_cast<uint16_t>(src_port));
    if (bind(sock, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)) < 0)
    {
        perror("bind failed");
        close(sock);
        return;
    }

    // configure server's socket
    sockaddr_in6 server{};
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(static_cast<uint16_t>(dst_port));
    if (inet_pton(AF_INET6, dst_ip.c_str(), &server.sin6_addr) != 1)
    {
        std::cerr << "Invalid destination IPv6: " << dst_ip << std::endl;
        close(sock);
        return;
    }

    long long ts = get_real_time_ns();
    if (connect(sock, reinterpret_cast<sockaddr *>(&server), sizeof(server)) < 0)
    {
        perror("connect failed");
        close(sock);
        return;
    }

    std::cout << "Connected from src port " << src_port << " to " << dst_ip << ":" << dst_port << " at ts=" << ts << std::endl;
    close(sock);
}
