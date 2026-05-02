#include <iostream>
#include <cstring>
#include <pcap.h>
#include <thread>
#include <queue>
#include <mutex>
#include <vector>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

using namespace std;

const int PORT = 9999;
const char *MY_MAC = nullptr;
char *INTERFACE = nullptr; // nullptr is the deafult
// char *INTERFACE = "lo";
// Thread-safe queue for ISN data
char *victim_ip = nullptr;
struct ISNEntry
{
          int source_port;
          uint32_t isn;
};

queue<ISNEntry> isn_queue;
mutex queue_mutex;

void init()
{
          printf("capturing initialized (Linux libpcap version).\n");
}

void sends_isns(int listen_port)
{
          int server_fd, client_fd;
          struct sockaddr_in address, client_addr;
          socklen_t addrlen = sizeof(client_addr);

          // Create socket
          server_fd = socket(AF_INET, SOCK_STREAM, 0);
          if (server_fd == -1)
          {
                    fprintf(stderr, "ERROR creating server socket\n");
                    return;
          }

          // Set socket options
          int opt = 1;
          setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

          // Bind socket
          address.sin_family = AF_INET;
          address.sin_addr.s_addr = INADDR_ANY;
          address.sin_port = htons(listen_port);

          if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1)
          {
                    fprintf(stderr, "ERROR binding server socket: %s\n", strerror(errno));
                    close(server_fd);
                    return;
          }

          // Listen for connections
          if (listen(server_fd, 3) == -1)
          {
                    fprintf(stderr, "ERROR listening on socket\n");
                    close(server_fd);
                    return;
          }

          printf("capturing server listening on port %d\n", listen_port);

          // Accept client connection
          client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
          if (client_fd == -1)
          {
                    fprintf(stderr, "ERROR accepting connection\n");
                    close(server_fd);
                    return;
          }

          printf("Client connected to capturing server.\n");
          victim_ip = inet_ntoa(client_addr.sin_addr);
          // Send ISN data from queue
          while (true)
          {
                    ISNEntry entry;
                    bool has_data = false;

                    {
                              lock_guard<mutex> lock(queue_mutex);
                              if (!isn_queue.empty())
                              {
                                        entry = isn_queue.front();
                                        isn_queue.pop();
                                        has_data = true;
                              }
                    }

                    if (has_data)
                    {
                              // Format: "port:isn\n"
                              char buffer[256];
                              snprintf(buffer, sizeof(buffer), "%d:%u\n", entry.source_port, entry.isn);

                              ssize_t sent = send(client_fd, buffer, strlen(buffer), 0);
                              if (sent == -1)
                              {
                                        fprintf(stderr, "ERROR sending data to client\n");
                                        break;
                              }

                              printf("Sent: %s", buffer);
                    }
                    else
                    {
                              usleep(10000); // Sleep 10ms
                    }
          }

          close(client_fd);
          close(server_fd);
          printf("capturing server closed.\n");
}

void extract_isn_and_port(const char *packet_data, int packet_len, int &src_port, uint32_t &isn)
{
          // Extract TCP source port and ISN from packet
          // Assuming IP header is 20 bytes (simplified)
          if (packet_len < 40) // IP header + TCP header minimum
                    return;

          // Skip IP header (assuming 20 bytes for now)
          const unsigned char *tcp_header = (const unsigned char *)(packet_data + 20);

          // Extract source port (bytes 0-1 of TCP header)
          src_port = (tcp_header[0] << 8) | tcp_header[1];

          // Extract sequence number / ISN (bytes 4-7 of TCP header)
          isn = (tcp_header[4] << 24) | (tcp_header[5] << 16) | (tcp_header[6] << 8) | tcp_header[7];
}

void sniff()
{
          char errbuf[PCAP_ERRBUF_SIZE];
          pcap_t *handle;
          struct pcap_pkthdr header;
          const u_char *packet;
          struct bpf_program fp;

          // Find default network device
          char *dev = pcap_lookupdev(errbuf);
          if (dev == NULL)
          {
                    fprintf(stderr, "ERROR finding device: %s\n", errbuf);
                    return;
          }
          if (INTERFACE != nullptr)
          {
                    dev = INTERFACE;
          }
          printf("Sniffing on device: %s\n", dev);

          // Open device for sniffing
          handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
          if (handle == NULL)
          {
                    fprintf(stderr, "ERROR opening device: %s\n", errbuf);
                    return;
          }
          // Cache link-layer type (e.g., Ethernet)
          int linktype = pcap_datalink(handle);

          // Compile and apply BPF filter for TCP packets to target IP
          char filter_exp[256];
          snprintf(filter_exp, sizeof(filter_exp), "tcp");
          if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
          {
                    fprintf(stderr, "ERROR compiling filter: %s\n", pcap_geterr(handle));
                    pcap_close(handle);
                    return;
          }

          if (pcap_setfilter(handle, &fp) == -1)
          {
                    fprintf(stderr, "ERROR setting filter: %s\n", pcap_geterr(handle));
                    pcap_close(handle);
                    return;
          }

          printf("Filter applied: %s\n", filter_exp);
          printf("Starting packet sniffer...\n");

          // Sniff packets
          while (true)
          {
                    packet = pcap_next(handle, &header);
                    // printf("Captured a packet with length of [%d]\n", header.len);
                    if (packet == NULL)
                              continue;

                    // Determine IP header offset if capturing on Ethernet
                    size_t ip_offset = 0;
                    if (linktype == DLT_EN10MB)
                    {
                              if (header.len < 14)
                                        continue;
                              uint16_t ethertype = (uint16_t)((packet[12] << 8) | packet[13]);
                              if (ethertype == 0x8100)
                              {
                                        // VLAN-tagged: EtherType after 4 bytes
                                        if (header.len < 18)
                                                  continue;
                                        ethertype = (uint16_t)((packet[16] << 8) | packet[17]);
                                        ip_offset = 18;
                              }
                              else
                              {
                                        ip_offset = 14;
                              }
                              if (ethertype != 0x0800)
                                        continue; // Not IPv4
                    }
                    // Parse IP header
                    if (header.len < ip_offset + 20)
                              continue;
                    struct ip *ip_hdr = (struct ip *)(packet + ip_offset);
                    int ip_hdr_len = ip_hdr->ip_hl * 4;

                    // prints the source IP
                    char src_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
                    char dst_mac[18];
                    snprintf(dst_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                             packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
                    // printf("src ip: %s, dst mac: %s\n", src_ip, dst_mac);
                    if (victim_ip == nullptr || strcmp(src_ip, victim_ip) != 0 || (MY_MAC != nullptr && strcmp(dst_mac, MY_MAC) != 0))
                    {
                              continue;
                    }
                    // printf("Source IP: %s\n", src_ip);
                    // printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
                    // Check if it's TCP
                    if (ip_hdr->ip_p != IPPROTO_TCP)
                              continue;

                    if (header.len < ip_offset + ip_hdr_len + 20)
                              continue;

                    // Parse TCP header
                    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ip_offset + ip_hdr_len);
                    int src_port = ntohs(tcp_hdr->th_sport);
                    uint32_t seq_num = ntohl(tcp_hdr->th_seq);
                    unsigned char tcp_flags = tcp_hdr->th_flags;

                    // Check for SYN flag
                    if (tcp_flags & TH_SYN)
                    {
                              // printf("----\n");
                              // printf("packet dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                              //        packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
                              printf("Captured SYN packet: src_port=%d, ISN=%u\n", src_port, seq_num);

                              // Add to queue
                              ISNEntry entry = {src_port, seq_num};
                              {
                                        lock_guard<mutex> lock(queue_mutex);
                                        isn_queue.push(entry);
                              }
                    }
          }

          pcap_freecode(&fp);
          pcap_close(handle);
}

int main(int argc, char **argv)
{
          init();

          thread sniff_thread(sniff);
          thread sends_isns_thread(sends_isns, PORT);

          sniff_thread.join();
          sends_isns_thread.join();

          return 0;
}