#ifndef ISN_GENERATOR_H
#define ISN_GENERATOR_H
#include <string>
#include <vector>
#include <cstdint>

class ISNGenerator
{
public:
          ISNGenerator(std::string csv_path, int time_factor = 6);

          // Returns current real time in nanoseconds since epoch
          long long get_real_time_ns() const;

          // Load CSV from `path` into `out_vec` (port -> {isn, timestamp})
          bool load_results_csv(const std::string &path, std::vector<std::pair<uint32_t, long long>> &out_vec);

          // Generate an ISN for given source port using loaded CSV results
          uint32_t generate_isn(int src_port) const;

          // Generate an ISN for given source port and timestamp using loaded CSV results
          uint32_t generate_isn(int src_port, long long timestamp) const;

          // Initiate a simple TCP handshake from `src_port` to `dst_ip:dst_port`
          // `dst_ip` and `dst_port` may be provided; implementation may provide defaults.
          void initiate_tcp_handshake_ipv4(int src_port, const std::string &dst_ip, int dst_port);
          void initiate_tcp_handshake_ipv6(int src_port, const std::string &dst_ip, int dst_port);

private:
          int TIME_FACTOR = 6;
          std::string CSV_PATH;
          std::vector<std::pair<uint32_t, long long>> ports_isns;
};

#endif // ISN_GENERATOR_H
