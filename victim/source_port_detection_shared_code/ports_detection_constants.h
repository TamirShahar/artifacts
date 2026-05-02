#ifndef CONSTANTS_H
#define CONSTANTS_H

#define START_PORT 32768
#define END_PORT 61000

#define TOTAL_PORTS 65536             // Total number of ports (0-65535)
#define LINUX_BIND0ITERATIONS 3e5     // Number of iterations for random port scanning
#define WINDOWS_BIND0ITERATIONS 66000 // Number of iterations for random port scanning

#define PROC_NET_UDP "/proc/net/udp"
#define PROC_NET_TCP "/proc/net/tcp"
#define PROC_NET_TCP6 "/proc/net/tcp6"
#define EXPERIMENTS_REPETITIONS 5000
// #define NUM_ITER_IN_PERIOD 5

// Protocol types
#define PROTOCOL_UDP 0
#define PROTOCOL_TCP 1

// website data
#define WEBSITE_IP "192.0.2.123"
#define WEBSITE_DSTPORT 80
// for android bind(p+2),...bind(p+16)
#define UPDATE_CORRECT_PORT_RATE 100

#endif // CONSTANTS_H
