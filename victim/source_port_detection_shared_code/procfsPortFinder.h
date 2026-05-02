
#ifndef PROCFS_PORT_FINDER_H
#define PROCFS_PORT_FINDER_H

#include "portFinderBase.h"
class ProcfsPortsFinder : public PortFinderBase
{
public:
    ProcfsPortsFinder(int protocol, bool ipv6 = false);
    ~ProcfsPortsFinder();
    long long get_last_timestamp() const
    {
        return last_timestamp_;
    }

protected:
    void updatePortsImpl() override;

private:
    // FILE *fp_ = nullptr; // File pointer for /proc/net/udp or /proc
    int fp_ = -1; // File descriptor for /proc/net/udp or /proc
    int last_number_of_established_ = 0;
    long long last_timestamp_ = 0;
};

#endif // PROCFS_PORT_FINDER_H
