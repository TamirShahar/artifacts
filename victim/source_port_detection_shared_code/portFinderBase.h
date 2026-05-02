#ifndef PORT_FINDER_BASE_H
#define PORT_FINDER_BASE_H

#include <chrono>
#include <iostream>
#include <cstring> // for memcpy
#include <cstdio>  // for printf
#include <queue>
#include "ports_detection_constants.h"

class PortFinderBase
{
private:
    std::queue<int> ports_queue = std::queue<int>();

protected:
    int current_status[TOTAL_PORTS] = {0};
    int previous_status[TOTAL_PORTS] = {0};
    int protocol_;                      // 0 for UDP, 1 for TCP
    virtual void updatePortsImpl() = 0; // pure virtual

public:
    PortFinderBase(int protocol) : protocol_(protocol) {}

    void init()
    {
        updatePortsImpl();
        memcpy(previous_status, current_status, sizeof(previous_status));
        clear_queue();
    }
    virtual ~PortFinderBase() = default;
    void printPortsChanges()
    {
        for (int i = 1; i < TOTAL_PORTS; i++)
        {
            if (current_status[i] == previous_status[i])
            {
                continue;
            }
            if (current_status[i] == 1)
            {
                printf("Port %d is now occupied.\n", i);
            }
            else
            {
                printf("Port %d is now free.\n", i);
            }
        }
    }

    void reset()
    {
        memset(current_status, 0, sizeof(current_status));
        memset(previous_status, 0, sizeof(previous_status));
    }
    bool done(int p)
    {
        return current_status[p];
    }

    void find_port(int p, bool print)
    {
        while (!done(p))
        {
            updatePortsImpl();
            if (print)
            {
                printPortsChanges();
            }
            memcpy(previous_status, current_status, sizeof(previous_status));
        }
        reset();
    }
    int port_opened()
    {
        if (!ports_queue.empty())
        {
            int port = ports_queue.front();
            ports_queue.pop();
            return port;
        }
        int port = 0;
        updatePortsImpl();
        for (int i = 1; i < TOTAL_PORTS; i++)
        {
            if ((previous_status[i] == 0) && (current_status[i] == 1))
            {
                ports_queue.push(i);
                // break;
            }
        }
        memcpy(previous_status, current_status, sizeof(previous_status));
        if (!ports_queue.empty())
        {
            port = ports_queue.front();
            ports_queue.pop();
        }
        return port;
    }
    void clear_queue()
    {
        ports_queue = std::queue<int>();
    }
    void debug_bind0()
    {
        std::cout << "debug_bind0 called" << std::endl;
        for (int i = 33000; i < 34000; i++)
        {
            if (current_status[i])
            {
                std::cout << i << " ";
            }
        }
        std::cout << "------" << std::endl;
    }
};

#endif // PORT_FINDER_BASE_H
