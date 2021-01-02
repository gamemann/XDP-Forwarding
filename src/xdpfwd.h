#pragma once

#include <inttypes.h>

#define MAXRULES 256
#define MAXCONNECTIONS 1000000

// These represent the min and max port ranges that can be used as source ports. By default, we use 20 ports due to low BPF limitations. I am able to get this working at 1 - 65534 with a custom kernel built.
#define MINPORT 1
#define MAXPORT 60000

struct connection
{
    uint32_t clientaddr;
    uint16_t clientport;

    uint16_t bindport;

    uint16_t port;

    uint64_t firstseen;
    uint64_t lastseen;

    uint64_t count;
};

struct forward_key
{
    uint32_t bindaddr;
    uint8_t protocol;

    uint16_t bindport;
};

struct forward_info
{
    uint32_t destaddr;
    uint16_t destport;
};

struct port_key
{
    uint32_t bindaddr;
    uint32_t destaddr;
    uint16_t port;
};

struct conn_key
{
    uint32_t clientaddr;
    uint16_t clientport;
    uint32_t bindaddr;
    uint16_t bindport;
    uint8_t protocol;
};

#define FORWARD_MAP "/sys/fs/bpf/xdpfwd/forward_map"
#define PIN_DIR "/sys/fs/bpf/xdpfwd"