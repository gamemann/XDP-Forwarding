#pragma once

#include <inttypes.h>

#define MAXRULES 256
#define MAXPORTS 65535
#define MAXCONNECTIONS 1000000

struct connection
{
    uint32_t clientaddr;
    uint16_t port;
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
    uint16_t port;
};

struct conn_key
{
    uint32_t clientaddr;
    uint32_t bindaddr;
    uint8_t protocol;
};

#define FORWARD_MAP "/sys/fs/bpf/xdpfwd/forward_map"
#define PIN_DIR "/sys/fs/bpf/xdpfwd"