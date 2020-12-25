#pragma once

#include <inttypes.h>

struct connection
{
    uint16_t tcpport;
    uint64_t tcplastseen;

    uint16_t udpport;
    uint64_t udplastseen;

    uint64_t count;
};

struct forward_key
{
    uint32_t bindaddr;
    uint16_t bindport;

    uint8_t protocol;

    uint32_t destaddr;
    uint16_t destport;
};

struct forward_info
{
    uint32_t tcpmap;
    uint32_t udpmap;
    uint32_t connmap;
};