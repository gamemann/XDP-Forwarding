#pragma once

#include <inttypes.h>

#include "xdpfwd.h"

struct forward_rule
{
    const char *bindaddr;
    uint16_t bindport;

    const char *destaddr;
    uint16_t destport;
};

extern int rcount;

struct config
{
    const char *interface;

    struct forward_rule rules[MAXRULES];
};

int parseconfig(const char *file, struct config *cfg);