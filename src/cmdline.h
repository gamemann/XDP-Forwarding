#pragma once

#include <inttypes.h>

struct cmdline
{
    char *cfgfile;
    unsigned int offload : 1;
    unsigned int skb : 1;

    char *baddr;
    uint16_t bport;

    char *daddr;
    uint16_t dport;

    char *protocol;

    unsigned int help : 1;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);