#pragma once

#include <inttypes.h>

struct cmdline
{
    char *cfgfile;
    unsigned int offload : 1;
    unsigned int skb : 1;
    unsigned int time;

    char *baddr;
    uint16_t bport;

    char *daddr;
    uint16_t dport;

    char *protocol;
    
    unsigned int save : 1;

    unsigned int list : 1;
    unsigned int help : 1;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);