#pragma once

struct cmdline
{
    char *cfgfile;
    unsigned int offload : 1;

    unsigned int help : 1;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);