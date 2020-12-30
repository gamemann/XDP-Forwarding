#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "cmdline.h"

const struct option lopts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"offload", no_argument, NULL, 'o'},

    {"baddr", required_argument, NULL, 'b'},
    {"bport", required_argument, NULL, 'B'},
    {"daddr", required_argument, NULL,  'd'},
    {"dport", required_argument, NULL, 'D'},
    {"protocol", required_argument, NULL, 'p'},

    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int c = -1;

    while (optind < argc)
    {
        if ((c = getopt_long(argc, argv, "c:oh", lopts, NULL)) != -1)
        {
            switch (c)
            {
                case 'c':
                    cmd->cfgfile = optarg;

                    break;

                case 'o':
                    cmd->offload = 1;

                    break;

                case 'h':
                    cmd->help = 1;

                    break;

                case 'b':
                    cmd->baddr = optarg;

                    break;
                
                case 'B':
                    cmd->bport = (uint16_t)atoi(optarg);

                    break;

                case 'd':
                    cmd->daddr = optarg;

                    break;

                case 'D':
                    cmd->dport = (uint16_t)atoi(optarg);

                    break;

                case 'p':
                    cmd->protocol = (uint8_t)atoi(optarg);

                    break;

                case '?':
                    fprintf(stderr, "Missing argument.\n");

                    break;
            }
        }
        else
        {
            optind++;
        }
    }
}