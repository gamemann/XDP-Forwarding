#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "cmdline.h"

const struct option lopts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"offload", no_argument, NULL, 'o'},
    {"skb", no_argument, NULL, 's'},

    {"baddr", required_argument, NULL, 'b'},
    {"bport", required_argument, NULL, 'B'},
    {"daddr", required_argument, NULL,  'd'},
    {"dport", required_argument, NULL, 'D'},
    {"protocol", required_argument, NULL, 'p'},
    {"save", no_argument, NULL, 'a'},

    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

/**
 * Parses the command line via getopt.
 * 
 * @param argc The argument count from main().
 * @param argv A pointer to the argument array from main().
 * @param cmd A pointer to a cmdline struct which we'll use to store the argument information in.
 * 
 * @return void
 */
void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int c = -1;

    while (optind < argc)
    {
        if ((c = getopt_long(argc, argv, "c:osb:B:d:D:p:ah", lopts, NULL)) != -1)
        {
            switch (c)
            {
                case 'c':
                    cmd->cfgfile = optarg;

                    break;

                case 'o':
                    cmd->offload = 1;

                    break;

                case 's':
                    cmd->skb = 1;

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
                    cmd->protocol = optarg;

                    break;
                
                case 'a':
                    cmd->save = 1;

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