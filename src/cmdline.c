#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "cmdline.h"

const struct option lopts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"offload", no_argument, NULL, 'o'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int c = -1;

    while (optind < argc)
    {
        if ((c = getopt_long(argc, argv, "c:oh", &lopts, NULL)) != -1)
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