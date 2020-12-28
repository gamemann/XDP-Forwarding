#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <getopt.h>

#include <bpf.h>

#include "xdpfwd.h"
#include "xdp_prog.h"
#include "config.h"
#include "cmdline.h"

int raise_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    // Raise RLimit
    if (raise_rlimit() != 0)
    {
        fprintf(stderr, "Error setting rlimit. Please ensure you're running this program as a privileged user.\n");

        return EXIT_FAILURE;
    }

    // Parse command line.
    struct cmdline cmd = {0};

    parsecmdline(argc, argv, &cmd);

    return EXIT_SUCCESS;
}