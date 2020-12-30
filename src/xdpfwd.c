#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <getopt.h>
#include <inttypes.h>

#include <bpf.h>
#include <libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "xdpfwd.h"
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

int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    uint32_t mode = XDP_FLAGS_DRV_MODE;

    if (cmd->offload)
    {
        mode = XDP_FLAGS_HW_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err)
        {
            const char *smode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    smode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    smode = "DRV";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    smode = "SKB/generic";

                    break;
            }

            fprintf(stderr, "Could not attach with %s mode.\n", smode);
            
            if (mode != -err)
            {
                flags |= mode;
            }
        }
    }

    return mode;
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

    char *cfgfile = "/etc/xdpfwd/xdpfwd.conf";

    if (cmd.cfgfile != NULL)
    {
        cfgfile = cmd.cfgfile;
    }

    // Parse config file.
    struct config cfg = {0};

    if (parseconfig((const char *)cfgfile, &cfg) != 0)
    {
        fprintf(stderr, "Error reading config file :: %s.\n", strerror(errno));

        return EXIT_FAILURE;
    }

    // Retrieve interface index.
    int ifidx = if_nametoindex(cfg.interface);

    if (ifidx < 0)
    {
        fprintf(stderr, "Error retrieving interface index. Interface => %s\n", cfg.interface);

        return EXIT_FAILURE;
    }

    // Load XDP/BPF map.
    int progfd;
    const char *bpfprog = "/etc/xdpfwd/xdp_prog.o";

    struct bpf_object *obj;

    int err = 0;

    struct bpf_prog_load_attr loadattr =
    {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex = ifidx
    };

    loadattr.file = bpfprog;

    if ((err = bpf_prog_load_xattr(&loadattr, &obj, &progfd)))
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Number -> %d\n", bpfprog, strerror(-err), err);

        return EXIT_FAILURE;
    }

    err = attachxdp(ifidx, progfd, &cmd);

    if (err != XDP_FLAGS_HW_MODE && err != XDP_FLAGS_DRV_MODE && err != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(err), err);

        return EXIT_FAILURE;
    }
    
    // Update forwarding map.
    for (int i = 0; i < rcount; i++)
    {
        
    }

    return EXIT_SUCCESS;
}