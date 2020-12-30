#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <bpf.h>
#include <libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "xdpfwd.h"
#include "config.h"
#include "cmdline.h"

uint8_t cont = 1;

void signhdl(int tmp)
{
    cont = 0;
}

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

        if (err || progfd == -1)
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

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", smode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                flags |= mode;
            }
        }
        else
        {
            break;
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

    if (ifidx < 1)
    {
        fprintf(stderr, "Error retrieving interface index. Interface => %s\n", cfg.interface);

        return EXIT_FAILURE;
    }

    // Load XDP/BPF map.
    int progfd = -1;
    const char *bpfprog = "/etc/xdpfwd/xdp_prog.o";

    struct bpf_object *obj;

    int err = 0;

    if ((err = bpf_prog_load(bpfprog, BPF_PROG_TYPE_XDP, &obj, &progfd)))
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

    // Pin maps.
    bpf_object__pin_maps(obj, PIN_DIR);

    signal(SIGINT, signhdl);

    // Get forward_map FD.
    int forwardfd = bpf_object__find_map_fd_by_name(obj, "forward_map");

    if (forwardfd < 0)
    {
        fprintf(stderr, "WARNING - Failed retrieving 'forward_map' FD.\n");
    }
    else
    {
        // Update forwarding map.
        for (int i = 0; i < rcount; i++)
        {
            uint32_t bindaddr;
            uint32_t destaddr;
            uint8_t protocol;

            // Fill out information.
            struct in_addr baddr;
            inet_pton(AF_INET, cfg.rules[i].bindaddr, &baddr);
            bindaddr = baddr.s_addr;

            struct in_addr daddr;
            inet_pton(AF_INET, cfg.rules[i].destaddr, &daddr);
            destaddr = daddr.s_addr;

            if (cfg.rules[i].protocol != NULL)
            {
                if (strcmp(cfg.rules[i].protocol, "tcp") == 0)
                {
                    protocol = IPPROTO_TCP;
                }
                else if (strcmp(cfg.rules[i].protocol, "udp") == 0)
                {
                    protocol = IPPROTO_UDP;
                }
                else
                {
                    protocol = IPPROTO_ICMP; 
                }
            }

            struct forward_key fwdkey = {0};

            fwdkey.bindaddr = bindaddr;
            fwdkey.bindport = htons(cfg.rules[i].bindport);
            fwdkey.protocol = protocol;

            struct forward_info fwdinfo = {0};
            fwdinfo.destaddr = destaddr;
            fwdinfo.destport = htons(cfg.rules[i].destport);

            //fprintf(stdout, "Adding forwarding rule with %" PRIu32 ":%" PRIu16 " => %" PRIu32 ":%" PRIu16 " (%" PRIu8 ")\n", fwdkey.bindaddr, fwdkey.bindport, fwdinfo.destaddr, fwdinfo.destport, fwdkey.protocol);

            if (bpf_map_update_elem(forwardfd, &fwdkey, &fwdinfo, BPF_ANY) != 0)
            {
                fprintf(stderr, "Failed adding forward rule %d :: %s.\n", i, strerror(errno));
            }
        }
    }

    while (cont)
    {
        sleep(1);
    }

    // Unpin maps.
    bpf_object__unpin_maps(obj, PIN_DIR);

    // Detach XDP program.
    attachxdp(ifidx, -1, &cmd);

    return EXIT_SUCCESS;
}