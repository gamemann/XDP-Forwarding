#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include <bpf.h>
#include <libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "xdpfwd.h"
#include "config.h"
#include "cmdline.h"
#include "utils.h"

uint8_t cont = 1;

void signhdl(int tmp)
{
    cont = 0;
}

/**
 * Raises the RLimit.
 * 
 * @return Returns 0 on success (EXIT_SUCCESS) or 1 on failure (EXIT_FAILURE).
 */
int raise_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    uint32_t mode = XDP_FLAGS_DRV_MODE;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
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
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

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

    // Check for help menu.
    if (cmd.help)
    {
        fprintf(stdout, "Usage: xdpfwd [-o -s -c <config file> -h]\n" \
                        "-o --offload => Attempt to load XDP program with HW/offload mode. If fails, will try DRV and SKB mode in that order.\n" \
                        "-s --skb => Force program to load in SKB/generic mode.\n" \
                        "-t --time => The amount of time in seconds to run the program for. Unset or 0 = infinite.\n" \
                        "-c --config => Location to XDP Forward config (default is /etc/xdpfwd/xdpfwd.conf).\n" \
                        "-l --list => List all forwarding rules." \
                        "-h --help => Print out command line usage.\n");

        return EXIT_SUCCESS;
    }

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

    // Check for list.
    if (cmd.list)
    {
        fprintf(stdout, "Forwarding Rules\n");

        // List all rules (loop through 256 times).
        for (unsigned int i = 0; i < MAXRULES; i++)
        {
            struct forward_rule *rule = &cfg.rules[i];

            if (rule == NULL)
            {
                continue;
            }

            // Make sure the rule isn't null.
            if (rule == NULL || rule->bindaddr == NULL || rule->destaddr == NULL || rule->protocol == NULL)
            {
                continue;
            }

            char *protocol = (char *)rule->protocol;

            // If protocol string is empty, set to all!
            if (protocol[0] == '\0')
            {
                protocol = "All";
            }
            
            fprintf(stdout, "Rule #%i\n", (i + 1));

            fprintf(stdout, "\tProtocol => %s\n\n", protocol);

            fprintf(stdout, "\tBind Address => %s\n", rule->bindaddr);
            fprintf(stdout, "\tBind Port => %u\n\n", rule->bindport);

            fprintf(stdout, "\tDest Address => %s\n", rule->destaddr);
            fprintf(stdout, "\tDest Port => %u\n\n", rule->destport);
        }

        fprintf(stdout, "\n");

        return EXIT_SUCCESS;
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
        fprintf(stderr, "WARNING - Failed retrieving 'forward_map' FD. This shouldn't happen.\n");

        attachxdp(ifidx, -1, &cmd);

        return EXIT_FAILURE;
    }
    else
    {
        // Update forwarding map.
        for (int i = 0; i < rcount; i++)
        {
            uint32_t bindaddr;
            uint32_t destaddr;
            uint8_t protocol = 0;

            // Fill out information.
            struct in_addr baddr;
            inet_pton(AF_INET, cfg.rules[i].bindaddr, &baddr);
            bindaddr = baddr.s_addr;

            struct in_addr daddr;
            inet_pton(AF_INET, cfg.rules[i].destaddr, &daddr);
            destaddr = daddr.s_addr;

            char *protocolstr = "ALL";

            if (cfg.rules[i].protocol != NULL)
            {
                if (strcmp(lowerstr((char *)cfg.rules[i].protocol), "tcp") == 0)
                {
                    protocolstr = "TCP";
                    protocol = IPPROTO_TCP;
                }
                else if (strcmp(lowerstr((char *)cfg.rules[i].protocol), "udp") == 0)
                {
                    protocolstr = "UDP";
                    protocol = IPPROTO_UDP;
                }
                else if (strcmp(lowerstr((char *)cfg.rules[i].protocol), "icmp") == 0)
                {
                    protocolstr = "ICMP";
                    protocol = IPPROTO_ICMP; 
                }
                else
                {
                    fprintf(stderr, "Rule #%d has an invalid protocol. Please use TCP, UDP, or ICMP.\n", i);
                    continue;
                }
            }

            struct forward_key fwdkey = {0};

            fwdkey.bindaddr = bindaddr;
            fwdkey.bindport = (protocol == IPPROTO_ICMP) ? 0 : htons(cfg.rules[i].bindport);
            fwdkey.protocol = protocol;

            struct forward_info fwdinfo = {0};
            fwdinfo.destaddr = destaddr;
            fwdinfo.destport = (protocol == IPPROTO_ICMP) ? 0 : htons(cfg.rules[i].destport);

            if (bpf_map_update_elem(forwardfd, &fwdkey, &fwdinfo, BPF_ANY) != 0)
            {
                fprintf(stderr, "Failed adding forward rule %d :: %s.\n", i, strerror(errno));
            }
            else
            {
                if (protocol == IPPROTO_ICMP)
                {
                    fprintf(stdout, "Adding forwarding rule with %s => %s (%s).\n", cfg.rules[i].bindaddr, cfg.rules[i].destaddr, protocolstr);
                }
                else
                {
                    fprintf(stdout, "Adding forwarding rule with %s:%" PRIu16 " => %s:%" PRIu16 " (%s).\n", cfg.rules[i].bindaddr, ntohs(fwdkey.bindport), cfg.rules[i].destaddr, ntohs(fwdinfo.destport), protocolstr);
                }
            }
        }
    }

    time_t endTime = (cmd.time > 0) ? time(NULL) + cmd.time : 0;

    while (cont)
    {
        // Check if we need to end or not.
        time_t curTime = time(NULL);

        if (endTime > 0 && curTime >= endTime)
        {
            break;
        }

        sleep(1);
    }

    // Unpin maps.
    bpf_object__unpin_maps(obj, PIN_DIR);

    // Detach XDP program.
    attachxdp(ifidx, -1, &cmd);

    return EXIT_SUCCESS;
}